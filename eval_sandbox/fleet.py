"""评测车队：N 个任务并发执行，且并发时每个任务仍是独立命名空间 + 独立 cgroup。

并发模型用 ThreadPoolExecutor：每个任务本身是一个独立的 OS 进程（bwrap），
线程只负责 Popen + communicate + 收账，Python 侧没有共享可变状态；
隔离来自命名空间与 cgroup，而不是来自 Python 的进程/线程边界。
不用进程池是为了避免再复制 N 份解释器；不用 asyncio 是因为这里的等待就是
"等子进程退出"，线程池足够且更直白。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace

from .cgroup import residual_processes, sweep_orphan_cgroups
from .policy import Policy
from .sandbox import RunResult, run

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------- 任务负载

_STANDARD = r"""
import json, socket, sys, time

ev = {}
try:
    socket.create_connection(("1.1.1.1", 443), timeout=2)
    ev["net"] = "LEAK"
except OSError as e:
    ev["net"] = "denied:%d" % e.errno

with open("/work/own.txt", "w") as f:
    f.write(sys.argv[1])

try:
    with open("/work/shared.txt", "rb") as f:
        f.read(64)
    ev["shared"] = "visible"
except OSError as e:
    ev["shared"] = "absent:%d" % e.errno

end = time.monotonic() + %(spin)f
while time.monotonic() < end:
    pass

print("RESULT", json.dumps(ev, sort_keys=True), flush=True)
ok = ev["net"] == "denied:101" and ev["shared"].startswith("absent:2")
print("SELFCHECK=pass" if ok else "VIOLATION", flush=True)
sys.exit(0 if ok else 9)
"""

_WRITER = r"""
import json, socket, sys, time

ev = {}
with open("/work/shared.txt", "wb") as f:
    f.write(b"WRITER_CONTENT")
try:
    with open("/work/shared.txt", "rb") as f:
        got = f.read(64)
    ev["shared"] = "visible" if got == b"WRITER_CONTENT" else "corrupt"
except OSError as e:
    ev["shared"] = "absent:%d" % e.errno

try:
    socket.create_connection(("1.1.1.1", 443), timeout=2)
    ev["net"] = "LEAK"
except OSError as e:
    ev["net"] = "denied:%d" % e.errno

end = time.monotonic() + %(spin)f
while time.monotonic() < end:
    pass

print("RESULT", json.dumps(ev, sort_keys=True), flush=True)
ok = ev["net"] == "denied:101" and ev["shared"] == "visible"
print("SELFCHECK=pass" if ok else "VIOLATION", flush=True)
sys.exit(0 if ok else 9)
"""

_READER = r"""
import json, socket, sys, time

ev = {"shared": "absent:2"}
for _ in range(10):
    try:
        with open("/work/shared.txt", "rb") as f:
            f.read(64)
        ev["shared"] = "visible"
        break
    except OSError as e:
        ev["shared"] = "absent:%d" % e.errno
    time.sleep(0.1)

try:
    socket.create_connection(("1.1.1.1", 443), timeout=2)
    ev["net"] = "LEAK"
except OSError as e:
    ev["net"] = "denied:%d" % e.errno

end = time.monotonic() + %(spin)f
while time.monotonic() < end:
    pass

print("RESULT", json.dumps(ev, sort_keys=True), flush=True)
ok = ev["net"] == "denied:101" and ev["shared"].startswith("absent:2")
print("SELFCHECK=pass" if ok else "VIOLATION", flush=True)
sys.exit(0 if ok else 9)
"""

_OOM = r"""
import json, socket, sys, time

ev = {}
try:
    socket.create_connection(("1.1.1.1", 443), timeout=2)
    ev["net"] = "LEAK"
except OSError as e:
    ev["net"] = "denied:%d" % e.errno

end = time.monotonic() + %(spin)f
while time.monotonic() < end:
    pass

print("RESULT", json.dumps(ev, sort_keys=True), flush=True)
print("PRE_OOM_OK", flush=True)
bytearray(200 * 1024 * 1024)
print("ALLOC_UNEXPECTEDLY_OK", flush=True)
"""

_FAULT_TIMEOUT = "while True:\n    pass\n"

_FAULT_FS = r"""
import sys
try:
    with open("/usr/lib/.esbx-fault", "wb") as f:
        f.write(b"x")
except OSError as e:
    sys.stderr.write("DENIED_FS errno=%d\n" % e.errno)
    sys.exit(5)
print("WRITE_UNEXPECTEDLY_OK")
"""

_FAULT_NET = r"""
import socket, sys
try:
    socket.create_connection(("1.1.1.1", 443), timeout=2)
except OSError as e:
    sys.stderr.write("DENIED_NET errno=%d\n" % e.errno)
    sys.exit(3)
print("CONNECTED_UNEXPECTEDLY")
"""

_FAULT_NONZERO = r"""
import sys
print("NONZERO_MARKER")
sys.exit(7)
"""


@dataclass(frozen=True)
class TaskSpec:
    cid: str
    kind: str
    payload: str


@dataclass(frozen=True)
class FleetConfig:
    root: str
    spin_seconds: float = 0.4
    memory_bytes: int = 128 * 1024 * 1024
    oom_memory_bytes: int = 64 * 1024 * 1024
    cpu_quota_pct: int = 50
    wall_seconds: float = 8.0


def _render(template: str, spin: float) -> str:
    # 载荷里有大量字面量 %d（errno 格式化），所以不能用 % 字典插值，只能定点替换。
    return template.replace("%(spin)f", str(spin))


def build_specs(cfg: FleetConfig, n: int = 20) -> list[TaskSpec]:
    """n 个任务：n-3 个标准任务 + 1 个写者 + 1 个读者 + 1 个 OOM 注入。"""
    if n < 4:
        raise ValueError("至少需要 4 个任务（写者/读者/OOM/标准）")
    spin = cfg.spin_seconds
    specs = [TaskSpec("t%02d" % i, "standard", _render(_STANDARD, spin)) for i in range(n - 3)]
    specs.append(TaskSpec("fs_writer", "writer", _render(_WRITER, spin)))
    specs.append(TaskSpec("fs_reader", "reader", _render(_READER, spin)))
    specs.append(TaskSpec("mem_oom", "oom", _render(_OOM, spin)))
    return specs


def build_standard_specs(cfg: FleetConfig, n: int) -> list[TaskSpec]:
    """同构任务集（只有标准负载）。用于测并发加速比：混入读任务时它的固定等待
    会把 N 小时的加速比压平，测不准编排本身。"""
    return [TaskSpec("s%02d" % i, "standard", _render(_STANDARD, cfg.spin_seconds))
            for i in range(n)]


def build_fault_specs() -> list[TaskSpec]:
    return [
        TaskSpec("fault_timeout", "timeout", _FAULT_TIMEOUT),
        TaskSpec("fault_fs", "fs_denied", _FAULT_FS),
        TaskSpec("fault_net", "net_denied", _FAULT_NET),
        TaskSpec("fault_nonzero", "nonzero", _FAULT_NONZERO),
    ]


def _policy_for(cfg: FleetConfig, spec: TaskSpec) -> Policy:
    workdir = os.path.join(cfg.root, "work", spec.cid)
    os.makedirs(workdir, exist_ok=True)
    memory = cfg.oom_memory_bytes if spec.kind == "oom" else cfg.memory_bytes
    wall = 3.0 if spec.kind == "timeout" else cfg.wall_seconds
    return Policy(workdir=workdir, memory_bytes=memory, cpu_quota_pct=cfg.cpu_quota_pct,
                  wall_seconds=wall)


def run_fleet(specs: list[TaskSpec], cfg: FleetConfig, workers: int | None = None,
              run_token: str = "run") -> list[RunResult]:
    workers = workers or len(specs)
    results: list[RunResult | None] = [None] * len(specs)

    def _one(index: int, spec: TaskSpec) -> None:
        policy = _policy_for(cfg, spec)
        results[index] = run(
            [sys.executable, "-u", "-c", spec.payload, spec.cid],
            policy,
            task_id="fleet-%s" % spec.cid,               # 稳定：跨重跑进摘要
            label="fleet-%s-%s" % (run_token, spec.cid),  # 唯一：本轮孤儿排查用
        )

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_one, i, s) for i, s in enumerate(specs)]
        for future in futures:
            future.result()
    return [r for r in results if r is not None]


def fleet_digest(results: list[RunResult]) -> str:
    """汇总摘要：按 cid 排序后哈希，与并发完成顺序无关。"""
    import hashlib

    merged = {r.task_id: r.verdict_sha256 for r in sorted(results, key=lambda x: x.task_id)}
    blob = json.dumps(merged, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def attribute(result: RunResult) -> str:
    """把终态压成五类可区分归因。"""
    if result.outcome == "wall_timeout":
        return "wall_timeout"
    if result.outcome == "oom":
        return "oom"
    text = result.stdout + result.stderr
    if "DENIED_FS" in text:
        return "denied_fs"
    if "DENIED_NET" in text:
        return "denied_network"
    if result.outcome != "ok":
        return "nonzero_exit"
    return "ok"


def task_event(result: RunResult) -> dict:
    """从负载的 RESULT 行解析出它自报的隔离事实。"""
    for line in result.stdout.splitlines():
        if line.startswith("RESULT "):
            try:
                return json.loads(line[len("RESULT "):])
            except ValueError:
                return {}
    return {}


def wait_for_no_residual(token: str, timeout: float = 3.0) -> list[int]:
    """等一段有界时间让内核把刚被杀的进程收尾，再判定残留。

    真正的泄漏（例如漏掉的 300s 长睡进程）不会在 3s 内消失，所以这个窗口
    不会把泄漏洗白，只是避免把"正在退出的进程"误判成孤儿。
    """
    deadline = time.monotonic() + timeout
    left = residual_processes(token)
    while left and time.monotonic() < deadline:
        time.sleep(0.05)
        left = residual_processes(token)
    return left


# ---------------------------------------------------------------- 泄漏检测

_LEAK_CHILD = r"""
import sys, tempfile
from eval_sandbox import Policy, run
run([sys.executable, "-c", "import time;time.sleep(300)"],
    Policy(workdir=tempfile.mkdtemp(), wall_seconds=300),
    task_id=%r)
"""


def leak_test(token: str, wait_start: float = 3.0, wait_reap: float = 3.0) -> dict:
    """杀掉编排器，断言沙盒进程不残留；随后清掉遗留的空 cgroup 目录。"""
    env = dict(os.environ, PYTHONPATH=REPO_ROOT)
    proc = subprocess.Popen(
        [sys.executable, "-c", _LEAK_CHILD % ("leak-" + token)],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    started = time.monotonic()
    running: list[int] = []
    while time.monotonic() - started < wait_start:
        running = residual_processes(token)
        if running:
            break
        time.sleep(0.05)

    proc.kill()
    proc.wait(timeout=10)

    deadline = time.monotonic() + wait_reap
    leftover = residual_processes(token)
    while leftover and time.monotonic() < deadline:
        time.sleep(0.05)
        leftover = residual_processes(token)

    swept = sweep_orphan_cgroups(token)
    return {
        "sandbox_pids_observed": running,
        "residual_after_kill": leftover,
        "swept_cgroup_dirs": swept,
        "passed": bool(running) and not leftover,
    }
