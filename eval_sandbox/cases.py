"""可执行判据：每个 case 都在沙盒里真跑一次，并对结果做断言。

所有 case 的负载都是内联 Python 片段，参数通过 argv 传入，不拼字符串，避免
测试本身成为注入面。
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Callable

from .policy import Policy
from .sandbox import RunResult

Check = Callable[[RunResult], tuple[bool, str]]

MEMORY_LIMIT = 64 * 1024 * 1024
MEMORY_BOMB_BYTES = 200 * 1024 * 1024

NET_EXTERNAL = r"""
import socket, sys
try:
    socket.create_connection(("1.1.1.1", 443), timeout=3)
except OSError as e:
    sys.stderr.write("DENIED %s: %s\n" % (type(e).__name__, e))
    sys.exit(3)
print("CONNECTED_UNEXPECTEDLY")
sys.exit(0)
"""

LOOPBACK = r"""
import socket
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.bind(("127.0.0.1", 0))
srv.listen(1)
port = srv.getsockname()[1]
cli = socket.create_connection(("127.0.0.1", port), timeout=2)
conn, _ = srv.accept()
cli.sendall(b"ping")
print("LOOPBACK_OK", conn.recv(4).decode())
"""

READ_PATH = r"""
import sys
try:
    with open(sys.argv[1], "rb") as fh:
        fh.read(64)
except OSError as e:
    sys.stderr.write("DENIED %s: %s\n" % (type(e).__name__, e))
    sys.exit(4)
print("READ_UNEXPECTEDLY_OK")
sys.exit(0)
"""

WRITE_PATH = r"""
import sys
try:
    with open(sys.argv[1], "wb") as fh:
        fh.write(b"x")
except OSError as e:
    sys.stderr.write("DENIED %s: %s\n" % (type(e).__name__, e))
    sys.exit(5)
print("WRITE_UNEXPECTEDLY_OK")
sys.exit(0)
"""

WORKDIR_RW = r"""
with open("/work/rw_probe.txt", "wb") as fh:
    fh.write(b"workdir-ok")
with open("/work/rw_probe.txt", "rb") as fh:
    assert fh.read() == b"workdir-ok"
print("WORKDIR_RW_OK")
"""

WALL_SPIN = r"""
while True:
    pass
"""

MEMORY_BOMB = r"""
import time
a = bytearray(%d)
print("ALLOC_OK")
time.sleep(2)
""" % MEMORY_BOMB_BYTES

CPU_SPIN = r"""
import time
end = time.monotonic() + 2.0
n = 0
while time.monotonic() < end:
    n += 1
print("SPIN_DONE", n)
"""

FORK_BOMB = r"""
import os, sys, time
kids = []
try:
    for _ in range(40):
        pid = os.fork()
        if pid == 0:
            time.sleep(3)
            os._exit(0)
        kids.append(pid)
except OSError as e:
    sys.stderr.write("DENIED %s: %s\n" % (type(e).__name__, e))
    for k in kids:
        try:
            os.kill(k, 9)
        except OSError:
            pass
    sys.exit(6)
print("FORKED_ALL", len(kids))
"""

DETERMINISTIC = r"""
import hashlib, json
rows = [{"id": i, "score": (i * 37) % 101} for i in range(1000)]
blob = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
print("DET", hashlib.sha256(blob).hexdigest())
"""


def _py(code: str, *args: str) -> tuple[str, ...]:
    return (sys.executable, "-c", code, *args)


@dataclass(frozen=True)
class Case:
    cid: str
    kind: str
    description: str
    argv: tuple[str, ...]
    policy: Policy
    check: Check
    repeats: int = 1


def case_set(workdir: str, forbidden_path: str) -> list[Case]:
    net = Policy(workdir=workdir, memory_bytes=128 * 1024 * 1024, wall_seconds=5)
    fs = Policy(workdir=workdir, memory_bytes=128 * 1024 * 1024, wall_seconds=5)
    wall = Policy(workdir=workdir, memory_bytes=128 * 1024 * 1024, wall_seconds=2)
    oom = Policy(workdir=workdir, memory_bytes=MEMORY_LIMIT, wall_seconds=10)
    cpu = Policy(workdir=workdir, cpu_quota_pct=50, wall_seconds=8)
    det = Policy(workdir=workdir, memory_bytes=128 * 1024 * 1024, wall_seconds=5)

    def net_denied(r: RunResult) -> tuple[bool, str]:
        readable = ("DENIED" in r.stderr) or ("Network is unreachable" in r.stderr)
        fast = r.duration_s < 2.0
        ok = r.outcome != "ok" and readable and fast
        detail = "stderr=%r %.2fs" % (r.stderr.strip().replace("\n", " ")[:110], r.duration_s)
        if r.outcome == "ok":
            detail = "外连竟然成功了：" + detail
        elif not readable:
            detail = "被拒但错误不可读：" + detail
        elif not fast:
            detail = "像是静默超时（%.1fs ≥ 2s）" % r.duration_s
        return ok, detail

    def loopback_ok(r: RunResult) -> tuple[bool, str]:
        ok = r.outcome == "ok" and "LOOPBACK_OK" in r.stdout
        return ok, "stdout=%r" % r.stdout.strip()[:80]

    def read_denied(r: RunResult) -> tuple[bool, str]:
        ok = r.outcome != "ok" and ("DENIED" in r.stderr)
        return ok, "stderr=%r" % r.stderr.strip().replace("\n", " ")[:110]

    def write_denied(r: RunResult) -> tuple[bool, str]:
        ok = r.outcome != "ok" and ("DENIED" in r.stderr)
        return ok, "stderr=%r" % r.stderr.strip().replace("\n", " ")[:110]

    def workdir_rw(r: RunResult) -> tuple[bool, str]:
        return r.outcome == "ok" and "WORKDIR_RW_OK" in r.stdout, "stdout=%r" % r.stdout.strip()[:80]

    def wall_killed(r: RunResult) -> tuple[bool, str]:
        ok = r.outcome == "wall_timeout" and r.duration_s >= 1.9
        return ok, "outcome=%s exit=%s %.2fs" % (r.outcome, r.exit_code, r.duration_s)

    def oom_killed(r: RunResult) -> tuple[bool, str]:
        oom_kill = r.evidence.get("memory_events", {}).get("oom_kill", 0)
        peak = r.evidence.get("memory_peak_bytes") or 0
        within = peak <= MEMORY_LIMIT * 1.02
        ok = r.outcome == "oom" and oom_kill >= 1 and within and "ALLOC_OK" not in r.stdout
        return ok, "outcome=%s oom_kill=%d peak=%d/%d" % (
            r.outcome, oom_kill, peak, MEMORY_LIMIT)

    def cpu_throttled(r: RunResult) -> tuple[bool, str]:
        stat = r.evidence.get("cpu_stat", {})
        throttled = stat.get("throttled_usec", 0)
        usage = stat.get("usage_usec", 0)
        ok = r.outcome == "ok" and throttled > 0 and usage <= int(r.duration_s * 1_000_000 * 0.75)
        return ok, "usage=%dus throttled=%dus wall=%.2fs" % (usage, throttled, r.duration_s)

    def pids_limited(r: RunResult) -> tuple[bool, str]:
        ok = r.outcome != "ok" and "DENIED" in r.stderr and "FORKED_ALL" not in r.stdout
        return ok, "stderr=%r" % r.stderr.strip().replace("\n", " ")[:110]

    return [
        Case("net_external_denied", "network",
             "沙盒内直连 1.1.1.1:443 必须失败，且错误可读、不是静默超时",
             _py(NET_EXTERNAL), net, net_denied),
        Case("net_loopback_allowed", "network",
             "同一沙盒内 127.0.0.1 自连必须成功（允许的本地资源仍可访问）",
             _py(LOOPBACK), net, loopback_ok),
        Case("fs_read_outside_denied", "filesystem",
             "读取未挂载的宿主路径必须被拒（No such file or directory）",
             _py(READ_PATH, forbidden_path), fs, read_denied),
        Case("fs_write_system_denied", "filesystem",
             "写 /usr 只读挂载必须被拒（Read-only file system）",
             _py(WRITE_PATH, "/usr/lib/.esbx-write-probe"), fs, write_denied),
        Case("fs_workdir_readwrite", "filesystem",
             "/work 是唯一可写目录，写入后读回必须一致",
             _py(WORKDIR_RW), fs, workdir_rw),
        Case("res_wall_timeout", "resource",
             "死循环必须被 2s 墙钟杀掉",
             _py(WALL_SPIN), wall, wall_killed),
        Case("res_memory_oom", "resource",
             "申请 200MB 超过 64MB 上限，必须被 OOM 杀掉且 oom_kill 可归因",
             _py(MEMORY_BOMB), oom, oom_killed),
        Case("res_cpu_quota", "resource",
             "50%% CPU 配额下空转 2s，必须出现 throttled 且实际占用不超过配额",
             _py(CPU_SPIN), cpu, cpu_throttled),
        Case("res_pids_limit", "resource",
             "pids.max=16 时 fork 40 个子进程必须失败",
             _py(FORK_BOMB), Policy(workdir=workdir, pids_max=16, wall_seconds=8),
             pids_limited),
        Case("det_repeat3", "determinism",
             "同一负载连跑 3 次，判决 sha256 必须完全一致",
             _py(DETERMINISTIC), det, lambda r: (True, ""), repeats=3),
    ]
