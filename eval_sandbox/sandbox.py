"""任务级沙盒执行器。

隔离由三部分组成，每一层都能在结果里被单独观察到：
  1. bwrap（bubblewrap）：net/pid/uts/ipc/user/cgroup 命名空间 + 挂载白名单
  2. 自建 cgroup v2 子组：memory.max / memory.swap.max / cpu.max / pids.max
  3. 监督者墙钟超时 + cgroup.kill 整树击杀

bwrap 需要 `--unshare-pid`，它会再 fork 出一个真正的负载进程，因此"启动后把
Popen 的 pid 写进 cgroup.procs"只会把 bwrap 自己关进去，负载仍在原 cgroup。
正确做法是在 preexec_fn 里让即将 exec 的子进程自己写入，之后 fork 出来的后代
天然继承成员关系。
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field

from .cgroup import CgroupLimit, CgroupUnavailable
from .policy import Policy

BWRAP = shutil.which("bwrap")


class SandboxUnavailable(RuntimeError):
    """隔离能力不成立时抛出；调用方必须据此判定失败，不能降级成"没隔离也算过"。"""


def classify_outcome(deadline_hit: bool, oom_kill: int, exit_code: int | None) -> str:
    """把"进程为什么结束"变成可归因的枚举。顺序很重要：墙钟超时也会留下 -9。"""
    if deadline_hit:
        return "wall_timeout"
    if oom_kill > 0:
        return "oom"
    if exit_code == 0:
        return "ok"
    if exit_code is None:
        return "unknown"
    if exit_code < 0:
        return "killed_by_signal"
    return "nonzero_exit"


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def verdict_payload(
    task_id: str, outcome: str, exit_code: int | None, stdout: str, stderr: str, policy: Policy
) -> dict:
    return {
        "task_id": task_id,
        "outcome": outcome,
        "exit_code": exit_code,
        "stdout_sha256": _sha256_text(stdout),
        "stderr_sha256": _sha256_text(stderr),
        "limits": policy.limits(),
    }


def verdict_sha256(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class RunResult:
    task_id: str
    outcome: str
    exit_code: int | None
    duration_s: float
    stdout: str
    stderr: str
    verdict_sha256: str
    sandbox_id: str
    evidence: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.outcome == "ok"


def build_bwrap_argv(policy: Policy, argv: list[str]) -> list[str]:
    if BWRAP is None:
        raise SandboxUnavailable("找不到 bwrap（bubblewrap）；不做降级，直接拒绝执行")
    args = [
        BWRAP,
        "--die-with-parent",
        "--new-session",
        "--unshare-all",          # net/pid/uts/ipc/user/cgroup 全部断开
        "--clearenv",
        "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
        "--setenv", "HOME", "/work",
        "--setenv", "TMPDIR", "/tmp",
        "--setenv", "PYTHONHASHSEED", "0",
        "--setenv", "LC_ALL", "C.UTF-8",
        "--setenv", "TZ", "UTC",
    ]
    for mount in policy.ro_binds:
        if os.path.isdir(mount):
            args += ["--ro-bind", mount, mount]
    args += [
        "--symlink", "usr/bin", "/bin",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--bind", policy.workdir, "/work",
        "--chdir", "/work",
    ]
    return args + list(argv)


def run(argv: list[str], policy: Policy, task_id: str = "task") -> RunResult:
    if BWRAP is None:
        raise SandboxUnavailable("找不到 bwrap（bubblewrap）；不做降级，直接拒绝执行")

    try:
        cg = CgroupLimit(task_id)
    except CgroupUnavailable as exc:
        raise SandboxUnavailable(str(exc)) from exc

    cg.set_limits(policy.memory_bytes, policy.cpu_quota_pct, policy.pids_max)
    cmd = build_bwrap_argv(policy, argv)
    procs_file = cg.procs_file

    def _enter_cgroup() -> None:
        # 在 exec 之前把"将要变成 bwrap 的这个进程"放进 cgroup；
        # bwrap 再 fork 出的负载与后代全部继承这个成员关系。
        with open(procs_file, "w", encoding="utf-8") as fh:
            fh.write(str(os.getpid()))

    deadline_hit = False
    started = time.monotonic()
    stdout = stderr = ""
    exit_code: int | None = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=_enter_cgroup,
            start_new_session=True,
            cwd=policy.workdir,
        )
        try:
            stdout, stderr = proc.communicate(timeout=policy.wall_seconds)
        except subprocess.TimeoutExpired:
            deadline_hit = True
            cg.kill()  # 整树击杀：bwrap + 命名空间内的负载
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
        exit_code = proc.returncode
    finally:
        duration = time.monotonic() - started
        evidence = cg.stats()
        cg.close()

    oom_kill = evidence.get("memory_events", {}).get("oom_kill", 0)
    outcome = classify_outcome(deadline_hit, oom_kill, exit_code)
    payload = verdict_payload(task_id, outcome, exit_code, stdout, stderr, policy)
    return RunResult(
        task_id=task_id,
        outcome=outcome,
        exit_code=exit_code,
        duration_s=duration,
        stdout=stdout,
        stderr=stderr,
        verdict_sha256=verdict_sha256(payload),
        sandbox_id=cg.sandbox_id,
        evidence={**evidence, "verdict_payload": payload, "deadline_hit": deadline_hit},
    )


def capabilities() -> dict:
    """探测本机实际能提供什么，供 CLI/README 如实报告。"""
    from .cgroup import find_writable_base

    return {
        "bwrap": BWRAP,
        "cgroup_base": find_writable_base(),
        "userns_unprivileged": _read_flag("/proc/sys/kernel/unprivileged_userns_clone"),
        "unshare": shutil.which("unshare"),
    }


def _read_flag(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return None
