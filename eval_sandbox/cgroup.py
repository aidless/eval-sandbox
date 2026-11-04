"""cgroup v2 资源限额。

本机无 root，无法在 /sys/fs/cgroup 顶层建组。但 systemd 的用户管理器对自己
的子树做了 Delegate，`user@1000.service` 目录对当前用户可写，且子树里
cpu/memory/pids 三个控制器已开启——所以可以自建子组、直接写 memory.max。

如果拿不到这样的目录，就明确报 CgroupUnavailable，由上层决定退回 prlimit
还是拒绝执行；绝不假装限额生效。
"""
from __future__ import annotations

import os
import time
import uuid

CGROUP_FS = "/sys/fs/cgroup"


class CgroupUnavailable(RuntimeError):
    """本机没有可写的 cgroup v2 子树，cgroup 级限额不可用。"""


def own_cgroup_path() -> str | None:
    try:
        with open("/proc/self/cgroup", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("0::"):
                    rel = line.strip().split("::", 1)[1].lstrip("/")
                    return os.path.join(CGROUP_FS, rel)
    except OSError:
        return None
    return None


_BASE_CACHE: list[str | None] = []


def find_writable_base() -> str | None:
    """从本进程所在 cgroup 逐级向上，找第一个能建子组且子组带 memory/cpu 的目录。

    结果进程内缓存：fleet 并发时 20 个线程各自探测会反复建删目录，既慢又吵。
    """
    if _BASE_CACHE:
        return _BASE_CACHE[0]
    base = _probe_writable_base()
    _BASE_CACHE.append(base)
    return base


def _probe_writable_base() -> str | None:
    cur = own_cgroup_path()
    candidates: list[str] = []
    while cur and cur.startswith(CGROUP_FS):
        candidates.append(cur)
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent

    for base in candidates:
        probe = os.path.join(base, "esbx-cap-%d-%s" % (os.getpid(), uuid.uuid4().hex[:6]))
        try:
            os.makedirs(probe)
        except OSError:
            continue
        usable = False
        try:
            with open(os.path.join(probe, "cgroup.controllers"), encoding="utf-8") as fh:
                controllers = fh.read().split()
            usable = "memory" in controllers and "cpu" in controllers
        except OSError:
            usable = False
        finally:
            try:
                os.rmdir(probe)
            except OSError:
                pass
        if usable:
            return base
    return None


class CgroupLimit:
    """一个任务的独立 cgroup，兼作该任务的 sandbox_id。"""

    def __init__(self, label: str = "task") -> None:
        base = find_writable_base()
        if base is None:
            raise CgroupUnavailable(
                "找不到可写的 cgroup v2 子树（通常是 systemd 用户管理器未启用 Delegate）"
            )
        safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in label)[:24]
        self.path = os.path.join(base, "esbx-%s-%s" % (safe, uuid.uuid4().hex[:8]))
        os.makedirs(self.path)
        self.procs_file = os.path.join(self.path, "cgroup.procs")
        self.applied: dict[str, str] = {}
        self.unsupported: list[str] = []

    @property
    def sandbox_id(self) -> str:
        return os.path.basename(self.path)

    def _write(self, name: str, value: str) -> bool:
        path = os.path.join(self.path, name)
        if not os.path.exists(path):
            self.unsupported.append(name)
            return False
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(value)
        self.applied[name] = value
        return True

    def set_limits(self, memory_bytes: int, cpu_quota_pct: int, pids_max: int) -> None:
        self._write("memory.max", str(memory_bytes))
        self._write("memory.swap.max", "0")   # 禁掉 swap，否则内存超限会被换页而不是被杀
        self._write("memory.oom.group", "0")  # 只杀越界进程，不整组连坐
        self._write("cpu.max", "%d 100000" % (int(cpu_quota_pct) * 1000))
        self._write("pids.max", str(pids_max))

    def read(self, name: str) -> str | None:
        try:
            with open(os.path.join(self.path, name), encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError:
            return None

    def _kv(self, name: str) -> dict[str, int]:
        raw = self.read(name) or ""
        out: dict[str, int] = {}
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].lstrip("-").isdigit():
                out[parts[0]] = int(parts[1])
        return out

    def stats(self) -> dict:
        peak = self.read("memory.peak")
        return {
            "sandbox_id": self.sandbox_id,
            "cgroup_path": self.path,
            "memory_peak_bytes": int(peak) if peak and peak.isdigit() else None,
            "memory_events": self._kv("memory.events"),
            "cpu_stat": self._kv("cpu.stat"),
            "applied_limits": dict(self.applied),
            "unsupported_limits": list(self.unsupported),
            "mechanism": "cgroup_v2",
        }

    def kill(self) -> bool:
        """杀掉该组内所有进程（cgroup.kill 是原子的整树击杀）。"""
        try:
            with open(os.path.join(self.path, "cgroup.kill"), "w", encoding="utf-8") as fh:
                fh.write("1")
            return True
        except OSError:
            return False

    def close(self) -> None:
        for _ in range(30):
            try:
                os.rmdir(self.path)
                return
            except OSError:
                time.sleep(0.01)


def _is_zombie(pid: int) -> bool:
    """僵尸进程已经退出、只是在等父进程 reap；/proc 里还挂着但不再占资源。"""
    try:
        with open("/proc/%d/stat" % pid, encoding="utf-8") as fh:
            data = fh.read()
    except OSError:
        return True
    tail = data.rsplit(")", 1)[-1].split()
    return bool(tail) and tail[0] == "Z"


def residual_processes(token: str) -> list[int]:
    """按标识查孤儿：遍历 /proc，看还有没有**活着的**进程留在本轮 cgroup 子树里。

    只认 cgroup 路径里的唯一 token，不靠"看起来没了"；僵尸态不算活进程，
    否则内核尚未 reap 的退出过程会被误判成泄漏。
    """
    found: list[int] = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open("/proc/%s/cgroup" % entry, encoding="utf-8") as fh:
                content = fh.read()
        except OSError:
            continue
        if token in content and not _is_zombie(pid):
            found.append(pid)
    return sorted(found)


def sweep_orphan_cgroups(token: str) -> list[str]:
    """清理崩溃遗留的空 cgroup 目录（进程已死但目录还在的情况）。有进程在里面的不碰。"""
    base = find_writable_base()
    if base is None:
        return []
    removed: list[str] = []
    try:
        names = os.listdir(base)
    except OSError:
        return []
    for name in names:
        if not name.startswith("esbx-") or token not in name:
            continue
        path = os.path.join(base, name)
        try:
            with open(os.path.join(path, "cgroup.procs"), encoding="utf-8") as fh:
                if fh.read().strip():
                    continue
            os.rmdir(path)
            removed.append(name)
        except OSError:
            continue
    return sorted(removed)
