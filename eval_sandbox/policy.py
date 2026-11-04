"""一次沙盒任务的资源与访问策略。

每个字段都有明确上下界：越界直接 ValueError，而不是静默回落到默认值——沙盒
配置写错时必须炸出声音，不能"看起来跑通了"。
"""
from __future__ import annotations

import os
from dataclasses import dataclass

MIN_MEMORY_BYTES = 8 * 1024 * 1024

# 只实现"完全断网"。白名单出网需要 veth/slirp 一类的东西，本机无 root 做不到，
# 所以这里不放一个能赋值但实际不生效的开关。
SUPPORTED_NETWORK_MODES = ("none",)


@dataclass(frozen=True)
class Policy:
    workdir: str
    memory_bytes: int = 256 * 1024 * 1024
    cpu_quota_pct: int = 100
    pids_max: int = 64
    wall_seconds: float = 10.0
    network: str = "none"
    ro_binds: tuple[str, ...] = ("/usr", "/lib", "/lib64")

    def __post_init__(self) -> None:
        if not os.path.isabs(self.workdir):
            raise ValueError("workdir 必须是绝对路径：%r" % (self.workdir,))
        if not os.path.isdir(self.workdir):
            raise ValueError("workdir 不存在或不是目录：%r" % (self.workdir,))
        if self.network not in SUPPORTED_NETWORK_MODES:
            raise ValueError(
                "network=%r 未实现；当前只支持 %s（白名单出网没有落地，不接受假开关）"
                % (self.network, ", ".join(SUPPORTED_NETWORK_MODES))
            )
        if not MIN_MEMORY_BYTES <= self.memory_bytes <= 64 * 1024 * 1024 * 1024:
            raise ValueError("memory_bytes 越界：%r" % (self.memory_bytes,))
        if not 1 <= self.cpu_quota_pct <= 800:
            raise ValueError("cpu_quota_pct 越界（1-800）：%r" % (self.cpu_quota_pct,))
        if not 8 <= self.pids_max <= 4096:
            raise ValueError("pids_max 越界（8-4096）：%r" % (self.pids_max,))
        if not 0.1 <= self.wall_seconds <= 600:
            raise ValueError("wall_seconds 越界（0.1-600）：%r" % (self.wall_seconds,))

    def limits(self) -> dict:
        """参与判决摘要的稳定字段；不含耗时、峰值等易变值。"""
        return {
            "memory_bytes": self.memory_bytes,
            "cpu_quota_pct": self.cpu_quota_pct,
            "pids_max": self.pids_max,
            "wall_seconds": self.wall_seconds,
            "network": self.network,
        }
