"""任务级沙盒隔离：bwrap 命名空间隔离 + cgroup v2 资源上限 + 可归因判决。"""
from .policy import Policy
from .sandbox import (
    RunResult,
    SandboxUnavailable,
    capabilities,
    classify_outcome,
    run,
    verdict_payload,
    verdict_sha256,
)

__all__ = [
    "Policy",
    "RunResult",
    "SandboxUnavailable",
    "capabilities",
    "classify_outcome",
    "run",
    "verdict_payload",
    "verdict_sha256",
]
