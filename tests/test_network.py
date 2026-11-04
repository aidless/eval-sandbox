"""网络隔离：外网必须连不通且报错可读；同一沙盒内的 loopback 必须可用。"""
import subprocess

from eval_sandbox import Policy, run
from eval_sandbox.cases import LOOPBACK, NET_EXTERNAL, _py
from eval_sandbox.sandbox import build_bwrap_argv


def _policy(workdir):
    return Policy(workdir=workdir, memory_bytes=128 * 1024 * 1024, wall_seconds=5)


def test_external_network_denied_with_readable_error(workdir):
    result = run(list(_py(NET_EXTERNAL)), _policy(workdir), task_id="net-denied")
    assert result.outcome != "ok", "沙盒内竟然连上了外网"
    assert "DENIED" in result.stderr, "被拒但没有可读的错误信息：%r" % result.stderr
    # 立即返回而不是等到墙钟：证明是"拒绝"不是"静默超时"
    assert result.duration_s < 2.0


def test_loopback_allowed_inside_sandbox(workdir):
    result = run(list(_py(LOOPBACK)), _policy(workdir), task_id="net-loopback")
    assert result.outcome == "ok"
    assert "LOOPBACK_OK" in result.stdout


def test_denial_comes_from_netns_not_from_upstream(workdir):
    """负控制：保留宿主网络命名空间（--share-net）时，不能再出现内核级 ENETUNREACH。

    若两条路径的报错相同，说明"外连被拒"只是本机没网造成的巧合，隔离并未生效。
    """
    policy = _policy(workdir)
    argv = build_bwrap_argv(policy, []) + ["--share-net"] + list(_py(NET_EXTERNAL))
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=20)
    assert "Network is unreachable" not in proc.stderr, (
        "共享宿主 netns 后仍是 ENETUNREACH，网络拒绝与命名空间无关：%r" % proc.stderr
    )

