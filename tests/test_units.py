"""纯函数单测：策略校验、归因分类、判决摘要规范化、cgroup 探测。"""
import pytest

from eval_sandbox import Policy, classify_outcome, verdict_payload, verdict_sha256
from eval_sandbox.cgroup import find_writable_base
from eval_sandbox.sandbox import build_bwrap_argv, capabilities


def test_policy_rejects_relative_workdir():
    with pytest.raises(ValueError):
        Policy(workdir="relative/dir")


def test_policy_rejects_unimplemented_network_mode(tmp_path):
    with pytest.raises(ValueError):
        Policy(workdir=str(tmp_path), network="whitelist")


def test_policy_rejects_out_of_range_limits(tmp_path):
    with pytest.raises(ValueError):
        Policy(workdir=str(tmp_path), memory_bytes=1024)
    with pytest.raises(ValueError):
        Policy(workdir=str(tmp_path), cpu_quota_pct=0)
    with pytest.raises(ValueError):
        Policy(workdir=str(tmp_path), pids_max=4097)
    with pytest.raises(ValueError):
        Policy(workdir=str(tmp_path), wall_seconds=0)


@pytest.mark.parametrize("deadline,oom,rc,expected", [
    (True, 0, -9, "wall_timeout"),
    (False, 1, -9, "oom"),
    (False, 0, 0, "ok"),
    (False, 0, 3, "nonzero_exit"),
    (False, 0, -11, "killed_by_signal"),
    (False, 0, None, "unknown"),
])
def test_classify_outcome(deadline, oom, rc, expected):
    assert classify_outcome(deadline, oom, rc) == expected


def test_verdict_sha_is_canonical_and_stable(tmp_path):
    policy = Policy(workdir=str(tmp_path))
    p1 = verdict_payload("t", "ok", 0, "x", "", policy)
    p2 = verdict_payload("t", "ok", 0, "x", "", policy)
    assert verdict_sha256(p1) == verdict_sha256(p2)
    # 键顺序不影响摘要（canonical JSON 按 key 排序）
    reordered = dict(reversed(list(p1.items())))
    assert verdict_sha256(reordered) == verdict_sha256(p1)


def test_verdict_sha_distinguishes_outcome(tmp_path):
    policy = Policy(workdir=str(tmp_path))
    assert verdict_sha256(verdict_payload("t", "ok", 0, "", "", policy)) != \
        verdict_sha256(verdict_payload("t", "oom", 0, "", "", policy))


def test_bwrap_argv_requests_full_namespace_isolation(tmp_path):
    policy = Policy(workdir=str(tmp_path))
    argv = build_bwrap_argv(policy, ["echo", "hi"])
    assert "--unshare-all" in argv
    assert "--clearenv" in argv
    assert argv.count("--bind") == 1  # 只把 workdir 绑成可写


def test_capabilities_report_real_paths():
    caps = capabilities()
    assert caps["bwrap"] is not None, "本机缺少 bwrap，测试前提不成立"
    assert find_writable_base(), "本机没有可写的 cgroup v2 子树，测试前提不成立"
