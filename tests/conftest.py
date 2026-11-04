import shutil

import pytest

from eval_sandbox.cgroup import find_writable_base

# 这些文件里的用例会真的调 bwrap / 建 cgroup 子组，需要特权主机。
INTEGRATION_TESTS = {
    "test_filesystem.py",
    "test_network.py",
    "test_resources.py",
    "test_fleet.py",
    "test_determinism.py",
}

# 单测文件里断言"本机确实具备前置能力"或直接构造 bwrap argv 的用例，同样需要特权主机。
HOST_PREREQ_TESTS = {
    "test_capabilities_report_real_paths",
    "test_bwrap_argv_requests_full_namespace_isolation",
}


def _prereq_gap() -> str | None:
    if shutil.which("bwrap") is None:
        return "bwrap 未安装"
    if find_writable_base() is None:
        return "没有可写的 cgroup v2 子树"
    return None


def pytest_collection_modifyitems(config, items):
    """缺前置条件时显式跳过集成用例，而不是让它们假绿或假红。"""
    gap = _prereq_gap()
    if gap is None:
        return
    skip = pytest.mark.skip(reason=f"集成用例需要特权主机：{gap}")
    for item in items:
        if item.path.name in INTEGRATION_TESTS or item.name in HOST_PREREQ_TESTS:
            item.add_marker(skip)


@pytest.fixture()
def workdir(tmp_path):
    d = tmp_path / "work"
    d.mkdir()
    return str(d)


@pytest.fixture()
def forbidden_path(tmp_path):
    d = tmp_path / "host_only"
    d.mkdir()
    p = d / "secret.txt"
    p.write_text("host-only\n", encoding="utf-8")
    return str(p)
