"""文件系统隔离：越权读、越权写被拒；工作目录可读写。"""
from eval_sandbox import Policy, run
from eval_sandbox.cases import READ_PATH, WORKDIR_RW, WRITE_PATH, _py


def _policy(workdir):
    return Policy(workdir=workdir, memory_bytes=128 * 1024 * 1024, wall_seconds=5)


def test_read_outside_workdir_denied(workdir, forbidden_path):
    result = run(list(_py(READ_PATH, forbidden_path)), _policy(workdir), task_id="fs-read")
    assert result.outcome != "ok"
    assert "DENIED" in result.stderr
    assert "No such file" in result.stderr


def test_write_to_system_path_denied(workdir):
    result = run(list(_py(WRITE_PATH, "/usr/lib/.esbx-write-probe")),
                 _policy(workdir), task_id="fs-write")
    assert result.outcome != "ok"
    assert "DENIED" in result.stderr
    assert "Read-only file system" in result.stderr


def test_workdir_is_readwrite(workdir):
    result = run(list(_py(WORKDIR_RW)), _policy(workdir), task_id="fs-rw")
    assert result.outcome == "ok"
    assert "WORKDIR_RW_OK" in result.stdout
