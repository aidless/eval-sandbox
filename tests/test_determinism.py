"""确定性：同一负载重复运行，判决 sha256 完全一致。"""
from eval_sandbox import Policy, run
from eval_sandbox.cases import DETERMINISTIC, _py


def test_three_runs_share_verdict_sha256(workdir):
    policy = Policy(workdir=workdir, memory_bytes=128 * 1024 * 1024, wall_seconds=5)
    digests = [run(list(_py(DETERMINISTIC)), policy, task_id="det").verdict_sha256
               for _ in range(3)]
    assert len(set(digests)) == 1, "三次判决 sha256 不一致：%r" % (digests,)
    assert len(digests[0]) == 64


def test_verdict_changes_when_output_changes(workdir):
    policy = Policy(workdir=workdir, memory_bytes=128 * 1024 * 1024, wall_seconds=5)
    a = run(list(_py("print('A')")), policy, task_id="det")
    b = run(list(_py("print('B')")), policy, task_id="det")
    assert a.verdict_sha256 != b.verdict_sha256
