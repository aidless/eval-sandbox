"""资源上限：墙钟、内存、CPU 配额生效，且三类失败的归因互不混淆。"""
import subprocess

from eval_sandbox import Policy, run
from eval_sandbox.cases import CPU_SPIN, FORK_BOMB, MEMORY_BOMB, WALL_SPIN, _py

LIMIT = 64 * 1024 * 1024


def test_wall_clock_kills_infinite_loop(workdir):
    policy = Policy(workdir=workdir, memory_bytes=128 * 1024 * 1024, wall_seconds=2)
    result = run(list(_py(WALL_SPIN)), policy, task_id="wall")
    assert result.outcome == "wall_timeout"
    assert result.duration_s >= 1.9


def test_memory_limit_kills_with_oom_attribution(workdir):
    policy = Policy(workdir=workdir, memory_bytes=LIMIT, wall_seconds=10)
    result = run(list(_py(MEMORY_BOMB)), policy, task_id="oom")
    assert result.outcome == "oom"
    assert result.evidence["memory_events"]["oom_kill"] >= 1
    assert result.evidence["memory_peak_bytes"] <= LIMIT * 1.02
    assert "ALLOC_OK" not in result.stdout


def test_cpu_quota_throttles_busy_loop(workdir):
    policy = Policy(workdir=workdir, cpu_quota_pct=50, wall_seconds=8)
    result = run(list(_py(CPU_SPIN)), policy, task_id="cpu")
    assert result.outcome == "ok"
    assert result.evidence["cpu_stat"]["throttled_usec"] > 0
    usage = result.evidence["cpu_stat"]["usage_usec"]
    assert usage <= int(result.duration_s * 1_000_000 * 0.75)


def test_timeout_and_oom_are_distinguishable(workdir):
    wall = run(list(_py(WALL_SPIN)),
               Policy(workdir=workdir, memory_bytes=128 * 1024 * 1024, wall_seconds=2),
               task_id="wall")
    oom = run(list(_py(MEMORY_BOMB)),
              Policy(workdir=workdir, memory_bytes=LIMIT, wall_seconds=10),
              task_id="oom")
    assert wall.outcome == "wall_timeout"
    assert oom.outcome == "oom"
    assert wall.evidence["memory_events"].get("oom_kill", 0) == 0
    assert wall.evidence["deadline_hit"] is True


def test_memory_bomb_would_succeed_without_cgroup_limit(workdir):
    """负控制：同一负载在宿主上能分配成功，证明它确实是"被 64MB 上限杀掉的"。"""
    proc = subprocess.run(list(_py(MEMORY_BOMB)), capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0
    assert "ALLOC_OK" in proc.stdout


def test_pids_limit_blocks_fork_bomb(workdir):
    policy = Policy(workdir=workdir, pids_max=16, wall_seconds=8)
    result = run(list(_py(FORK_BOMB)), policy, task_id="pids")
    assert result.outcome != "ok"
    assert "DENIED" in result.stderr
    assert "FORKED_ALL" not in result.stdout
