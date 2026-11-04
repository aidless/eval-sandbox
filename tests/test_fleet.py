"""eval-fleet 的判据测试：并发下隔离不退化、互不干扰、限额独立、无孤儿、确定性。

为了 pytest 跑得动，这里的规模比 CLI 的 20 任务小（N=5，spin=0.15s），
但断言口径与 CLI 完全一致。
"""
from __future__ import annotations

import time
import types
import uuid

import pytest

from eval_sandbox.fleet import (
    FleetConfig,
    RunResult,
    attribute,
    build_fault_specs,
    build_specs,
    build_standard_specs,
    fleet_digest,
    leak_test,
    run_fleet,
    task_event,
    wait_for_no_residual,
)
from eval_sandbox.sandbox import cpu_usage_within_quota


def _make_result(task_id: str, outcome: str, stdout: str = "", stderr: str = "") -> RunResult:
    return RunResult(
        task_id=task_id, outcome=outcome, exit_code=0 if outcome == "ok" else 1,
        duration_s=1.0, stdout=stdout, stderr=stderr,
        verdict_sha256="sha-" + task_id, sandbox_id="sbx-" + task_id, evidence={},
    )


@pytest.fixture(scope="module")
def fleet(tmp_path_factory):
    root = str(tmp_path_factory.mktemp("fleet"))
    cfg = FleetConfig(root=root, spin_seconds=0.15, memory_bytes=64 * 1024 * 1024,
                      oom_memory_bytes=48 * 1024 * 1024, cpu_quota_pct=50, wall_seconds=6.0)
    token = uuid.uuid4().hex[:8]
    specs = build_specs(cfg, 5)

    started = time.monotonic()
    conc = run_fleet(specs, cfg, workers=len(specs), run_token=token)
    t_conc = time.monotonic() - started

    return types.SimpleNamespace(
        cfg=cfg, token=token, specs=specs, conc=conc, t_conc=t_conc,
        kind_of={s.cid: s.kind for s in specs},
        by_cid={r.task_id.rsplit("-", 1)[-1]: r for r in conc},
    )


# ---------------------------------------------------------------- 单元层

def test_build_specs_has_writer_reader_oom():
    specs = build_specs(FleetConfig(root="/tmp"), 6)
    assert len(specs) == 6
    kinds = [s.kind for s in specs]
    assert kinds.count("standard") == 3
    assert kinds[-3:] == ["writer", "reader", "oom"]
    assert len({s.cid for s in specs}) == len(specs)


def test_build_specs_rejects_too_few():
    with pytest.raises(ValueError):
        build_specs(FleetConfig(root="/tmp"), 3)


def test_attribute_distinguishes_four_failure_classes():
    assert attribute(_make_result("a", "wall_timeout")) == "wall_timeout"
    assert attribute(_make_result("b", "oom")) == "oom"
    assert attribute(_make_result("c", "nonzero_exit", stderr="DENIED_FS errno=30")) == "denied_fs"
    assert attribute(_make_result("d", "nonzero_exit", stderr="DENIED_NET errno=101")) == "denied_network"
    assert attribute(_make_result("e", "nonzero_exit")) == "nonzero_exit"
    assert attribute(_make_result("f", "ok")) == "ok"
    assert {s.kind for s in build_fault_specs()} == {
        "timeout", "fs_denied", "net_denied", "nonzero"}


def test_fleet_digest_is_order_independent():
    a = _make_result("fleet-t00", "ok")
    b = _make_result("fleet-t01", "ok")
    c = _make_result("fleet-mem_oom", "oom")
    assert fleet_digest([a, b, c]) == fleet_digest([c, a, b])
    assert fleet_digest([a, b, c]) != fleet_digest([a, b, _make_result("fleet-t02", "ok")])


def test_label_is_separate_from_stable_task_id(fleet):
    """cgroup 名字带本轮 token（便于按标识查孤儿），判决里的 task_id 不带（便于跨重跑比 sha）。"""
    for result in fleet.conc:
        assert result.task_id == "fleet-" + result.task_id.rsplit("-", 1)[-1]
        assert fleet.token in result.evidence["cgroup_path"]


# ---------------------------------------------------------------- 并发层

def test_concurrent_is_faster_than_serial(tmp_path):
    """同构 8 任务：并发墙钟必须不到串行的一半。"""
    cfg = FleetConfig(root=str(tmp_path), spin_seconds=0.2, memory_bytes=64 * 1024 * 1024,
                      cpu_quota_pct=50, wall_seconds=6.0)
    specs = build_standard_specs(cfg, 8)

    started = time.monotonic()
    serial = run_fleet(specs, cfg, workers=1, run_token="spdup-serial")
    t_serial = time.monotonic() - started

    started = time.monotonic()
    conc = run_fleet(specs, cfg, workers=len(specs), run_token="spdup-conc")
    t_conc = time.monotonic() - started

    assert len(serial) == len(conc) == len(specs)
    assert all(r.outcome == "ok" for r in conc)
    assert t_conc < 0.5 * t_serial, "serial=%.2fs concurrent=%.2fs" % (t_serial, t_conc)


def test_each_concurrent_task_is_still_network_denied(fleet):
    for result in fleet.conc:
        ev = task_event(result)
        assert ev.get("net") == "denied:101", (result.task_id, result.stdout, result.stderr)


def test_each_concurrent_task_has_its_own_cgroup_within_its_own_limit(fleet):
    paths = set()
    for result in fleet.conc:
        limit = (fleet.cfg.oom_memory_bytes if fleet.kind_of[result.task_id.rsplit("-", 1)[-1]] == "oom"
                 else fleet.cfg.memory_bytes)
        peak = result.evidence["memory_peak_bytes"]
        paths.add(result.evidence["cgroup_path"])
        assert peak <= limit * 1.05, "%s peak=%d limit=%d" % (result.task_id, peak, limit)
        assert result.evidence["applied_limits"]["memory.max"] == str(limit)
    assert len(paths) == len(fleet.conc)


def test_cpu_quota_effective_per_task_under_concurrency(fleet):
    for result in fleet.conc:
        cpu = result.evidence["cpu_stat"]
        ok, why = cpu_usage_within_quota(
            cpu["usage_usec"], cpu["throttled_usec"], result.duration_s,
            fleet.cfg.cpu_quota_pct)
        assert ok, (result.task_id, why)


def test_same_filename_is_not_shared_between_tasks(fleet):
    writer = fleet.by_cid["fs_writer"]
    reader = fleet.by_cid["fs_reader"]
    assert task_event(writer)["shared"] == "visible"
    assert str(task_event(reader)["shared"]).startswith("absent:2")


def test_oom_kills_only_the_offending_task(fleet):
    oom = [r for r in fleet.conc if r.outcome == "oom"]
    assert [r.task_id for r in oom] == ["fleet-mem_oom"]
    assert len([r for r in fleet.conc if r.outcome == "ok"]) == len(fleet.conc) - 1
    assert oom[0].evidence["memory_events"]["oom_kill"] >= 1


def test_no_orphans_after_fleet(fleet):
    assert wait_for_no_residual(fleet.token) == []


def test_three_repeats_have_identical_digests(fleet):
    repeats = [fleet.conc]
    for _ in range(2):
        repeats.append(run_fleet(fleet.specs, fleet.cfg, workers=len(fleet.specs),
                                 run_token=fleet.token))
    assert len({fleet_digest(r) for r in repeats}) == 1
    baseline = [r.verdict_sha256 for r in sorted(repeats[0], key=lambda x: x.task_id)]
    for rep in repeats[1:]:
        assert [r.verdict_sha256 for r in sorted(rep, key=lambda x: x.task_id)] == baseline


def test_killing_orchestrator_leaves_no_sandbox_processes(tmp_path):
    """leak test：编排器被 SIGKILL 后，沙盒进程不残留（按 cgroup 标识断言）。"""
    token = "lk" + uuid.uuid4().hex[:8]
    report = leak_test(token)
    assert report["sandbox_pids_observed"], "没观察到沙盒进程，说明泄漏测试没测到东西"
    assert report["residual_after_kill"] == []
    assert report["passed"] is True
    assert wait_for_no_residual(token) == []


def test_missing_cgroup_delegation_fails_closed(monkeypatch, tmp_path):
    """拿不到 cgroup 委托时必须炸，不能静默降级成"没限额也算过"。"""
    import eval_sandbox.cgroup as cgroup_module
    from eval_sandbox.policy import Policy
    from eval_sandbox.sandbox import SandboxUnavailable, run

    monkeypatch.setattr(cgroup_module, "find_writable_base", lambda: None)
    work = tmp_path / "w"
    work.mkdir()
    with pytest.raises(SandboxUnavailable):
        run(["/bin/echo", "hi"], Policy(workdir=str(work)))


def test_fleet_cli_fails_closed_without_cgroup(monkeypatch, tmp_path):
    import json

    import eval_sandbox.cgroup as cgroup_module
    from eval_sandbox import cli

    monkeypatch.setattr(cgroup_module, "find_writable_base", lambda: None)
    evidence_path = tmp_path / "e.json"
    rc = cli.main(["fleet", "--tasks", "4", "--evidence", str(evidence_path)])
    assert rc == 1
    assert json.loads(evidence_path.read_text(encoding="utf-8"))["summary"]["all_passed"] is False
