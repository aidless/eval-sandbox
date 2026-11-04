"""命令行入口。

    python3 -m eval_sandbox.cli check    # 单任务隔离判据
    python3 -m eval_sandbox.cli fleet    # 并发车队判据

两条命令都输出 PASS/FAIL 汇总；任何一条不通过（包括"隔离能力根本拿不到"）都以非 0 退出。
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
import time
import uuid

from . import cases as case_module
from .cgroup import sweep_orphan_cgroups
from .sandbox import (
    RunResult, SandboxUnavailable, capabilities, cpu_usage_within_quota, run,
)


def _print_caps(caps: dict) -> None:
    print("运行环境探测")
    print("  bwrap            : %s" % (caps["bwrap"] or "缺失"))
    print("  cgroup v2 可写子树: %s" % (caps["cgroup_base"] or "不可用"))
    print("  unshare          : %s" % (caps["unshare"] or "缺失"))
    print("  unprivileged userns: %s" % (caps["userns_unprivileged"] or "未开启"))
    print()


def _fmt_row(cid: str, kind: str, outcome: str, passed: bool) -> str:
    return "%-24s %-12s %-16s %s" % (
        cid, kind, outcome, "PASS" if passed else "FAIL")


def run_case(case, repeats: int = None) -> dict:
    repeats = repeats or case.repeats
    runs: list[RunResult] = []
    started = time.monotonic()
    try:
        for _ in range(repeats):
            runs.append(run(list(case.argv), case.policy, task_id=case.cid))
    except SandboxUnavailable as exc:
        return {
            "cid": case.cid, "kind": case.kind, "passed": False,
            "outcome": "unavailable",
            "detail": "隔离能力不可用：%s" % exc,
            "duration_s": time.monotonic() - started,
        }

    first = runs[0]
    digests = [r.verdict_sha256 for r in runs]
    if repeats > 1:
        passed = len(set(digests)) == 1
        detail = "3 次 sha256=%s（%s）" % (
            digests[0], "全部一致" if passed else "不一致：" + ",".join(digests))
    else:
        passed, detail = case.check(first)
    return {
        "cid": case.cid,
        "kind": case.kind,
        "passed": passed,
        "outcome": first.outcome,
        "detail": detail,
        "duration_s": first.duration_s,
        "sandbox_id": first.sandbox_id,
        "verdict_sha256": first.verdict_sha256,
        "runs": [
            {
                "outcome": r.outcome,
                "exit_code": r.exit_code,
                "duration_s": round(r.duration_s, 4),
                "sandbox_id": r.sandbox_id,
                "verdict_sha256": r.verdict_sha256,
                "stdout": r.stdout.strip()[:400],
                "stderr": r.stderr.strip()[:400],
                "evidence": {
                    "memory_peak_bytes": r.evidence.get("memory_peak_bytes"),
                    "memory_events": r.evidence.get("memory_events", {}),
                    "cpu_stat": r.evidence.get("cpu_stat", {}),
                    "applied_limits": r.evidence.get("applied_limits", {}),
                    "mechanism": r.evidence.get("mechanism"),
                },
            }
            for r in runs
        ],
    }


def _run_check(args) -> int:
    caps = capabilities()
    if not args.quiet:
        _print_caps(caps)

    own_workdir = args.workdir is None
    workdir = args.workdir or tempfile.mkdtemp(prefix="esbx-work-")
    forbidden_dir = tempfile.mkdtemp(prefix="esbx-forbidden-")
    forbidden = os.path.join(forbidden_dir, "secret.txt")
    with open(forbidden, "w", encoding="utf-8") as fh:
        fh.write("host-only\n")

    results: list[dict] = []
    try:
        for case in case_module.case_set(workdir, forbidden):
            res = run_case(case)
            results.append(res)
            if not args.quiet:
                print(_fmt_row(res["cid"], res["kind"], res["outcome"], res["passed"]))
                print("    %s" % res["detail"])
    finally:
        shutil.rmtree(forbidden_dir, ignore_errors=True)
        if own_workdir:
            shutil.rmtree(workdir, ignore_errors=True)

    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    print()
    print("SUMMARY: %d/%d PASS%s" % (passed, total, "" if passed == total else "  (%d FAIL)" % (total - passed)))

    evidence = {
        "generated_by": "eval_sandbox.cli check",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "capabilities": caps,
        "summary": {"passed": passed, "total": total, "all_passed": passed == total},
        "results": results,
    }
    _write_evidence(args.evidence, evidence)
    print("evidence -> %s" % args.evidence)
    return 0 if passed == total else 1


def _write_evidence(path: str, payload: dict) -> None:
    if os.path.dirname(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=True)


# ---------------------------------------------------------------- fleet

def _ledger(result: RunResult, kind: str, attribution: str) -> dict:
    peak = result.evidence.get("memory_peak_bytes") or 0
    cpu = result.evidence.get("cpu_stat", {})
    return {
        "task_id": result.task_id,
        "kind": kind,
        "outcome": result.outcome,
        "attribution": attribution,
        "exit_code": result.exit_code,
        "wall_s": round(result.duration_s, 3),
        "memory_peak_bytes": peak,
        "cpu_usage_usec": cpu.get("usage_usec", 0),
        "cpu_throttled_usec": cpu.get("throttled_usec", 0),
        "sandbox_id": result.sandbox_id,
        "verdict_sha256": result.verdict_sha256,
    }


def _run_fleet(args) -> int:
    from .fleet import (
        FleetConfig, attribute, build_fault_specs, build_specs, fleet_digest,
        leak_test, run_fleet, task_event, wait_for_no_residual,
    )

    caps = capabilities()
    token = uuid.uuid4().hex[:8]
    root = tempfile.mkdtemp(prefix="esbx-fleet-")
    cfg = FleetConfig(root=root, spin_seconds=args.spin)
    specs = build_specs(cfg, args.tasks)
    kind_of = {s.cid: s.kind for s in specs}

    print("eval-fleet  token=%s  tasks=%d  spin=%.2fs  cpu_quota=%d%%" % (
        token, len(specs), cfg.spin_seconds, cfg.cpu_quota_pct))
    print("  bwrap=%s  cgroup=%s" % (caps["bwrap"], caps["cgroup_base"]))
    print()

    checks: list[dict] = []
    evidence: dict = {"generated_by": "eval_sandbox.cli fleet",
                      "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      "token": token, "tasks": args.tasks,
                      "capabilities": caps, "checks": checks}

    try:
        # 串行基线
        t0 = time.monotonic()
        run_fleet(specs, cfg, workers=1, run_token=token)
        t_serial = time.monotonic() - t0

        # 并发
        t0 = time.monotonic()
        conc = run_fleet(specs, cfg, workers=len(specs), run_token=token)
        t_conc = time.monotonic() - t0
        residual_after_conc = wait_for_no_residual(token)

        print("并发 vs 串行：串行 %.2fs / 并发 %.2fs（%d 个任务，加速 %.1fx）" % (
            t_serial, t_conc, len(specs), t_serial / max(t_conc, 1e-6)))
        print()

        checks.append({
            "id": "C1_concurrency", "passed": t_conc < 0.5 * t_serial,
            "detail": "serial=%.2fs concurrent=%.2fs speedup=%.1fx" % (
                t_serial, t_conc, t_serial / max(t_conc, 1e-6)),
        })

        # C2 并发隔离不退化
        net_ok = 0
        mem_ok = 0
        cpu_ok = 0
        cgroup_paths = set()
        failures: list[str] = []
        for r in conc:
            ev = task_event(r)
            if ev.get("net") == "denied:101":
                net_ok += 1
            elif r.outcome != "oom":
                failures.append("%s net=%r" % (r.task_id, ev.get("net")))
            limit = cfg.oom_memory_bytes if kind_of[r.task_id.rsplit("-", 1)[-1]] == "oom" else cfg.memory_bytes
            peak = r.evidence.get("memory_peak_bytes") or 0
            if peak <= limit:
                mem_ok += 1
            else:
                failures.append("%s peak=%d>%d" % (r.task_id, peak, limit))
            cpu = r.evidence.get("cpu_stat", {})
            ok_cpu, why_cpu = cpu_usage_within_quota(
                cpu.get("usage_usec", 0), cpu.get("throttled_usec", 0),
                r.duration_s, cfg.cpu_quota_pct)
            if ok_cpu:
                cpu_ok += 1
            else:
                failures.append("%s cpu %s" % (r.task_id, why_cpu))
            cgroup_paths.add(r.evidence.get("cgroup_path"))
        passed_c2 = (net_ok == len(conc) and mem_ok == len(conc)
                     and cpu_ok == len(conc) and len(cgroup_paths) == len(conc))
        checks.append({
            "id": "C2_isolation_no_degradation", "passed": passed_c2,
            "detail": "net_denied=%d/%d mem_within_limit=%d/%d cpu_quota_ok=%d/%d distinct_cgroups=%d/%d%s" % (
                net_ok, len(conc), mem_ok, len(conc), cpu_ok, len(conc),
                len(cgroup_paths), len(conc), (" failures=" + "; ".join(failures)) if failures else ""),
        })

        # C3 跨任务文件不可见
        writer = next(r for r in conc if r.task_id.endswith("fs_writer"))
        reader = next(r for r in conc if r.task_id.endswith("fs_reader"))
        w_ev, r_ev = task_event(writer), task_event(reader)
        passed_c3 = (w_ev.get("shared") == "visible"
                     and str(r_ev.get("shared", "")).startswith("absent:2"))
        checks.append({
            "id": "C3_cross_task_invisible", "passed": passed_c3,
            "detail": "writer(/work/shared.txt)=%r reader(同名重试10次)=%r" % (
                w_ev.get("shared"), r_ev.get("shared")),
        })

        # C4 OOM 只杀一个
        oom = [r for r in conc if r.outcome == "oom"]
        done = [r for r in conc if r.outcome == "ok"]
        passed_c4 = len(oom) == 1 and len(done) == len(conc) - 1
        checks.append({
            "id": "C4_oom_isolated", "passed": passed_c4,
            "detail": "started=%d ok=%d oom=%d oom_task=%s" % (
                len(conc), len(done), len(oom),
                oom[0].task_id.rsplit("-", 1)[-1] if oom else "none"),
        })

        # C5 无孤儿进程（含杀编排器的泄漏测试）
        t0 = time.monotonic()
        leak = leak_test(token)
        leak_secs = time.monotonic() - t0
        passed_c5 = not residual_after_conc and leak["passed"]
        checks.append({
            "id": "C5_no_orphans", "passed": passed_c5,
            "detail": "after_run=%s leak_probe_observed=%s residual_after_kill=%s swept=%d dirs (%.1fs)" % (
                residual_after_conc, leak["sandbox_pids_observed"], leak["residual_after_kill"],
                len(leak["swept_cgroup_dirs"]), leak_secs),
        })

        # C7 三次重跑确定性（conc 作为第 1 次）
        repeats = [conc]
        for _ in range(2):
            repeats.append(run_fleet(specs, cfg, workers=len(specs), run_token=token))
        digests = [fleet_digest(r) for r in repeats]
        per_task_same = all(
            [x.verdict_sha256 for x in sorted(rep, key=lambda y: y.task_id)] ==
            [x.verdict_sha256 for x in sorted(repeats[0], key=lambda y: y.task_id)]
            for rep in repeats)
        passed_c7 = len(set(digests)) == 1 and per_task_same
        checks.append({
            "id": "C7_determinism", "passed": passed_c7,
            "detail": "aggregate_sha256=%s (%s) per_task_identical=%s" % (
                digests[0], "一致" if len(set(digests)) == 1 else "不一致", per_task_same),
        })

        # 故障集：四类归因
        faults = run_fleet(build_fault_specs(), cfg, workers=4, run_token=token)
        attributions_main = {attribute(r) for r in conc}
        attributions_fault = {attribute(r) for r in faults}
        needed = {"wall_timeout", "denied_fs", "denied_network", "nonzero_exit"}
        passed_c6 = needed <= (attributions_main | attributions_fault)
        checks.append({
            "id": "C6_ledger_attribution", "passed": passed_c6,
            "detail": "attributions=%s" % ",".join(sorted(attributions_main | attributions_fault)),
        })

        # 资源账表
        print("每任务资源账（主车队 %d + 故障集 %d）" % (len(conc), len(faults)))
        print("%-24s %-10s %-13s %-15s %7s %9s %8s  %s" % (
            "task_id", "kind", "outcome", "attribution", "wall_s", "peak_MB", "cpu_ms", "sha256"))
        rows = []
        for r in conc:
            cid = r.task_id.rsplit("-", 1)[-1]
            rows.append(_ledger(r, kind_of[cid], attribute(r)))
        for r, s in zip(faults, build_fault_specs()):
            rows.append(_ledger(r, s.kind, attribute(r)))
        for row in rows:
            print("%-24s %-10s %-13s %-15s %7.2f %9.1f %8.0f  %s" % (
                row["task_id"], row["kind"], row["outcome"], row["attribution"],
                row["wall_s"], row["memory_peak_bytes"] / (1024 * 1024),
                row["cpu_usage_usec"] / 1000.0, row["verdict_sha256"][:10]))
        print()

        for check in checks:
            print("%-32s %s  %s" % (check["id"], "PASS" if check["passed"] else "FAIL", check["detail"]))
        passed = sum(1 for c in checks if c["passed"])
        print()
        print("SUMMARY: %d/%d PASS" % (passed, len(checks)))

        evidence.update({
            "timing": {"serial_s": round(t_serial, 3), "concurrent_s": round(t_conc, 3)},
            "digests": digests,
            "ledger": rows,
            "leak_test": leak,
            "summary": {"passed": passed, "total": len(checks), "all_passed": passed == len(checks)},
        })
        for check in checks:
            check.pop("detail", None)
        _write_evidence(args.evidence, evidence)
        print("evidence -> %s" % args.evidence)
        return 0 if passed == len(checks) else 1
    except SandboxUnavailable as exc:
        # fail closed：拿不到命名空间/cgroup 就判 FAIL，绝不当成"跑过了"。
        print()
        print("ISOLATION_UNAVAILABLE      FAIL  %s" % exc)
        print("SUMMARY: 0/1 PASS  (隔离能力不可用，不降级)")
        checks.append({"id": "C0_isolation_available", "passed": False})
        evidence["summary"] = {"passed": 0, "total": 1, "all_passed": False,
                              "error": "SandboxUnavailable: %s" % exc}
        _write_evidence(args.evidence, evidence)
        return 1
    finally:
        sweep_orphan_cgroups(token)
        shutil.rmtree(root, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="eval-sandbox", description="任务级沙盒 / 评测车队自检")
    parser.add_argument("command", nargs="?", default="check", choices=["check", "fleet"],
                        help="check = 单任务隔离判据；fleet = 并发车队判据")
    parser.add_argument("--workdir", default=None, help="沙盒工作目录（默认建临时目录）")
    parser.add_argument("--evidence", default="evidence/run.json", help="证据 JSON 输出路径")
    parser.add_argument("--quiet", action="store_true", help="只打印汇总")
    parser.add_argument("--tasks", type=int, default=20, help="fleet 并发任务数")
    parser.add_argument("--spin", type=float, default=0.4, help="fleet 每任务 CPU 空转秒数")
    args = parser.parse_args(argv)

    if args.command == "fleet":
        if args.evidence == "evidence/run.json":
            args.evidence = "evidence/fleet.json"
        return _run_fleet(args)
    return _run_check(args)


if __name__ == "__main__":
    raise SystemExit(main())
