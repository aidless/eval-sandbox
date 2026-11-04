"""一条命令跑完全部判据，输出 PASS/FAIL 汇总与证据。

    python3 -m eval_sandbox.cli check

任何一条不通过（包括"隔离能力根本拿不到"）都以非 0 退出。
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
import time

from . import cases as case_module
from .sandbox import RunResult, SandboxUnavailable, capabilities, run


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="eval-sandbox", description="任务级沙盒隔离自检")
    parser.add_argument("command", nargs="?", default="check", choices=["check"],
                        help="check = 跑完全部判据（默认）")
    parser.add_argument("--workdir", default=None, help="沙盒工作目录（默认建临时目录）")
    parser.add_argument("--evidence", default="evidence/run.json", help="证据 JSON 输出路径")
    parser.add_argument("--quiet", action="store_true", help="只打印汇总")
    args = parser.parse_args(argv)

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
    ev_path = args.evidence
    if os.path.dirname(ev_path):
        os.makedirs(os.path.dirname(ev_path), exist_ok=True)
    with open(ev_path, "w", encoding="utf-8") as fh:
        json.dump(evidence, fh, ensure_ascii=False, indent=2, sort_keys=True)
    print("evidence -> %s" % ev_path)
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
