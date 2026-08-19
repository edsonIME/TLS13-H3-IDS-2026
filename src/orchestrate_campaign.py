#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
orchestrate_campaign.py — drive a WHOLE campaign (all runs) then build + validate + evaluate the
dataset [audit v20.26].

It reads the campaign manifest, runs each declared run through orchestrate_run.py in manifest order,
enforces the campaign discipline the analytical layer assumes — no run_id executed twice, a cool-down
between runs, and a HARD STOP if an OFFICIAL (non-diagnostic) run fails — then calls the existing
merge_and_split / validate_dataset / evaluate_realism to produce the split, validated, evaluated
dataset. Re-running RESUMES: runs already sealed PASS are skipped.

Artifacts: campaign_execution_report.json, campaign_hashes.json, campaign_completion_status.json.

`run_campaign` takes the per-run and analytics callables as parameters, so the driver logic
(ordering, resume, abort-on-official-failure, reserved configs) is unit-tested with mocks; the real
main wires those to orchestrate_run.py and the analytical tools as subprocesses.
"""

import argparse
import os
import sys

import runlib


def _run_completion(base_dir, run_id):
    """Read a run's completion verdict if it was already sealed (for --resume idempotency)."""
    p = os.path.join(base_dir, "run{}".format(run_id), "run{}_completion_status.json".format(run_id))
    return runlib.read_json(p) if os.path.exists(p) else None


# --- analytics command builders (pure; unit-tested so the §8 wiring can't silently regress) --------

def split_ready_paths(base_dir, runs):
    """Per-run split-ready CSVs the labeler wrote with `--out run<N>.csv` [audit v20.27 §4]."""
    return [os.path.join(base_dir, "run{}".format(r), "run{}_split_ready.csv".format(r)) for r in runs]


def status_paths(base_dir, runs):
    """Per-run status files (run<N>_run_status.json), the byte-authentication for each run [§4]."""
    return [os.path.join(base_dir, "run{}".format(r), "run{}_run_status.json".format(r)) for r in runs]


def merge_cmd(src_dir, campaign, sr, st, prefix):
    """merge_and_split: status files passed EXPLICITLY and required (campaign feeds the merge) [§8]."""
    return ["python3", os.path.join(src_dir, "merge_and_split.py"), *sr,
            "--campaign", campaign, "--status", *st, "--require-status",
            "--prefix", prefix, "--overwrite"]


def validate_cmd(src_dir, campaign, sr, st, json_out):
    """validate_dataset: was entirely MISSING from the campaign before — now always run [§8]."""
    return ["python3", os.path.join(src_dir, "validate_dataset.py"),
            "--csv", *sr, "--status", *st, "--require-status",
            "--campaign", campaign, "--json", json_out]


def evaluate_cmd(src_dir, campaign, sr, st, synth, json_out):
    """evaluate_realism: the evaluator ABORTS without --synth, so it is only built when a synthetic
    dataset is supplied; passing it is what stops the campaign from crashing the evaluator [§8]."""
    return ["python3", os.path.join(src_dir, "evaluate_realism.py"),
            "--real", *sr, "--synth", synth, "--status", *st, "--require-status",
            "--campaign", campaign, "--by-class", "--tstr-balance",
            "--domain-distinguishability", "--json", json_out]


def run_campaign(manifest, base_dir, run_one, run_analytics, resume=True, cooldown_s=0, sleep=None,
                 verify_run=None):
    """Drive the campaign.

    manifest      : loaded campaign dict (campaign.load output).
    run_one(rid, spec) -> completion dict with {"overall": "PASS"/"FAIL", "diagnostic": bool}.
    run_analytics(runs) -> dict with {"overall": ..., "steps": {...}} (merge/validate/evaluate).
    verify_run(rid) -> bool: re-verify a sealed run's hashes before trusting a resume [audit v20.30 §20].
    Returns the execution report. Aborts (stops scheduling) as soon as an OFFICIAL run fails.
    """
    sleep = sleep or (lambda s: __import__("time").sleep(s))
    order = sorted((manifest.get("runs") or {}).items(), key=lambda kv: int(kv[0]))
    executed, results, seen_configs, overall = [], [], set(), "PASS"
    for rid, spec in order:
        cfg_id = spec.get("config_id")
        if cfg_id in seen_configs:                         # the manifest itself is malformed
            results.append({"run": rid, "state": "ABORT", "reason": "duplicate config_id {}".format(cfg_id)})
            overall = "FAIL"; break
        seen_configs.add(cfg_id)
        prior = _run_completion(base_dir, rid) if resume else None
        # RESUME only if the sealed run ALSO re-verifies (hashes unchanged) and was OFFICIAL — a tampered
        # or diagnostic completion must NOT be trusted as a finished official run [audit v20.30 §20].
        if prior and prior.get("overall") == "PASS":
            if prior.get("official") is False:
                results.append({"run": rid, "state": "ABORT",
                                "reason": "prior completion is DIAGNOSTIC (official=false); re-run officially"})
                overall = "FAIL"; break
            if verify_run is not None and not verify_run(rid):
                results.append({"run": rid, "state": "ABORT",
                                "reason": "sealed run failed --verify (evidence changed since sealing)"})
                overall = "FAIL"; break
            results.append({"run": rid, "state": "SKIP_RESUME", "completion": prior})
            executed.append(int(rid))
            continue
        comp = run_one(rid, spec)
        results.append({"run": rid, "state": "RAN", "completion": comp})
        if comp.get("overall") != "PASS":
            # A diagnostic (pilot) run may be allowed to fail-soft; an OFFICIAL run must stop the campaign.
            if not comp.get("diagnostic", False):
                overall = "FAIL"
                results[-1]["fatal"] = "official run failed"
                break
        else:
            executed.append(int(rid))                      # run ids are the manifest keys (ints)
        if cooldown_s:
            sleep(cooldown_s)

    analytics = None
    declared = sorted(int(k) for k in (manifest.get("runs") or {}))
    if overall == "PASS" and executed == declared:         # only build the dataset if ALL runs are in
        analytics = run_analytics(executed)
        if analytics.get("overall") != "PASS":
            overall = "FAIL"
    elif overall == "PASS":
        overall = "INCOMPLETE"                             # nothing failed, but not every run is present

    return {"overall": overall, "generated_utc": runlib.utc_now_iso(),
            "campaign_id": manifest.get("campaign_id"), "executed_runs": executed,
            "run_results": results, "analytics": analytics}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Drive a whole campaign end to end ({}).".format(runlib.TOOL_VERSION))
    ap.add_argument("--campaign", required=True, help="campaign manifest")
    ap.add_argument("--base-dir", required=True, help="root holding run<N>/ directories")
    ap.add_argument("--src-dir", default=".", help="directory with the tool scripts")
    ap.add_argument("--run-config", required=True, help="base run config JSON for orchestrate_run")
    ap.add_argument("--cooldown", type=float, default=60.0, help="seconds between runs")
    ap.add_argument("--no-resume", action="store_true", help="re-run even runs already sealed PASS")
    ap.add_argument("--synth", help="synthetic *_split_ready.csv* to evaluate realism against; if "
                                    "omitted, realism evaluation is SKIPPED (merge+validate still run)")
    ap.add_argument("--out-dir", default=".")
    args = ap.parse_args(argv)
    runlib.print_banner("orchestrate_campaign.py")

    import campaign as camp
    manifest = camp.load(args.campaign, require_reproducible=True)
    base_cfg = runlib.read_json(args.run_config)

    def run_one(rid, spec):
        cfg = dict(base_cfg); cfg["run_id"] = rid; cfg["campaign"] = args.campaign; cfg["base_dir"] = args.base_dir
        cfg_path = os.path.join(args.out_dir, "_run_cfg_{}.json".format(rid))
        runlib.write_json(cfg_path, cfg)
        r = runlib.run_cmd(["python3", os.path.join(args.src_dir, "orchestrate_run.py"),
                            "--config", cfg_path], timeout=None)
        comp = _run_completion(args.base_dir, rid) or {"overall": "FAIL", "reason": "no completion status"}
        # The orchestrator's EXIT CODE is authoritative: a non-zero rc means the run failed even if a
        # stale completion file happens to say PASS [audit v20.30 §20].
        if not r.ok:
            comp = {"overall": "FAIL", "reason": "orchestrate_run exit {}".format(r.returncode),
                    "completion_seen": comp.get("overall")}
        comp["diagnostic"] = bool(camp.bruteforce_unpinned(manifest))   # pilot => soft-fail allowed
        return comp

    def verify_run(rid):
        """Re-verify a sealed run's hashes before a resume trusts it [audit v20.30 §20]."""
        r = runlib.run_cmd(["python3", os.path.join(args.src_dir, "finalize_run.py"),
                            "--run-dir", os.path.join(args.base_dir, "run{}".format(rid)),
                            "--run-id", str(rid), "--verify"], timeout=120)
        return r.ok

    def run_analytics(runs):
        sr = split_ready_paths(args.base_dir, runs)         # run<N>_split_ready.csv [audit v20.27 §4]
        st = status_paths(args.base_dir, runs)              # run<N>_run_status.json
        prefix = os.path.join(args.out_dir, "dataset")
        steps, artifacts = {}, []

        # 1) MERGE + temporal split — status files passed explicitly and required [audit v20.27 §8].
        merge = runlib.run_cmd(merge_cmd(args.src_dir, args.campaign, sr, st, prefix))
        steps["merge"] = merge.as_dict()
        ok = merge.ok
        for suffix in ("_train.csv", "_val.csv", "_test.csv"):
            if os.path.exists(prefix + suffix):
                artifacts.append(prefix + suffix)

        # 2) VALIDATE the split-ready runs (was entirely missing before) [audit v20.27 §8].
        if ok:
            vjson = os.path.join(args.out_dir, "campaign_validate.json")
            val = runlib.run_cmd(validate_cmd(args.src_dir, args.campaign, sr, st, vjson))
            steps["validate"] = val.as_dict()
            ok = ok and val.ok
            if os.path.exists(vjson):
                artifacts.append(vjson)

        # 3) EVALUATE realism — needs a synthetic counterpart; the evaluator ABORTS without --synth,
        #    so run it only when --synth was given, else record it as SKIPPED [audit v20.27 §8].
        if ok and args.synth:
            ejson = os.path.join(args.out_dir, "campaign_evaluate.json")
            ev = runlib.run_cmd(evaluate_cmd(args.src_dir, args.campaign, sr, st, args.synth, ejson))
            steps["evaluate"] = ev.as_dict()
            ok = ok and ev.ok
            if os.path.exists(ejson):
                artifacts.append(ejson)
        elif ok:
            steps["evaluate"] = {"skipped": "no --synth provided; realism not evaluated"}

        return {"overall": "PASS" if ok else "FAIL", "steps": steps, "artifacts": artifacts}

    report = run_campaign(manifest, args.base_dir, run_one, run_analytics,
                          resume=not args.no_resume, cooldown_s=args.cooldown, verify_run=verify_run)
    rp = os.path.join(args.out_dir, "campaign_execution_report.json")
    runlib.write_json(rp, report)

    # Seal the dataset + evidence so the campaign result is byte-verifiable [audit v20.27 §8].
    artifacts = ((report.get("analytics") or {}).get("artifacts")) or []
    hashes = {os.path.basename(p): runlib.sha256_file(p) for p in artifacts if os.path.exists(p)}
    hashes["campaign_execution_report.json"] = runlib.sha256_file(rp)
    hp = os.path.join(args.out_dir, "campaign_hashes.json")
    runlib.write_json(hp, {"campaign_id": report["campaign_id"], "overall": report["overall"],
                           "generated_utc": runlib.utc_now_iso(), "hashes": hashes})
    runlib.write_json(os.path.join(args.out_dir, "campaign_completion_status.json"),
                      {"overall": report["overall"], "executed_runs": report["executed_runs"],
                       "report_sha256": runlib.sha256_file(rp),
                       "hashes_sha256": runlib.sha256_file(hp)})
    print("CAMPAIGN {} -> {} (runs {})".format(report["campaign_id"], report["overall"],
                                               report["executed_runs"]))
    return 0 if report["overall"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
