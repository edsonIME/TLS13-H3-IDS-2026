#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
orchestrate_run.py — coordinate ONE end-to-end run across NB1..NB4 [audit v20.27].

The whole reason this script exists is TIMING: a capture that starts after the attacks would miss
them. So the pipeline is:

    preflight                                            (NB4)
    clocks_start on NB1,NB2,NB3,NB4                       (evidence, before anything moves)
    START capture (background)                            (NB4)  <-- sensor is recording FIRST
    START service monitor (background)                    (NB4)
    START benign traffic (background)                     (NB2)
    warm-up sleep
    ATTACKS (foreground, blocking)                        (NB3)  <-- captured, because capture is up
    cool-down sleep
    STOP benign, STOP monitor, STOP capture (last)        <-- capture spans warm-up..cool-down
    clocks_end on NB1,NB2,NB3,NB4
    fetch NB3 ground-truth annotations -> NB4 run dir
    process PCAP with Zeek                                (NB4)
    label flows (--out run<N>.csv -> run<N>_run_status.json)  (NB4)
    analyze service effect (DoS availability drop)        (NB4)
    finalize + seal                                       (NB4)

Everything runs through a `Runner` (local in tests, ssh in the lab), and the long-running steps
(capture/monitor/benign) are real BACKGROUND jobs started before the attacks and stopped after —
so concurrency is explicit, not faked with fixed durations [audit v20.27 §2/§3/§4].

TESTABILITY: `run_pipeline` (the control logic) is separated from the concrete steps and is
unit-tested with mock steps (order, abort, and — new — that background jobs are ALWAYS stopped even
when a required step aborts). `--dry-run` makes every step record the argv/intent it WOULD execute,
so the exact ORDER (capture-start < attacks < capture-stop) is asserted with no lab present.
"""

import argparse
import json
import os
import sys
import time
import uuid

import runlib


class Step(object):
    """One pipeline step: a name, a callable fn() -> (ok: bool, detail: dict), and two flags.

    required : a failure ABORTS the run (no point continuing to label a run whose attacks failed).
    always   : this step runs EVEN AFTER an abort — it is cleanup (e.g. stop the background capture),
               so we never leak a running tcpdump or lose the capture's seal when something upstream
               fails [audit v20.27 §2]."""

    def __init__(self, name, fn, required=True, always=False):
        self.name, self.fn, self.required, self.always = name, fn, required, always


def run_pipeline(steps, report_path=None, attempt_id=None, campaign_sha256=None, run_id=None):
    """Execute steps in order. On the first REQUIRED failure the run is marked FAIL and every later
    NON-cleanup step is SKIPPED — but `always` (cleanup) steps still run, so background jobs are
    always stopped and partial evidence is always sealed. Pure control logic (unit-tested). The run's
    `attempt_id` is recorded in the report so the seal can bind the evidence to this attempt [v20.44 §5]."""
    results, overall, aborted_at = [], "PASS", None
    for step in steps:
        if aborted_at is not None and not step.always:
            results.append({"step": step.name, "required": step.required,
                            "ok": None, "skipped": True, "detail": {"reason": "skipped after abort"}})
            continue
        try:
            ok, detail = step.fn()
        except Exception as exc:                           # a crashing step is a failure, not a traceback
            ok, detail = False, {"exception": repr(exc)[:300]}
        results.append({"step": step.name, "required": step.required,
                        "ok": bool(ok), "detail": detail})
        if not ok and step.required and aborted_at is None:
            overall, aborted_at = "FAIL", step.name          # keep going so `always` cleanup still runs
    report = {"overall": overall, "aborted_at": aborted_at, "generated_utc": runlib.utc_now_iso(),
              "tool_version": runlib.TOOL_VERSION, "attempt_id": attempt_id,
              "campaign_sha256": campaign_sha256, "run_id": run_id, "steps": results}
    if report_path:
        runlib.write_json(report_path, report)
    return report


def _tool_argv(script, host_dir, args):
    """python3 <host_dir>/<script> <args...> — resolves the script next to the src/ copy on the
    host that will run it, so every notebook runs the same code."""
    return ["python3", os.path.join(host_dir, script)] + [str(a) for a in args]


def _stage_of(cfg, run_dir, runners, host, rid):
    """Where a host writes its artifacts. NB4 (the local sensor) uses the run dir directly; a REMOTE
    notebook uses its own per-run staging dir (default /tmp/nids_run<N>, or cfg['stages'][host]) so its
    logs/outputs never depend on the NB4 path existing there [audit v20.28 §6]."""
    if isinstance(runners[host], runlib.LocalRunner):
        return run_dir
    default = "/tmp/nids_run{}".format(rid)
    return (cfg.get("stages", {}) or {}).get(host, cfg.get("remote_stage", default))


def build_steps(cfg, run_dir, dry_run=False, jobs=None):
    """Construct the concrete, correctly-ordered pipeline for one run. `jobs` is a shared dict that
    background-start steps populate and stop steps consume (kept external so a test can inspect it).
    In `dry_run` every step only records the argv/intent it WOULD run (no host is touched).

    Note: `finalize` is intentionally NOT a step here — it must run AFTER the orchestration report is
    written so it can SEAL that report; `main` runs it once the pipeline (incl. cleanup) is done
    [audit v20.28 §14]."""
    rid = str(cfg["run_id"])
    src = cfg.get("src_dir", ".")
    jobs = jobs if jobs is not None else {}
    runners = {h: runlib.make_runner(cfg.get("runners", {}).get(h, {"kind": "local"}))
               for h in ("nb1", "nb2", "nb3", "nb4", "admin")}
    dur = cfg.get("durations", {})
    warmup = float(dur.get("warmup", 30))
    cooldown = float(dur.get("cooldown", 30))
    sustain = float(dur.get("sustain", 0))  # [fix] benign-only window AFTER attacks
    attack_timeout = float(cfg.get("attack_timeout", 1800))
    ready_timeout = float(cfg.get("ready_timeout", 20))
    # Poll interval for the readiness gate. Default stays 0.3s so the shipped behaviour and
    # test_orchestrate_run_readiness_gates_on_liveness are unchanged. A real lab RAISES it:
    # the gate needs TWO CONSECUTIVE strict size increases, so polling faster than the
    # capture writes puts two stalled samples after every increase and resets the streak.
    # ready_capture runs BEFORE benign/attacks, when the mirror is quiet (~1 write/s), so
    # run0.json sets "ready_poll_s": 2.0. A static PCAP still never grows -> still fails closed.
    ready_poll_s = float(cfg.get("ready_poll_s", 0.3))
    # Background caps default to the WHOLE possible run + margin, so capture/monitor/benign can never
    # self-terminate before the last attack + cool-down + the orchestrator's own stop [audit v20.29 §10].
    safe_cap = warmup + attack_timeout + cooldown + float(dur.get("margin", 300))
    capture_cap = float(dur.get("capture_cap", safe_cap))
    monitor_cap = float(dur.get("monitor_cap", safe_cap))
    benign_cap = float(dur.get("benign_cap", safe_cap))

    # Scripts and the campaign manifest live at DIFFERENT paths per host (NB2 is Windows: C:\nids\src),
    # so each host runs its own copy and reads its own manifest [audit v20.29 §6].
    def src_of(host):
        return (cfg.get("src_dirs", {}) or {}).get(host, src)

    def campaign_of(host):
        return (cfg.get("campaigns", {}) or {}).get(host, cfg["campaign"])

    def stage_of(host):
        return _stage_of(cfg, run_dir, runners, host, rid)

    def _prep_stage(host):
        """mkdir the host's staging dir (idempotent) so a background job can redirect its log there."""
        if not isinstance(runners[host], runlib.LocalRunner):
            runners[host].mkdir(stage_of(host))

    def _tail_log(job):
        try:
            if job and job.log_path and os.path.exists(job.log_path):
                return open(job.log_path, encoding="utf-8", errors="replace").read()[-800:]
        except OSError:
            pass
        return ""

    # ---- step-factory helpers -------------------------------------------------------------------
    def fg(host, name, script, args, timeout=None, required=True, prep=False):
        """A FOREGROUND tool invocation on `host` (blocks until it exits)."""
        argv = _tool_argv(script, src_of(host), args)

        def _fn():
            if dry_run:
                return True, {"dry_run": True, "host": host, "argv": argv}
            if prep:
                _prep_stage(host)
            r = runners[host].run(argv, timeout=timeout)
            return r.ok, r.as_dict()
        return Step(name, _fn, required=required)

    def start_bg(host, name, script, args, required=False):
        """START a BACKGROUND job on `host`; its log goes to the HOST's staging dir [§6]."""
        argv = _tool_argv(script, src_of(host), args)

        def _fn():
            if dry_run:
                return True, {"dry_run": True, "host": host, "background": True, "argv": argv}
            _prep_stage(host)
            log = os.path.join(stage_of(host), "run{}_{}_bg.log".format(rid, name)).replace("\\", "/")
            job = runners[host].start_background(argv, log_path=log, name=name)
            jobs[name] = job
            return (job.pid is not None), {"host": host, "background": True, "pid": job.pid,
                                           "argv": argv, "log": log}
        return Step("start_" + name, _fn, required=required)

    def ready(name, host, artifact, grow=False):
        """READINESS GATE [§5]: a background job counts as started only if, within `ready_timeout`, the
        process is STILL ALIVE and its first artifact appeared (and is GROWING for the capture). This is
        what catches a job that took a PID but died immediately (e.g. a bad CLI flag) BEFORE the attacks
        run — the exact failure mode that let a broken benign run go unnoticed."""
        def _fn():
            if dry_run:
                return True, {"dry_run": True, "ready": name, "artifact": artifact}
            job = jobs.get(name)
            if job is None:
                return False, {"ready": name, "error": "job was never started"}
            runner = job.runner
            deadline = time.time() + ready_timeout
            prev, grows = -1, 0
            while time.time() < deadline:
                code = runner.wait_background(job, timeout=0)
                if code is not None:                        # DIED before becoming ready
                    return False, {"ready": name, "error": "process exited before ready",
                                   "exit_code": code, "log_tail": _tail_log(job)}
                if runner.exists(artifact):
                    if not grow:
                        return True, {"ready": name, "artifact": artifact, "alive": True}
                    sz = runner.file_size(artifact)
                    # STRICT growth: a PCAP that only holds the header (static size) means NO packets are
                    # arriving — a dead mirror / wrong interface / stopped tcpdump — and must NEVER pass.
                    # Require TWO consecutive strict increases so a one-off blip can't fool it [§5].
                    if prev >= 0 and sz > prev:
                        grows += 1
                        if grows >= 2:
                            return True, {"ready": name, "artifact": artifact, "size": sz, "grows": grows}
                    elif prev >= 0:
                        grows = 0                            # a stall RESETS the streak (static never passes)
                    prev = sz
                time.sleep(ready_poll_s)
            return False, {"ready": name, "error": "artifact absent or NOT GROWING in {:.0f}s".format(ready_timeout),
                           "artifact": artifact, "log_tail": _tail_log(job)}
        return Step("ready_" + name, _fn, required=True)

    def recheck_alive(names):
        """RE-CHECK just before the attacks that the background jobs are STILL alive. A capture/monitor/
        benign that passed its readiness gate but DIED during warm-up (e.g. benign crashed after its first
        page) must abort the run BEFORE any attack traffic — otherwise we attack an unrecorded network
        [audit v20.30 §14]. Required, so a dead job aborts (and the `always` stops still clean up)."""
        def _fn():
            if dry_run:
                return True, {"dry_run": True, "recheck": list(names)}
            dead = []
            for n in names:
                job = jobs.get(n)
                if job is None:
                    dead.append({"job": n, "reason": "never started"})
                    continue
                code = job.runner.wait_background(job, timeout=0)
                if code is not None:                        # exited between readiness and attacks
                    dead.append({"job": n, "exit_code": code, "log_tail": _tail_log(job)})
            return (not dead), {"checked": list(names), "dead": dead}
        return Step("recheck_alive", _fn, required=True)

    def stop_bg(name, grace=3.0):
        """STOP a background job (cleanup). `always` so it runs even after an abort, and never itself
        aborts the run — a best-effort stop is the right thing on the way out."""
        def _fn():
            if dry_run:
                return True, {"dry_run": True, "stop": name}
            job = jobs.get(name)
            if job is None:
                return True, {"stop": name, "note": "never started; nothing to stop"}
            rc = job.runner.stop_background(job, grace=grace)
            job.runner.wait_background(job, timeout=grace + 10)   # ensure it flushed its seal/CSV
            return True, {"stop": name, "rc": rc}
        return Step("stop_" + name, _fn, required=False, always=True)

    def sleep_step(name, seconds):
        def _fn():
            if dry_run:
                return True, {"dry_run": True, "sleep_s": seconds}
            time.sleep(seconds)
            return True, {"slept_s": seconds}
        return Step(name, _fn, required=False)

    def clock_step(host, label, phase, required=False):
        """Collect clock-sync evidence on `host` (all four hosts, both phases). Local writes into the
        run dir; a remote writes into its staging dir and we FETCH the file back to NB4 [§7]."""
        name = "clock_{}_{}".format(label.lower(), phase)
        fname = "run{}_{}_clock_{}.json".format(rid, label.lower(), phase)

        def _fn():
            runner = runners[host]
            if dry_run:
                return True, {"dry_run": True, "host": host, "clock": [label, phase]}
            if isinstance(runner, runlib.LocalRunner):
                argv = _tool_argv("clock_evidence.py", src_of(host),
                                  ["--run-dir", run_dir, "--run-id", rid, "--host-label", label, "--phase", phase])
                r = runner.run(argv, timeout=60)
                return r.ok, r.as_dict()
            stage = stage_of(host)
            runner.mkdir(stage)
            argv = _tool_argv("clock_evidence.py", src_of(host),
                              ["--run-dir", stage, "--run-id", rid, "--host-label", label, "--phase", phase])
            r = runner.run(argv, timeout=60)
            fetched = runner.fetch("{}/{}".format(stage, fname), os.path.join(run_dir, fname)) if r.ok else False
            return (r.ok and fetched), {"host": host, "fetched": fetched, "detail": r.as_dict()}
        return Step(name, _fn, required=required)

    def fetch_step(name, host, remote, local, required=True):
        """Pull a file from `host` into the NB4 run dir [§6/§16]."""
        def _fn():
            if dry_run:
                return True, {"dry_run": True, "fetch_from": host, "remote": remote, "local": local}
            ok = runners[host].fetch(remote, local)
            return ok, {"fetch_from": host, "remote": remote, "local": local, "ok": ok}
        return Step(name, _fn, required=required)

    # ---- resolved paths (each on the host that owns it) -----------------------------------------
    conn_log = os.path.join(run_dir, "zeek_logs", "conn.log")
    annotations_local = os.path.join(run_dir, "run{}_annotations.csv".format(rid))
    nb3_stage = stage_of("nb3")
    annotations_remote = "{}/run{}_annotations.csv".format(nb3_stage, rid)     # WHERE we tell nb3 to write [§4]
    attack_logdir_remote = "{}/run{}_attack_logs".format(nb3_stage, rid)
    nb2_stage = stage_of("nb2")
    benign_jsonl_remote = "{}/run{}_benign.jsonl".format(nb2_stage, rid)
    benign_jsonl_local = os.path.join(run_dir, "run{}_benign.jsonl".format(rid))
    # A dedicated readiness MARKER benign_traffic writes EARLY (browser up + first request), so the gate
    # doesn't wait on the first full session's JSONL row (which can take >20s) [audit v20.29 §11].
    benign_ready_remote = "{}/run{}_benign_ready.json".format(nb2_stage, rid)
    monitor_csv = os.path.join(run_dir, "run{}_service_monitor.csv".format(rid))
    monitor_urls = cfg.get("monitor_urls", cfg.get("https", []))
    label_out = os.path.join(run_dir, "run{}.csv".format(rid))     # -> run<N>_run_status.json [§4]
    pcap_path = os.path.join(run_dir, "run{}.pcap".format(rid))

    # ONE attempt identity for the whole run, generated UP-FRONT and SHARED by every producer, so the seal
    # can bind the benign session log to THIS attempt: benign_traffic stamps it on each session and the
    # labeler records it as status.attempt_id, and finalize requires the two to match [audit v20.43 §6].
    # Overridable via cfg for reproducible replays/tests. And the benign-log fetch becomes MANDATORY when the
    # campaign's policy requires the jsonl, so a missing transfer aborts EARLY, not only at the seal [§8].
    attempt_id = cfg.get("attempt_id") or uuid.uuid4().hex
    benign_required = bool(cfg.get("require_benign_log", False))
    try:
        _bqp = (json.load(open(cfg["campaign"])) or {}).get("benign_quality_policy") or {}
        # the SAME gate the finalizer uses to decide it NEEDS the jsonl [audit v20.44 §11]: ANY of these
        # means the seal will require the benign log, so the fetch must be mandatory too — fail EARLY (when
        # the transfer fails), not only at seal time.
        if (_bqp.get("require_benign_jsonl") or _bqp.get("min_successful_sessions") is not None
                or _bqp.get("min_success_rate") is not None or _bqp.get("require_browser_evidence")):
            benign_required = True
    except Exception:                                              # a stub/unreadable manifest falls back to cfg
        pass

    steps = []
    # preflight on EACH host (host-specific profile), not just the sensor [§8].
    for host, label in (("nb1", "NB1"), ("nb2", "NB2"), ("nb3", "NB3"), ("nb4", "NB4")):
        pf_dir = run_dir if isinstance(runners[host], runlib.LocalRunner) else stage_of(host)
        # Each host gets its OWN preflight args (interface/disk on NB4, wordlists on NB3, DNS/HTTPS on NB1,
        # …) — a single shared block can't express the four roles [audit v20.30 §10].
        pf_args = (cfg.get("preflight_args_by_host", {}) or {}).get(host, cfg.get("preflight_args", []))
        steps.append(fg(host, "preflight_" + host, "preflight.py",
                        ["--run-id", rid, "--out-dir", pf_dir, "--profile", host] + pf_args, prep=True,
                        required=cfg.get("require_preflight", True)))
    for host, label in (("nb1", "NB1"), ("nb2", "NB2"), ("nb3", "NB3"), ("nb4", "NB4")):
        steps.append(clock_step(host, label, "start"))

    # capture MUST be up (and CONFIRMED up) before any attack traffic.
    steps.append(start_bg("nb4", "capture", "capture_run.py",
                          ["--run-dir", run_dir, "--run-id", rid, "--attempt-id", attempt_id,
                           "--interface", cfg.get("interface", "enp0s3"),
                           "--duration", capture_cap] + cfg.get("capture_args", []),
                          required=True))
    steps.append(ready("capture", "nb4", pcap_path, grow=False))     # PCAP must exist AND be growing [§5]
    monitor_args = ["--run-dir", run_dir, "--run-id", rid, "--duration", monitor_cap,
                    "--interval", cfg.get("monitor_interval", 2.0)]
    for u in monitor_urls:
        monitor_args += ["--url", u]
    steps.append(start_bg("nb4", "monitor", "service_monitor.py", monitor_args + cfg.get("monitor_args", [])))
    steps.append(ready("monitor", "nb4", monitor_csv))
    # benign_traffic takes --minutes (NOT --duration) and needs campaign/run-id/log for provenance [§3];
    # --ready-file is a dedicated EARLY marker the readiness gate waits on instead of the session JSONL [§11].
    steps.append(start_bg("nb2", "benign", "benign_traffic.py",
                          ["--minutes", benign_cap / 60.0, "--campaign", campaign_of("nb2"), "--run-id", rid,
                           "--attempt-id", attempt_id,                  # SHARE the run's attempt identity [§6]
                           "--log-jsonl", benign_jsonl_remote, "--ready-file", benign_ready_remote,
                           "--headless"] + cfg.get("benign_args", [])))
    # [audit] Gate on the SESSION JSONL growing, not the preflight marker. The marker is
    # written by the wrapper only after it reads "preflight ok:" from the level-2 stdout,
    # which is BLOCK-BUFFERED on Windows pipes and can arrive tens of seconds late (measured
    # ~67s), tripping this gate intermittently even though benign traffic is flowing fine.
    # The JSONL is written DIRECTLY by level-2 as sessions complete, so its growth is a
    # direct, reliable proof the benign side is alive AND producing traffic — a STRONGER
    # readiness signal than the marker. A benign that dies at once writes no JSONL, so the
    # original protection (catch a hollow benign) is preserved. [robust-ready v20.49]
    steps.append(ready("benign", "nb2", benign_jsonl_remote, grow=True))

    steps.append(sleep_step("warmup", warmup))
    steps.append(recheck_alive(("capture", "monitor", "benign")))   # all still alive BEFORE attacking [§14]
    steps.append(fg("nb3", "attacks", "run_attacks.py",
                    ["--campaign", campaign_of("nb3"), "--run-id", rid,
                     "--annotations", annotations_remote, "--logdir", attack_logdir_remote,
                     "--overwrite-annotations"] + cfg.get("attack_args", []),
                    timeout=attack_timeout, required=True, prep=True))
    steps.append(sleep_step("cooldown", cooldown))

    # [fix] hold capture open with benign-only traffic so the PCAP accumulates
    # >= min_benign_flows. Attacks are done; benign keeps running until we stop it.
    if sustain > 0:
        steps.append(sleep_step("sustain", sustain))
    # stop order: benign, monitor, then capture LAST so the PCAP spans warm-up..cool-down.
    steps.append(stop_bg("benign", grace=3.0))
    steps.append(stop_bg("monitor", grace=3.0))
    steps.append(stop_bg("capture", grace=15.0))            # generous: the seal must finish before SIGKILL [§3.3]

    for host, label in (("nb1", "NB1"), ("nb2", "NB2"), ("nb3", "NB3"), ("nb4", "NB4")):
        steps.append(clock_step(host, label, "end"))

    # pull the remote evidence to NB4: ground truth (required) + benign log (best-effort) [§6/§16].
    steps.append(fetch_step("fetch_annotations", "nb3", annotations_remote, annotations_local, required=True))
    steps.append(fetch_step("fetch_benign_log", "nb2", benign_jsonl_remote, benign_jsonl_local,
                            required=benign_required))          # MANDATORY when the campaign requires the jsonl [§8]
    steps.append(fg("nb4", "process_pcap", "process_pcap.py",
                    ["--run-dir", run_dir, "--run-id", rid, "--attempt-id", attempt_id]
                    + cfg.get("zeek_args", ["--site-script", cfg.get("zeek_site_script", "local")])))
    _zeek_dir = os.path.dirname(conn_log)
    # Pass the sibling Zeek logs UNCONDITIONALLY: build_steps runs at the START of the run,
    # before process_pcap has generated them, so os.path.exists() would be False here and the
    # flags would be dropped. process_pcap always writes conn/ssl/quic/flowmeter to zeek_logs/
    # before label_flows runs; label_flows itself validates presence/non-emptiness. [fix v2]
    _label_log_args = ["--conn", conn_log,
                       "--ssl", os.path.join(_zeek_dir, "ssl.log"),
                       "--quic", os.path.join(_zeek_dir, "quic.log"),
                       "--flowmeter", os.path.join(_zeek_dir, "flowmeter.log")]
    steps.append(fg("nb4", "label_flows", "label_flows.py",
                    _label_log_args + ["--annotations", annotations_local, "--attempt-id", attempt_id,
                     "--campaign", cfg["campaign"], "--out", label_out] + cfg.get("label_args", [])))
    steps.append(fg("nb4", "analyze_effect", "service_monitor.py",
                    ["--analyze", "--csv", monitor_csv, "--events", annotations_local,
                     "--out", os.path.join(run_dir, "run{}_service_effect.json".format(rid))],
                    required=False))
    return steps


def prepare_run_dir(base, run_id, overwrite=False):
    """Return a FRESH run directory. If one already exists and is NON-EMPTY:
      - overwrite=False (the safe default) -> ABORT: a run's evidence is never silently reused;
      - overwrite=True -> ROTATE the old dir to run<N>_attempt_<UTCstamp> (kept, not deleted) and make a
        clean one, so a NEW attempt can never inherit a STALE completion=PASS that the campaign driver
        would read as success [audit v20.28 §13]."""
    d = os.path.join(base, "run{}".format(run_id))
    if os.path.isdir(d) and os.listdir(d):
        if not overwrite:
            raise FileExistsError(
                "run directory {} already exists and is non-empty; set \"overwrite\": true to rotate it "
                "(old run moved to run{}_attempt_<UTCstamp>, never reused) [audit v20.28 §13]".format(d, run_id))
        os.rename(d, "{}_attempt_{}".format(d, time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())))
    os.makedirs(d, exist_ok=True)
    return d


def finalize_argv(cfg, run_dir):
    """The finalize_run invocation, built so it can be run AFTER the orchestration report exists [§14]."""
    return _tool_argv("finalize_run.py", cfg.get("src_dir", "."),
                      ["--run-dir", run_dir, "--run-id", cfg["run_id"], "--campaign", cfg["campaign"]]
                      + cfg.get("finalize_args", []))


def example_config():
    return {"run_id": 0, "base_dir": "/data", "src_dir": "/opt/nids/src", "campaign": "campaign.json",
            "interface": "enp0s3", "overwrite": False, "ready_timeout": 20, "attack_timeout": 1800,
            # Scripts + manifest live at DIFFERENT paths on the Windows NB2 [§6]; other hosts inherit
            # the top-level src_dir/campaign.
            "src_dirs": {"nb2": "C:\\nids\\src"},
            "campaigns": {"nb2": "C:\\nids\\campaign.json"},
            "remote_stage": "/tmp/nids_run0",                         # POSIX staging for NB1/NB3
            "stages": {"nb2": "C:\\nids\\run0"},                      # NB2 is Windows -> Windows path
            "zeek_site_script": "/opt/nids/lab/zeek/local.zeek",      # versioned Zeek policy [§15]
            # durations OMITTED on purpose: capture/monitor/benign caps auto-size to
            # warmup+attack_timeout+cooldown+margin so they never expire before the run ends [§10].
            "durations": {"warmup": 30, "cooldown": 30, "margin": 300},
            # OFFICIAL runs pin the capture-quality floor the finalizer enforces semantically [§4/§16]:
            "finalize_args": ["--min-packets", "1000", "--max-drop-rate", "0.02"],
            # Per-host preflight args — each notebook verifies its OWN role [audit v20.30 §10]:
            "preflight_args_by_host": {
                "nb1": ["--campaign", "/opt/nids/campaign.json", "--resolve", "blog.lab", "--resolve", "shop.lab",
                        "--https", "https://blog.lab", "--https", "https://shop.lab"],
                "nb2": ["--resolve", "blog.lab", "--resolve", "shop.lab"],
                "nb3": ["--campaign", "/opt/nids/campaign.json", "--wordlist-dir", "/opt/nids/wordlists"],
                "nb4": ["--interface", "enp0s3", "--disk-path", "/data", "--min-disk-gb", "20",
                        "--require-air-gap", "--zeek-site-script", "/opt/nids/lab/zeek/local.zeek"]},
            "monitor_urls": ["https://blog.lab", "https://shop.lab"], "monitor_interval": 2.0,
            "runners": {"nb1": {"kind": "ssh", "target": "lab@10.10.10.11", "key": "~/.ssh/id_lab"},
                        "nb2": {"kind": "windows", "target": "lab@10.10.10.20"},   # native Windows [§7]
                        "nb3": {"kind": "ssh", "target": "lab@10.10.10.30"},
                        "nb4": {"kind": "local"}}}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Orchestrate one end-to-end run ({}).".format(runlib.TOOL_VERSION))
    ap.add_argument("--config", help="run config JSON (see --print-example-config)")
    ap.add_argument("--run-id", help="override the config's run_id")
    ap.add_argument("--dry-run", action="store_true", help="stub every step (record argv, touch no host)")
    ap.add_argument("--print-example-config", action="store_true")
    args = ap.parse_args(argv)
    runlib.print_banner("orchestrate_run.py")
    if args.print_example_config:
        print(json.dumps(example_config(), indent=2))
        return 0
    if not args.config:
        sys.exit("ABORT: --config is required (or use --print-example-config).")
    cfg = runlib.read_json(args.config)
    if args.run_id is not None:
        cfg["run_id"] = args.run_id
    run_dir = prepare_run_dir(cfg["base_dir"], cfg["run_id"], overwrite=cfg.get("overwrite", False))
    # Generate the run's attempt_id HERE and pin it in cfg, so build_steps shares it with every producer AND
    # the orchestration report records it — the finalizer binds the seal to this attempt [audit v20.44 §5/§6].
    cfg["attempt_id"] = cfg.get("attempt_id") or uuid.uuid4().hex
    steps = build_steps(cfg, run_dir, dry_run=args.dry_run)
    report_path = os.path.join(run_dir, "run{}_orchestration.json".format(cfg["run_id"]))
    _csha = None                                                 # bind the report to THIS campaign+run [§8]
    try:
        _csha = runlib.sha256_file(cfg["campaign"])
    except Exception:
        pass
    report = run_pipeline(steps, report_path, attempt_id=cfg["attempt_id"],
                          campaign_sha256=_csha, run_id=cfg["run_id"])   # writes run<N>_orchestration.json

    # finalize runs LAST, in main (not as a pipeline step), so it seals the orchestration report too
    # [§14]. It runs only if the pipeline PASSED — a failed run is never sealed as complete.
    overall = report["overall"]
    if overall == "PASS":
        if args.dry_run:
            # dry-run seals nothing, so it is safe to fold the finalize INTENT into the report.
            report["finalize"] = {"dry_run": True, "argv": finalize_argv(cfg, run_dir)}
            runlib.write_json(report_path, report)
        else:
            # finalize seals the run INCLUDING run<N>_orchestration.json (written above). Do NOT rewrite
            # that report afterwards or --verify would flag it as tampered — keep the finalize outcome
            # in memory only; finalize's own completion_status.json is the authoritative seal [§14].
            nb4 = runlib.make_runner(cfg.get("runners", {}).get("nb4", {"kind": "local"}))
            fr = nb4.run(finalize_argv(cfg, run_dir), timeout=cfg.get("finalize_timeout", 600))
            report["finalize"] = fr.as_dict()
            if not fr.ok:
                overall = "FAIL"

    for s in report["steps"]:
        mark = "skip" if s.get("skipped") else ("ok" if s["ok"] else "FAIL")
        print("  [{}] {}".format(mark, s["step"]))
    print("ORCHESTRATE run{} -> {} (aborted_at={}, finalize={})".format(
        cfg["run_id"], overall, report["aborted_at"],
        "ok" if (report.get("finalize", {}).get("dry_run") or report.get("finalize", {}).get("returncode") == 0)
        else ("n/a" if "finalize" not in report else "FAIL")))
    return 0 if overall == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
