#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
process_pcap.py — run Zeek over a run's PCAP and verify the logs [audit v20.26].

Replaces the manual `zeek -C -r run0.pcap local`: it runs Zeek into a dedicated per-run
log directory, checks the exit code, confirms the REQUIRED logs exist and are non-empty
(conn.log, ssl.log, quic.log — the encrypted-traffic story needs the TLS/QUIC ones), counts
records, hashes each log, and writes a report. An empty ssl.log/quic.log after a capture that
DID contain TLS/QUIC almost always means a missing Zeek plugin (JA3) or QUIC support — catching
it here saves discovering it after seven runs.

`--check-env` runs the environment probe alone (Zeek present? which scripts/plugins? version?),
so it can gate a campaign before any capture.

Artifacts (under the run dir): run<N>_zeek_processing.json, run<N>_zeek_hashes.json, and a
zeek_logs/ directory with the raw logs. `zeek_log_report` (pure) is unit-tested on sample logs.
"""

import argparse
import glob
import os
import sys

import runlib

# flowmeter.log carries the per-flow packet/IAT statistics. Requiring it here means a
# site script missing `@load flowmeter` aborts BEFORE a run is processed, the same way
# a missing JA3 plugin already aborts on ssl.log.
REQUIRED_LOGS = ("conn.log", "ssl.log", "quic.log", "flowmeter.log")


def zeek_log_report(log_path):
    """Report on one Zeek TSV log: exists, record count (non-comment lines), field list, sha256,
    and an `empty` flag. Zeek logs start with '#fields\\t...'; data rows are the rest."""
    if not os.path.exists(log_path):
        return {"exists": False, "records": 0, "fields": [], "sha256": None, "empty": True}
    fields, records = [], 0
    with open(log_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
            elif line.startswith("#") or not line.strip():
                continue
            else:
                records += 1
    return {"exists": True, "records": records, "fields": fields,
            "sha256": runlib.sha256_file(log_path), "empty": records == 0}


def check_environment(zeek="zeek", site_script="local"):
    """Probe the Zeek install BEFORE a campaign: present? version? JA3 + QUIC analyzers loaded? and — if
    `site_script` is a FILE PATH (the versioned lab/zeek/local.zeek) — does it actually EXIST, and what is
    its SHA-256? [audit v20.30 §13]. A missing/renamed site script or a missing QUIC analyzer means the
    ssl.log/quic.log would be wrong, so those are PROBLEMS, not silent passes. A tiny real capture is out
    of scope here (needs an interface); this is the static + `zeek -N` probe."""
    env = {"zeek_path": runlib.which(zeek), "zeek_version": runlib.tool_version(zeek, "--version"),
           "plugins": None, "site_script": site_script, "site_script_is_file": False,
           "site_script_sha256": None, "ok": False, "problems": []}
    if env["zeek_path"] is None:
        env["problems"].append("zeek not found on PATH")
        return env
    # If a versioned site script was named as a PATH, it must exist (a bare 'local' is Zeek's builtin).
    if os.sep in site_script or site_script.endswith(".zeek"):
        if os.path.exists(site_script):
            env["site_script_is_file"] = True
            env["site_script_sha256"] = runlib.sha256_file(site_script)
        else:
            env["problems"].append("site_script {!r} does not exist on disk".format(site_script))
    plug = runlib.run_cmd([zeek, "-N"], timeout=20)         # recorded for evidence only (see below)
    env["plugins"] = (plug.stdout or "")[-4000:]
    # JA3 (salesforce) is a SCRIPT package and QUIC is BUILT-IN in Zeek 8 — NEITHER registers in `zeek -N`,
    # so scanning that output for them yields FALSE NEGATIVES even when both work (verified empirically:
    # ssl.log gains ja3/ja3s and quic.log is produced). The meaningful check is whether the site script
    # actually pulls them in: it must @load the JA3 package and base/protocols/quic, AND the JA3 package
    # must be installed (zkg). We assert the @loads statically here; the `zeek -b site_script` probe below
    # then proves the script (and thus those @loads) resolves without error — that is the real gate.
    site_txt = ""
    if env.get("site_script_is_file"):
        try:
            site_txt = open(site_script, encoding="utf-8", errors="replace").read()
        except OSError:
            site_txt = ""
    import re as _re
    loads_ja3  = bool(_re.search(r'(?m)^\s*@load\s+.*ja3', site_txt))
    loads_quic = bool(_re.search(r'(?m)^\s*@load\s+.*quic', site_txt))
    if not loads_ja3:
        env["problems"].append("site script does not @load the JA3 package (ssl.log would lack ja3/ja3s)")
    if not loads_quic:
        env["problems"].append("site script does not @load base/protocols/quic (quic.log/HTTP-3 missing)")
    # Whether the JA3 package is actually AVAILABLE to Zeek is proven by the `zeek -b site_script` probe
    # below: if @load ja3 referenced a missing package, that load fails (rc!=0) and is reported there.
    # We do NOT use `zkg list` here: zkg state is per-user, and a system-wide (sudo) install is invisible
    # to a non-root `zkg list`, which would false-negative even though Zeek loads JA3 fine (verified:
    # ssl.log gains ja3/ja3s). Record zkg output only as best-effort evidence, never as a gate.
    zkg = runlib.run_cmd(["zkg", "list"], timeout=20)
    env["zkg_list_tail"] = (zkg.stdout or "")[-1000:]
    env["ja3_pkg_in_user_zkg"] = ("ja3" in (zkg.stdout or "").lower())
    # Actually try to LOAD the site script so a SYNTAX error is caught here, not after a whole capture is
    # burned [audit v20.31 §14]. A load error exits fast with an error on stderr; a script that PARSES waits
    # for packets and is killed by the timeout (which we treat as 'loaded ok').
    if env["site_script_is_file"]:
        r = runlib.run_cmd([zeek, "-b", site_script], timeout=8)
        # A script that PARSES waits for packets and is killed by the timeout (treat as loaded ok); a
        # script that loads and exits cleanly returns 0. ANY OTHER non-zero exit means it FAILED to load
        # — fail CLOSED on rc!=0 regardless of whether a known keyword appears on stderr. The previous
        # `not any(keyword)` heuristic failed OPEN: a real load error whose message lacked our keywords
        # was wrongly accepted [audit v20.32 §15].
        loaded = bool(r.timed_out) or r.returncode == 0
        env["site_script_loads"] = loaded
        env["site_script_load_rc"] = None if r.timed_out else r.returncode
        env["site_script_load_timed_out"] = bool(r.timed_out)
        if not loaded:
            env["problems"].append("site_script failed to load in `zeek -b` (rc={}): {}".format(
                r.returncode, (r.stderr or "")[-200:]))
    env["ok"] = not env["problems"]
    return env


def run_zeek(pcap, out_dir, zeek="zeek", site_script="local", extra=None):
    """Run Zeek over `pcap` in `out_dir` (logs are written to the CWD, so we run WITH cwd=out_dir).
    Returns the CmdResult. `-C` ignores checksum offloading; `site_script` is usually 'local'."""
    os.makedirs(out_dir, exist_ok=True)
    argv = [zeek, "-C", "-r", os.path.abspath(pcap), site_script] + list(extra or [])
    return runlib.run_cmd(argv, timeout=None, cwd=out_dir)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run Zeek over a run PCAP and verify the logs "
                                             "({}).".format(runlib.TOOL_VERSION))
    ap.add_argument("--zeek", default="zeek", help="zeek binary (override for tests)")
    ap.add_argument("--site-script", default="local", help="Zeek site script to load (default: local)")
    ap.add_argument("--check-env", action="store_true", help="only probe the Zeek environment and exit")
    ap.add_argument("--run-dir", help="the run directory containing run<N>.pcap")
    ap.add_argument("--run-id")
    ap.add_argument("--attempt-id", default="", help="the run's shared attempt_id, stamped on zeek_processing "
                    "so the seal can bind the Zeek processing to the attempt [audit v20.46 §10]")
    args = ap.parse_args(argv)
    runlib.print_banner("process_pcap.py")

    if args.check_env:
        env = check_environment(args.zeek, args.site_script)
        print("zeek env: {}".format("OK" if env["ok"] else "PROBLEMS {}".format(env["problems"])))
        if args.run_dir:
            runlib.write_json(os.path.join(args.run_dir, "zeek_env_check.json"), env)
        return 0 if env["ok"] else 2

    if not (args.run_dir and args.run_id):
        sys.exit("ABORT: --run-dir and --run-id are required unless --check-env.")
    pcap = os.path.join(args.run_dir, "run{}.pcap".format(args.run_id))
    if not os.path.exists(pcap):
        sys.exit("ABORT: PCAP {} not found — run capture_run.py first.".format(pcap))
    if runlib.which(args.zeek) is None:
        sys.exit("ABORT: zeek ('{}') not found on PATH — install it or pass --zeek.".format(args.zeek))

    log_dir = os.path.join(args.run_dir, "zeek_logs")
    r = run_zeek(pcap, log_dir, args.zeek, args.site_script)
    reports = {name: zeek_log_report(os.path.join(log_dir, name))
               for name in sorted(set(REQUIRED_LOGS) | {os.path.basename(p)
                                   for p in glob.glob(os.path.join(log_dir, "*.log"))})}
    # Record WHICH site script produced these logs + its SHA-256, so a reviewer can prove the exact
    # analyzer set (JA3/QUIC/…) behind an ssl.log/quic.log — the versioned local.zeek is evidence [§15].
    site_is_file = os.path.exists(args.site_script)
    proc = {"run_id": args.run_id, "attempt_id": args.attempt_id, "processed_utc": runlib.utc_now_iso(), "zeek_returncode": r.returncode,
            "zeek_version": runlib.tool_version(args.zeek), "pcap_sha256": runlib.sha256_file(pcap),
            "site_script": args.site_script, "site_script_is_file": site_is_file,
            "site_script_sha256": runlib.sha256_file(args.site_script) if site_is_file else None,
            "logs": reports, "cmd": r.as_dict()}
    runlib.write_json(os.path.join(args.run_dir, "run{}_zeek_processing.json".format(args.run_id)), proc)
    runlib.write_json(os.path.join(args.run_dir, "run{}_zeek_hashes.json".format(args.run_id)),
                      {n: rep["sha256"] for n, rep in reports.items() if rep["sha256"]})

    if r.returncode != 0:
        sys.exit("ABORT: zeek exited {} on {}. [audit v20.26]".format(r.returncode, pcap))
    missing = [n for n in REQUIRED_LOGS if not reports[n]["exists"]]
    empty = [n for n in REQUIRED_LOGS if reports[n]["exists"] and reports[n]["empty"]]
    if missing:
        sys.exit("ABORT: required Zeek log(s) missing: {}. [audit v20.26]".format(missing))
    if empty:
        sys.exit("ABORT: required Zeek log(s) EMPTY: {} — likely a missing JA3/QUIC plugin or a "
                 "capture with no TLS/QUIC. [audit v20.26]".format(empty))
    print("zeek ok: " + ", ".join("{}={}".format(n, reports[n]["records"]) for n in REQUIRED_LOGS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
