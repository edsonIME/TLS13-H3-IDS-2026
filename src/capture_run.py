#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
capture_run.py — control ONE PCAP capture on the NB4 sensor [audit v20.26].

This is the missing "start the sensor" script: it picks the mirror interface, opens a
fresh run directory (never clobbering a previous run), records the clock, runs tcpdump,
watches the growing PCAP, stops cleanly, and seals the capture with tcpdump's own
packets-received/dropped stats plus the PCAP's SHA-256. A high drop rate is the single
most important thing to know BEFORE labeling — it means the ground truth and the capture
disagree — so it is recorded prominently.

Artifacts (under <base>/run<N>/):
  run<N>.pcap                run<N>_capture_start.json   run<N>_capture_end.json
  run<N>_tcpdump.log         run<N>_pcap.sha256

The pure helpers `pcap_report` and `parse_tcpdump_stats` are unit-tested directly; the
capture itself needs CAP_NET_RAW + a real interface, so `--simulate` treats a pre-placed
file at the PCAP path as the capture to exercise the sealing/report path anywhere.
"""

import argparse
import os
import re
import signal
import sys
import time

import runlib
import clock_evidence


# A STOP is signalled by setting a FLAG (not by raising) so a stop that lands during clock collection or
# any preamble is never SWALLOWED by an exception handler — the capture loop simply notices the flag and
# exits, and the seal (in main's finally) always runs [audit v20.31 §11].
_STOP = {"requested": False}


def _request_stop(*_):
    _STOP["requested"] = True


def _nonneg_int(s):
    """argparse type: integer >= 0 (rejects -1/junk) [audit v20.30 §11]."""
    v = int(s)
    if v < 0:
        raise argparse.ArgumentTypeError("must be an integer >= 0")
    return v


def _frac01(s):
    """argparse type: FINITE fraction in [0,1] — rejects NaN/inf/negatives/>1 so a bogus drop ceiling
    can't silently disable the gate (any comparison with NaN is false) [audit v20.30 §11]."""
    import math
    v = float(s)
    if not math.isfinite(v) or not (0.0 <= v <= 1.0):
        raise argparse.ArgumentTypeError("must be a finite number in [0,1]")
    return v


def parse_tcpdump_stats(stderr):
    """Extract tcpdump's end-of-run stats from its stderr, e.g.:
        '1234 packets captured\n1240 packets received by filter\n6 packets dropped by kernel'
    Missing counters stay None. The DROP rate is what tells you the capture is trustworthy."""
    out = {"packets_captured": None, "packets_received": None, "packets_dropped": None}
    for pat, key in ((r"(\d+)\s+packets captured", "packets_captured"),
                     (r"(\d+)\s+packets received by filter", "packets_received"),
                     (r"(\d+)\s+packets dropped by kernel", "packets_dropped")):
        m = re.search(pat, stderr or "")
        if m:
            out[key] = int(m.group(1))
    recv, drop = out["packets_received"], out["packets_dropped"]
    out["drop_rate"] = (drop / recv) if (recv and drop is not None) else (0.0 if recv else None)
    return out


def pcap_report(pcap_path):
    """Size + SHA-256 of the produced PCAP (or exists=False). Sealing evidence for the run."""
    if not os.path.exists(pcap_path):
        return {"exists": False, "size_bytes": 0, "sha256": None}
    return {"exists": True, "size_bytes": os.path.getsize(pcap_path),
            "sha256": runlib.sha256_file(pcap_path)}


def _capture(pcap_path, log_path, interface, bpf, duration, tcpdump):
    """Run tcpdump into `pcap_path` for `duration` seconds, then stop it cleanly (SIGINT so it
    flushes stats) and KILL if it lingers. Returns (returncode, stderr_text). Needs privileges.

    EARLY STOP: when driven by the orchestrator this process is started in the BACKGROUND and later
    stopped with SIGINT/SIGTERM (attacks + cool-down are done). We catch that here and fall through
    to the `finally`, which flushes tcpdump and returns its stats — so the capture is ALWAYS sealed,
    whether it ran the full `duration` or was cut short [audit v20.27 §2]."""
    argv = [tcpdump, "-i", interface, "-w", pcap_path, "-U"]
    if bpf:
        argv.append(bpf)                                   # a single BPF expression, e.g. "not (host X and port 22)"
    with open(log_path, "w", encoding="utf-8") as log:
        log.write("$ {}\n".format(" ".join(argv)))
        log.flush()
        proc = __import__("subprocess").Popen(argv, stdout=log, stderr=__import__("subprocess").PIPE,
                                              text=True, start_new_session=True)
        pidfile = pcap_path + ".pid"
        with open(pidfile, "w") as pf:
            pf.write(str(proc.pid))
        deadline = time.time() + duration
        try:
            while time.time() < deadline and proc.poll() is None and not _STOP["requested"]:
                time.sleep(min(1.0, max(0.0, deadline - time.time())))
                sz = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0
                log.write("[{}] pcap {} bytes\n".format(runlib.utc_now_iso(), sz)); log.flush()
        except KeyboardInterrupt:                          # belt-and-braces; the flag is the primary path
            log.write("[{}] stop requested — flushing tcpdump\n".format(runlib.utc_now_iso())); log.flush()
        finally:
            if proc.poll() is None:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGINT)   # flush + write stats
                    time.sleep(2)
                except (ProcessLookupError, PermissionError):
                    pass
                if proc.poll() is None:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
            _, err = proc.communicate()
            try:
                os.remove(pidfile)
            except OSError:
                pass
    return proc.returncode, err or ""


def _simulate_capture(pcap_path, log_path, duration):
    """Stand-in for `_capture` without CAP_NET_RAW: ensure a non-empty PCAP exists, then hold for
    `duration` seconds while remaining interruptible, so the orchestrator's background start/stop
    lifecycle (and the early-seal path) is exercised anywhere [audit v20.27 §2]. Returns tcpdump-shaped
    (returncode, stderr) so the same sealing code runs."""
    if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) == 0:
        with open(pcap_path, "wb") as fh:                  # minimal pcap global header (libpcap magic)
            fh.write(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                     b"\x00\x00\x04\x00\x01\x00\x00\x00SIMULATED-CAPTURE")
    packets = 0
    with open(log_path, "a", encoding="utf-8") as log:
        log.write("[{}] SIMULATED capture holding up to {}s\n".format(runlib.utc_now_iso(), duration))
        log.flush()
        deadline = time.time() + max(0.0, duration)
        try:
            while time.time() < deadline and not _STOP["requested"]:   # flag = primary stop path [§11]
                time.sleep(min(0.1, max(0.0, deadline - time.time())))
                try:
                    with open(pcap_path, "ab") as pf:      # append a fake packet record so the PCAP GROWS
                        pf.write(b"\x00" * 16)             # (lets the STRICT-growth readiness gate pass)
                    packets += 1
                except OSError:
                    pass
        except KeyboardInterrupt:
            log.write("[{}] SIMULATED stop requested\n".format(runlib.utc_now_iso())); log.flush()
    # Report a realistic packet count (= records written) so a --min-packets gate is testable [§4].
    return 0, "{n} packets captured\n{n} packets received by filter\n0 packets dropped by kernel".format(n=packets)


def _safe_clock(phase):
    """Collect clock evidence with a SHORT per-probe timeout, swallowing only ordinary Exceptions (a slow
    probe must not break the seal). It must NOT swallow a KeyboardInterrupt — the stop is signalled by a
    flag now, but if one is ever raised it must propagate so the process stops promptly rather than
    silently continuing to hold [audit v20.31 §11]."""
    try:
        return clock_evidence.collect("NB4", phase, timeout=2)
    except Exception as exc:                               # NOT BaseException — never swallow a stop
        return {"error": "clock collection skipped: {}".format(repr(exc)[:120]), "phase": phase}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Control one NB4 PCAP capture ({}).".format(runlib.TOOL_VERSION))
    ap.add_argument("--base-dir", help="root under which run<N>/ is created (omit if --run-dir given)")
    ap.add_argument("--run-dir", help="use this EXISTING run directory as-is (the orchestrator already "
                                      "created and owns it — skips the overwrite guard) [audit v20.27 §5]")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--attempt-id", default="", help="the run's shared attempt_id, stamped on capture_start/"
                    "end so the seal can bind this capture to the attempt [audit v20.46 §10]")
    ap.add_argument("--interface", default="enp0s3", help="mirror/capture interface on NB4")
    ap.add_argument("--duration", type=float, default=300.0,
                    help="max capture seconds; a background capture is normally stopped EARLY by the "
                         "orchestrator after attacks+cool-down, so this is the safety cap")
    ap.add_argument("--filter", default="", help="ONE tcpdump BPF expression (do NOT exclude scan ports)")
    ap.add_argument("--tcpdump", default="tcpdump", help="tcpdump binary (override for tests)")
    ap.add_argument("--overwrite", action="store_true", help="replace an existing run directory")
    ap.add_argument("--min-packets", type=_nonneg_int, default=0,
                    help="ABORT if fewer than N packets were captured (0 = off; the OFFICIAL config pins "
                         "a real floor so a header-only PCAP can't pass) [audit v20.29 §4]")
    ap.add_argument("--max-drop-rate", type=_frac01, default=None,
                    help="ABORT if the kernel drop rate exceeds this finite [0,1] fraction (e.g. 0.02) [§4/§11]")
    ap.add_argument("--allow-returncode", type=int, action="append", default=None,
                    help="tcpdump return code(s) to accept besides 0 (repeatable); a clean signal-stop is "
                         "already 0, so by default ANY non-zero rc ABORTS [audit v20.29 §4]")
    ap.add_argument("--simulate", action="store_true",
                    help="skip tcpdump; synthesize a non-empty PCAP and hold interruptibly for --duration "
                         "(exercises the sealing + background start/stop path without CAP_NET_RAW)")
    args = ap.parse_args(argv)
    runlib.print_banner("capture_run.py")

    # A stop (SIGINT/SIGTERM) sets a FLAG — it is never raised — so it can't be swallowed by any handler
    # during the start/clock preamble; the capture loop notices the flag and exits, and the finally below
    # ALWAYS seals [audit v20.31 §11].
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)

    if args.run_dir:                                        # orchestrator owns the directory [§5]
        run_dir = args.run_dir
        os.makedirs(run_dir, exist_ok=True)
    elif args.base_dir:
        run_dir = runlib.ensure_run_dir(args.base_dir, args.run_id, overwrite=args.overwrite)
    else:
        ap.error("one of --run-dir or --base-dir is required")
    pcap = os.path.join(run_dir, "run{}.pcap".format(args.run_id))
    log_path = os.path.join(run_dir, "run{}_tcpdump.log".format(args.run_id))

    if not args.simulate and runlib.which(args.tcpdump) is None:
        sys.exit("ABORT: tcpdump ('{}') not found on PATH — install it or pass --tcpdump.".format(args.tcpdump))

    # rc/stderr default so the finally can ALWAYS seal, even if a stop lands before capture begins.
    rc, stderr = None, "0 packets captured\n0 packets received by filter\n0 packets dropped by kernel"
    try:
        start = {"run_id": args.run_id, "attempt_id": args.attempt_id, "interface": args.interface,
                 "filter": args.filter, "duration_s": args.duration, "started_utc": runlib.utc_now_iso(),
                 "tcpdump_version": runlib.tool_version(args.tcpdump) if not args.simulate else "SIMULATED",
                 "clock": _safe_clock("start")}
        runlib.write_json(os.path.join(run_dir, "run{}_capture_start.json".format(args.run_id)), start)
        if args.simulate:
            rc, stderr = _simulate_capture(pcap, log_path, args.duration)
        else:
            rc, stderr = _capture(pcap, log_path, args.interface, args.filter, args.duration, args.tcpdump)
    except KeyboardInterrupt:                              # belt-and-braces; the flag is the primary path
        rc = rc if rc is not None else 0
    finally:
        # The seal write is NON-SKIPPABLE: whatever happened above (interrupt during start/clock/capture),
        # run<N>_capture_end.json is written here so the run is always sealed [audit v20.31 §11].
        stats = parse_tcpdump_stats(stderr)
        rep = pcap_report(pcap)
        end = {"run_id": args.run_id, "attempt_id": args.attempt_id, "ended_utc": runlib.utc_now_iso(),
               "tcpdump_returncode": rc if rc is not None else 0,
               "pcap": rep, "tcpdump_stats": stats, "clock": _safe_clock("end")}
        runlib.write_json(os.path.join(run_dir, "run{}_capture_end.json".format(args.run_id)), end)
        if rep["sha256"]:
            with open(os.path.join(run_dir, "run{}_pcap.sha256".format(args.run_id)), "w") as fh:
                fh.write("{}  run{}.pcap\n".format(rep["sha256"], args.run_id))
    rc = rc if rc is not None else 0

    # A capture is VALID only if tcpdump succeeded AND produced real data. A partial PCAP left behind by a
    # FAILING tcpdump must NOT read as success — the run would attack an unrecorded network [audit v20.29 §4].
    allowed_rc = set(args.allow_returncode or [0])
    drop = stats.get("drop_rate")
    packets = stats.get("packets_captured")
    problems = []
    if rc not in allowed_rc:
        problems.append("tcpdump returncode {} not in allowed {}".format(rc, sorted(allowed_rc)))
    if not rep["exists"] or rep["size_bytes"] == 0:
        problems.append("PCAP is empty ({} bytes) — check the mirror/interface".format(rep["size_bytes"]))
    if args.min_packets and (packets is None or packets < args.min_packets):
        problems.append("packets_captured {} < --min-packets {}".format(packets, args.min_packets))
    if args.max_drop_rate is not None and drop is not None and drop > args.max_drop_rate:
        problems.append("drop_rate {:.4%} > --max-drop-rate {:.4%}".format(drop, args.max_drop_rate))
    if problems:
        sys.exit("ABORT capture run{}: {}. (capture_end.json was still written for evidence) "
                 "[audit v20.29 §4]".format(args.run_id, "; ".join(problems)))

    print("capture run{} -> {} ({} bytes, sha256 {}…); packets={}, drops={}".format(
        args.run_id, pcap, rep["size_bytes"], (rep["sha256"] or "")[:12],
        packets, "n/a" if drop is None else "{:.4%}".format(drop)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
