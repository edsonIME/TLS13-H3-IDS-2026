#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
clock_evidence.py — capture CLOCK-SYNC evidence on one host at the start/end of a run
[audit v20.26]. NB3 (attacker) and NB4 (sensor) share a clock via NB1's chrony server;
this records HOW well, so a reviewer can trust that an attack window's timestamps line
up with the captured flows (the temporal tie the consumer enforces [audit v20.25 §6]).

Linux : `chronyc tracking`, `chronyc sources -v`, `timedatectl`
Windows: `w32tm /query /status`

Output: run<N>_<host>_clock_<phase>.json  (phase = start|end)

The PARSERS are pure functions (parse_chronyc_tracking / parse_w32tm_status /
parse_timedatectl), so they are unit-tested on captured sample text without a synced
clock — the collection wrapper degrades to whatever tools exist and records the rest as
null, never crashing a run for a missing binary.
"""

import argparse
import os
import platform
import re
import socket
import sys

import runlib


def parse_chronyc_tracking(text):
    """Pull the fields that matter from `chronyc tracking` output into a flat dict. Missing lines
    become None so a partial/old chrony still yields a well-formed record."""
    out = {"reference": None, "stratum": None, "system_time_offset_s": None,
           "rms_offset_s": None, "root_dispersion_s": None, "leap_status": None}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key, val = key.strip().lower(), val.strip()
        if key == "reference id":
            out["reference"] = val
        elif key == "stratum":
            out["stratum"] = _int(val)
        elif key == "system time":                          # 'System time : 0.000000123 seconds slow of NTP time'
            out["system_time_offset_s"] = _first_float(val)
        elif key == "rms offset":
            out["rms_offset_s"] = _first_float(val)
        elif key == "root dispersion":
            out["root_dispersion_s"] = _first_float(val)
        elif key == "leap status":
            out["leap_status"] = val
    return out


def parse_w32tm_status(text):
    """Pull key fields from Windows `w32tm /query /status` output."""
    out = {"source": None, "stratum": None, "phase_offset_s": None, "dispersion_s": None,
           "leap_indicator": None}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key, val = key.strip().lower(), val.strip()
        if key == "source":
            out["source"] = val
        elif key == "stratum":
            out["stratum"] = _int(_first_token(val))
        elif key == "phase offset":
            out["phase_offset_s"] = _first_float(val)
        elif key == "root dispersion":
            out["dispersion_s"] = _first_float(val)
        elif key == "leap indicator":
            out["leap_indicator"] = val
    return out


def parse_timedatectl(text):
    """Pull `System clock synchronized` / `NTP service` booleans + time zone from timedatectl."""
    out = {"synchronized": None, "ntp_service": None, "time_zone": None}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key, val = key.strip().lower(), val.strip()
        if key == "system clock synchronized":
            out["synchronized"] = val.lower() == "yes"
        elif key in ("ntp service", "network time on"):
            out["ntp_service"] = val.lower() in ("active", "yes", "on")
        elif key == "time zone":
            out["time_zone"] = val
    return out


def collect(host_label, phase, timeout=5):
    """Collect clock evidence on THIS host, tolerating any missing tool. Returns the record dict.

    `timeout` bounds EACH external probe: the capture-sealing path passes a SHORT one so a slow/hung
    `chronyc`/`timedatectl` can never make sealing exceed the orchestrator's stop-grace (which would get
    the capture SIGKILLed mid-seal and lose run<N>_capture_end.json) [audit v20.29 §3.3]."""
    rec = {"host_label": host_label, "phase": phase, "collected_utc": runlib.utc_now_iso(),
           "hostname": socket.gethostname(), "platform": platform.platform(),
           "chronyc_tracking": None, "chronyc_sources_raw": None, "timedatectl": None,
           "w32tm_status": None, "tools_present": {}}
    try:
        rec["ip"] = socket.gethostbyname(socket.gethostname())
    except OSError:
        rec["ip"] = None
    for tool in ("chronyc", "timedatectl", "w32tm"):
        rec["tools_present"][tool] = runlib.which(tool) is not None
    if rec["tools_present"].get("chronyc"):
        r = runlib.run_cmd(["chronyc", "tracking"], timeout=timeout)
        if r.ok:
            rec["chronyc_tracking"] = parse_chronyc_tracking(r.stdout)
        s = runlib.run_cmd(["chronyc", "sources", "-v"], timeout=timeout)
        rec["chronyc_sources_raw"] = (s.stdout or "")[-4000:] if s.ok else None
    if rec["tools_present"].get("timedatectl"):
        r = runlib.run_cmd(["timedatectl"], timeout=timeout)
        if r.ok:
            rec["timedatectl"] = parse_timedatectl(r.stdout)
    if rec["tools_present"].get("w32tm"):                   # Windows
        r = runlib.run_cmd(["w32tm", "/query", "/status"], timeout=timeout)
        if r.ok:
            rec["w32tm_status"] = parse_w32tm_status(r.stdout)
    return rec


def _int(s):
    m = re.search(r"-?\d+", s or "")
    return int(m.group()) if m else None


def _first_float(s):
    m = re.search(r"-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?", s or "")
    return float(m.group()) if m else None


def _first_token(s):
    return (s or "").split()[0] if (s or "").split() else ""


def main(argv=None):
    ap = argparse.ArgumentParser(description="Collect clock-sync evidence for one host/phase "
                                             "({}).".format(runlib.TOOL_VERSION))
    ap.add_argument("--run-dir", required=True, help="the run's directory (created by capture/orchestrate)")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--host-label", required=True, help="NB1|NB2|NB3|NB4 (which notebook this is)")
    ap.add_argument("--phase", required=True, choices=["start", "end"])
    args = ap.parse_args(argv)
    runlib.print_banner("clock_evidence.py")
    rec = collect(args.host_label, args.phase)
    out = os.path.join(args.run_dir, "run{}_{}_clock_{}.json".format(
        args.run_id, args.host_label.lower(), args.phase))
    sha = runlib.write_json(out, rec)
    print("clock evidence [{}/{}] -> {} (sha256 {}…)".format(args.host_label, args.phase, out, sha[:12]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
