#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
correlate_ground_truth.py — MULTI-LAYER ground truth [audit 16]
================================================================

The pipeline already confirms tool_executed -> traffic_observed -> usable flows.
This tool adds the APPLICATION layer: it cross-references, per attack event,

  * the ground-truth annotations (run_attacks.py: annotations_run<N>.csv),
  * the network evidence (label_flows' <out>_run_status.json events: usable /
    matched flows and, for scans, port_coverage),
  * the application evidence (Caddy JSON access log: requests to the target path
    inside the event window — e.g. Hydra POSTs to /wp-login.php, slow-HTTP GETs).

It DOES NOT prove effect (latency/availability); it raises the confidence level
from "the tool ran" to "the application actually received the requests", and
flags events that look like a NAME mismatch (e.g. a DoS with no measured impact
is more honestly a SlowHTTPDoSAttempt). Output: a JSON report + a printed table.

USAGE
-----
  python3 correlate_ground_truth.py \
      --annotations annotations_run0.csv \
      --run-status labeled_run0_run_status.json \
      --caddy-log blog.access.json \
      --out run0_ground_truth.json
"""

import argparse
import csv
import json
import sys
from datetime import datetime, timezone


def _to_epoch(iso_utc):
    """Parse an ISO-8601 UTC instant (requires tz) to epoch seconds."""
    dt = datetime.fromisoformat(iso_utc.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp has no timezone")
    return dt.astimezone(timezone.utc).timestamp()


def load_caddy(path):
    """Load Caddy JSON access-log lines -> list of dicts with ts/method/uri/status
    AND the client IP + Host, which are REQUIRED to attribute a request to the
    attacker vs a concurrent benign client [audit 10]."""
    reqs = []
    if not path:
        return reqs
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            req = e.get("request", {})
            ts = e.get("ts")                         # Caddy logs unix seconds (float)
            # Caddy may log the client as request.remote_ip (newer) or client_ip;
            # it can be "ip:port". Host is request.host.
            remote = req.get("remote_ip") or req.get("client_ip") or ""
            remote = str(remote).rsplit(":", 1)[0] if remote.count(":") == 1 else str(remote)
            reqs.append({"ts": float(ts) if ts is not None else None,
                         "method": req.get("method", ""), "uri": req.get("uri", ""),
                         "status": e.get("status", 0), "remote_ip": remote,
                         "host": req.get("host", "")})
    return reqs


def main():
    ap = argparse.ArgumentParser(description="Multi-layer ground-truth correlation.")
    ap.add_argument("--annotations", required=True)
    ap.add_argument("--run-status", default=None, help="label_flows' _run_status.json")
    ap.add_argument("--caddy-log", default=None, help="Caddy JSON access log")
    ap.add_argument("--login-path", default="/wp-login.php",
                    help="BruteForce evidence: POST to this path [audit 15]")
    ap.add_argument("--dos-path", default="/",
                    help="DoS evidence: GET starting with this path [audit 15]")
    ap.add_argument("--out", default=None, help="write the JSON report here")
    args = ap.parse_args()

    with open(args.annotations, newline="", encoding="utf-8") as fh:
        events = [r for r in csv.DictReader(fh) if (r.get("status") or "") == "success"]
    status = json.load(open(args.run_status)) if args.run_status else {}
    net_events = status.get("events", {})
    caddy = load_caddy(args.caddy_log)

    report = []
    print("event        label       net_usable  atk_reqs  benign_reqs  evidence")
    for r in events:
        ev = r.get("event_id", "")
        label = r.get("label", "")
        attacker_ip = (r.get("attacker_ip") or "").strip()
        target_host = (r.get("target_hostname") or "").strip()
        try:
            start, end = _to_epoch(r["start_utc"]), _to_epoch(r["end_utc"])
        except (KeyError, ValueError):
            start = end = None
        net = net_events.get(ev, {})
        usable = net.get("usable_flows")
        # App-layer requests INSIDE the window. Attribute ONLY to the attacker IP
        # (and Host, when known); count concurrent BENIGN requests to the same
        # endpoint separately so a benign login is NEVER mistaken for the attack
        # [audit 10]. For BruteForce require POST /wp-login.php.
        # PortScan is a NETWORK-layer attack — an HTTP access log is not valid
        # evidence for it, so we do not credit app requests; its evidence is the
        # per-event port coverage from the sensor [audit 15].
        app_applies = label in ("BruteForce", "DoS")
        atk_reqs = benign_reqs = 0
        if caddy and start is not None and app_applies:
            for q in caddy:
                ts = q["ts"]
                if ts is None or not (start <= ts <= end):
                    continue
                method, uri = q["method"].upper(), (q["uri"] or "")
                if label == "BruteForce":            # POST /wp-login.php only
                    if method != "POST" or args.login_path not in uri:
                        continue
                elif label == "DoS":                 # slow-HTTP GET on the planned path
                    if method != "GET" or not uri.startswith(args.dos_path):
                        continue
                if target_host and q["host"] and q["host"].split(":")[0] != target_host:
                    continue                         # different victim
                if q["remote_ip"] == attacker_ip:
                    atk_reqs += 1
                else:
                    benign_reqs += 1
        # Evidence level [audit 15/16] — application_observed requires ATTACKER reqs.
        levels = ["tool_executed"]                   # annotation exists + status=success
        if usable:
            levels.append("traffic_observed")
        if atk_reqs > 0:
            levels.append("application_observed")
        note = ""
        if label == "DoS":
            note = ("effect NOT measured (slow-HTTP may never emit a completed access "
                    "log) -> report as SlowHTTPDoSAttempt unless latency/availability confirmed")
        elif label == "PortScan" and net.get("port_coverage") is not None:
            note = "port_coverage={} of range width {}".format(
                net.get("port_coverage"), net.get("port_range_width"))
        if benign_reqs and atk_reqs == 0 and label == "BruteForce":
            note = ("{} benign request(s) to {} in-window but NONE from the attacker "
                    "{} — do NOT credit the attack [audit 10]").format(
                        benign_reqs, args.login_path, attacker_ip)
        rec = {"event_id": ev, "label": label, "net_usable_flows": usable,
               "attacker_app_requests": atk_reqs, "benign_app_requests": benign_reqs,
               "evidence_levels": levels, "note": note}
        report.append(rec)
        print("{:<12} {:<11} {:>10}  {:>8}  {:>11}  {}".format(
            ev[:12], label, "" if usable is None else usable, atk_reqs, benign_reqs,
            "->".join(levels)))
        if note:
            print("    note:", note)

    if not caddy:
        print("\nNOTE: no --caddy-log given, so application_observed could not be "
              "confirmed. effect_confirmed (latency/availability) is still out of scope "
              "— measure it separately for a DoS claim. [audit 16]")
    out = {"annotations": args.annotations, "run_status": args.run_status,
           "caddy_log": args.caddy_log, "events": report}
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        print("\nWrote", args.out)
    return out


if __name__ == "__main__":
    main()
