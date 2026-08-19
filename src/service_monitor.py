#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
service_monitor.py — sample the victim services on NB1 for the whole run [audit v20.26].

This is the evidence that turns "DoS" from a NAME into a MEASUREMENT. Every `interval`
seconds it probes each victim URL and records availability, HTTP status, and latency, plus
host CPU/memory and (optionally) container state. If a DoS run shows a latency spike / error
burst / availability drop during the attack window, you have the `effect_confirmed` signal
the auditor keeps asking for; if it shows nothing, the honest label is `DoSAttempt`.

Only the Python standard library is used (urllib for HTTP, /proc for host stats, `docker ps`
if present), so it runs on a minimal NB1. `sample_url` is unit-tested against a local server.

Artifacts: run<N>_service_monitor.csv (one row per probe) and run<N>_service_monitor.json
(per-URL summary: availability, p50/p95 latency, worst status, error count).
"""

import argparse
import csv
import datetime
import os
import signal
import ssl
import sys
import time
import urllib.request

import runlib


def sample_url(url, timeout=5.0, insecure=True):
    """Probe one URL once. Returns {ok, http_code, latency_ms, error}. `insecure` accepts the lab's
    self-signed CA (the victims use an internal CA); set False to enforce verification."""
    ctx = None
    if url.lower().startswith("https") and insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    t0 = time.time()
    try:
        with urllib.request.urlopen(url, timeout=timeout, context=ctx) as resp:
            code = resp.getcode()
            resp.read(1024)                                # touch the body so latency includes first bytes
        return {"ok": 200 <= code < 400, "http_code": code, "latency_ms": (time.time() - t0) * 1000.0,
                "error": None}
    except urllib.error.HTTPError as exc:                  # a 4xx/5xx is a REACHED-but-failing service
        return {"ok": False, "http_code": exc.code, "latency_ms": (time.time() - t0) * 1000.0,
                "error": "http_{}".format(exc.code)}
    except Exception as exc:                               # timeout / refused / TLS / DNS
        return {"ok": False, "http_code": None, "latency_ms": (time.time() - t0) * 1000.0,
                "error": type(exc).__name__}


def host_stats():
    """Coarse host load without psutil: CPU busy fraction (delta of /proc/stat over a short window)
    and memory-used fraction (/proc/meminfo). Returns Nones off Linux."""
    out = {"cpu_busy": None, "mem_used_frac": None}
    try:
        def _cpu():
            with open("/proc/stat") as fh:
                parts = [float(x) for x in fh.readline().split()[1:]]
            idle = parts[3] + (parts[4] if len(parts) > 4 else 0.0)
            return sum(parts), idle
        t1, i1 = _cpu(); time.sleep(0.1); t2, i2 = _cpu()
        if t2 > t1:
            out["cpu_busy"] = 1.0 - (i2 - i1) / (t2 - t1)
    except (OSError, IndexError, ValueError):
        pass
    try:
        mem = {}
        with open("/proc/meminfo") as fh:
            for line in fh:
                k, v = line.split(":", 1)
                mem[k] = float(v.strip().split()[0])
        total, avail = mem.get("MemTotal"), mem.get("MemAvailable")
        if total and avail is not None:
            out["mem_used_frac"] = 1.0 - avail / total
    except (OSError, KeyError, ValueError):
        pass
    return out


def container_states(names):
    """`docker ps` status for the named containers, or {} if docker is absent. Best-effort."""
    if not names or runlib.which("docker") is None:
        return {}
    r = runlib.run_cmd(["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"], timeout=10)
    states = {}
    if r.ok:
        for line in r.stdout.splitlines():
            if "\t" in line:
                nm, st = line.split("\t", 1)
                if nm in names:
                    states[nm] = st
    return {nm: states.get(nm, "ABSENT") for nm in names}


def _percentile(values, q):
    if not values:
        return None
    s = sorted(values)
    idx = min(len(s) - 1, int(round(q * (len(s) - 1))))
    return s[idx]


def monitor(urls, duration, interval, csv_path, containers=None, insecure=True):
    """Sample `urls` every `interval`s for `duration`s, streaming rows to `csv_path`. Returns the
    per-URL summary dict. Kept as a function so a test can drive it for ~1s against a local server."""
    per = {u: {"probes": 0, "ok": 0, "latencies": [], "errors": 0, "worst_code": None} for u in urls}
    end = time.time() + duration
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["utc", "url", "ok", "http_code", "latency_ms", "error", "cpu_busy", "mem_used_frac"])
        try:
            while time.time() < end:
                hs = host_stats()
                for u in urls:
                    s = sample_url(u, timeout=min(interval, 5.0), insecure=insecure)
                    w.writerow([runlib.utc_now_iso(), u, int(s["ok"]), s["http_code"],
                                round(s["latency_ms"], 2), s["error"],
                                "" if hs["cpu_busy"] is None else round(hs["cpu_busy"], 3),
                                "" if hs["mem_used_frac"] is None else round(hs["mem_used_frac"], 3)])
                    p = per[u]
                    p["probes"] += 1; p["ok"] += int(s["ok"]); p["latencies"].append(s["latency_ms"])
                    p["errors"] += int(s["error"] is not None)
                    if s["http_code"] and (p["worst_code"] is None or s["http_code"] > p["worst_code"]):
                        p["worst_code"] = s["http_code"]
                fh.flush()
                time.sleep(max(0.0, min(interval, end - time.time())))
        except KeyboardInterrupt:                          # orchestrator stopped us after cool-down
            fh.flush()                                     # rows already streamed; summary from `per` below
    summary = {}
    for u, p in per.items():
        summary[u] = {"probes": p["probes"], "availability": (p["ok"] / p["probes"]) if p["probes"] else None,
                      "p50_latency_ms": _percentile(p["latencies"], 0.5),
                      "p95_latency_ms": _percentile(p["latencies"], 0.95),
                      "errors": p["errors"], "worst_http_code": p["worst_code"]}
    if containers:
        summary["_containers_final"] = container_states(containers)
    return summary


def _to_epoch(text):
    """Parse an ISO-8601 timestamp (tz-aware or naive-as-UTC, tolerating a trailing 'Z') to epoch
    seconds. Both the monitor CSV's `utc` column and the annotations' start_utc/end_utc use this."""
    s = (text or "").strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.timestamp()


def load_windows(events_path, only_success=True, labels=None):
    """Read attack windows (event_id/label + start/end epoch) from the ground-truth annotations CSV —
    the SAME file the labeler consumes — so 'during the attack' means exactly the attacker's timeline.

    `labels`: if given, keep ONLY windows whose label is in it. A DoS effect must be measured against
    the DoS window, NOT against a PortScan/BruteForce window — otherwise a latency blip during a scan
    would falsely 'confirm' a DoS [audit v20.28 §11]."""
    keep = set(labels) if labels else None
    wins = []
    with open(events_path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if only_success and (r.get("status") or "").strip() != "success":
                continue
            lab = (r.get("label") or "").strip()
            if keep is not None and lab not in keep:
                continue
            try:
                start, end = _to_epoch(r["start_utc"]), _to_epoch(r["end_utc"])
            except (KeyError, ValueError, AttributeError):
                continue
            if start < end:
                wins.append({"event_id": (r.get("event_id") or "").strip(), "label": lab,
                             "start": start, "end": end})
    return wins


def analyze_effect(csv_path, windows, avail_drop_min=0.20, latency_mult_min=2.0, err_rate_rise_min=0.20):
    """Turn 'DoS' from a NAME into a MEASUREMENT: split each URL's probes into DURING-attack vs
    BASELINE (outside every window) and confirm an effect only if availability DROPPED, p95 latency
    grew by a factor, or the error rate ROSE past the thresholds. This is the honest `effect_confirmed`
    signal — a run that shows nothing is a DoSAttempt, not a DoS [audit v20.27]."""
    def in_window(t):
        return any(w["start"] <= t <= w["end"] for w in windows)

    per = {}
    with open(csv_path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            try:
                t = _to_epoch(r["utc"])
            except (KeyError, ValueError, AttributeError):
                continue
            bucket = "attack" if in_window(t) else "baseline"
            d = per.setdefault(r.get("url", ""), {"attack": [], "baseline": []})
            try:
                lat = float(r.get("latency_ms") or "nan")
            except ValueError:
                lat = float("nan")
            d[bucket].append((int(r.get("ok") or 0), lat, 1 if (r.get("error") or "").strip() else 0))

    def _avail(rows):
        return (sum(x[0] for x in rows) / len(rows)) if rows else None

    def _p95(rows):
        return _percentile([x[1] for x in rows if x[1] == x[1]], 0.95)   # drop NaN

    def _errrate(rows):
        return (sum(x[2] for x in rows) / len(rows)) if rows else None

    result, any_conf = {}, False
    for url, d in per.items():
        a, b = d["attack"], d["baseline"]
        av_a, av_b = _avail(a), _avail(b)
        l_a, l_b = _p95(a), _p95(b)
        e_a, e_b = _errrate(a), _errrate(b)
        conf, reasons = False, []
        if av_a is not None and av_b is not None and (av_b - av_a) >= avail_drop_min:
            conf = True; reasons.append("availability {:.2f}->{:.2f}".format(av_b, av_a))
        if l_a and l_b and l_b > 0 and (l_a / l_b) >= latency_mult_min:
            conf = True; reasons.append("p95_latency x{:.1f}".format(l_a / l_b))
        if e_a is not None and e_b is not None and (e_a - e_b) >= err_rate_rise_min:
            conf = True; reasons.append("error_rate {:.2f}->{:.2f}".format(e_b, e_a))
        result[url] = {"attack_probes": len(a), "baseline_probes": len(b),
                       "availability_attack": av_a, "availability_baseline": av_b,
                       "p95_latency_attack_ms": l_a, "p95_latency_baseline_ms": l_b,
                       "error_rate_attack": e_a, "error_rate_baseline": e_b,
                       "effect_confirmed": conf, "reasons": reasons}
        any_conf = any_conf or conf
    return {"effect_confirmed": any_conf, "n_windows": len(windows),
            "thresholds": {"avail_drop_min": avail_drop_min, "latency_mult_min": latency_mult_min,
                           "err_rate_rise_min": err_rate_rise_min},
            "per_url": result}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Monitor victim availability/latency during a run, or "
                                             "analyze the effect ({}).".format(runlib.TOOL_VERSION))
    ap.add_argument("--run-dir", help="run directory (required for monitoring)")
    ap.add_argument("--run-id", help="run id (required for monitoring)")
    ap.add_argument("--url", action="append", default=[], help="victim URL to probe (repeatable)")
    ap.add_argument("--duration", type=float, default=300.0,
                    help="max monitor seconds; a background monitor is stopped EARLY by the orchestrator")
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--container", action="append", default=[], help="docker container to watch (repeatable)")
    ap.add_argument("--verify-tls", action="store_true", help="enforce TLS verification (default: accept lab CA)")
    # --- effect analysis mode (post-run) ---
    ap.add_argument("--analyze", action="store_true",
                    help="do NOT probe; instead read a monitor CSV + attack windows and write the "
                         "effect_confirmed report")
    ap.add_argument("--csv", help="[--analyze] monitor CSV to analyze")
    ap.add_argument("--events", help="[--analyze] ground-truth annotations CSV (attack windows)")
    ap.add_argument("--out", help="[--analyze] effect report JSON to write")
    ap.add_argument("--label", action="append", default=None,
                    help="[--analyze] only measure the effect within windows of THIS label (repeatable; "
                         "default: DoS) — a DoS effect must not be 'confirmed' by a scan window [§11]")
    ap.add_argument("--avail-drop-min", type=float, default=0.20)
    ap.add_argument("--latency-mult-min", type=float, default=2.0)
    ap.add_argument("--err-rate-rise-min", type=float, default=0.20)
    args = ap.parse_args(argv)
    runlib.print_banner("service_monitor.py")

    if args.analyze:
        if not (args.csv and args.events and args.out):
            sys.exit("ABORT: --analyze needs --csv, --events and --out.")
        labels = args.label if args.label else ["DoS"]     # default: DoS-only effect [§11]
        windows = load_windows(args.events, labels=labels)
        report = analyze_effect(args.csv, windows, avail_drop_min=args.avail_drop_min,
                                latency_mult_min=args.latency_mult_min, err_rate_rise_min=args.err_rate_rise_min)
        report["effect_labels"] = labels
        report["csv_sha256"] = runlib.sha256_file(args.csv) if os.path.exists(args.csv) else None
        runlib.write_json(args.out, report)
        print("effect_confirmed={} over {} {} window(s) -> {}".format(
            report["effect_confirmed"], report["n_windows"], "/".join(labels), args.out))
        return 0

    if not (args.run_dir and args.run_id and args.url):
        sys.exit("ABORT: monitoring needs --run-dir, --run-id and at least one --url.")
    # SIGTERM behaves like Ctrl-C so a background monitor stopped with either signal still summarizes.
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    csv_path = os.path.join(args.run_dir, "run{}_service_monitor.csv".format(args.run_id))
    try:
        summary = monitor(args.url, args.duration, args.interval, csv_path,
                          containers=args.container, insecure=not args.verify_tls)
    except KeyboardInterrupt:                              # stop fired outside monitor()'s own guard
        summary = {}
    summary_doc = {"run_id": args.run_id, "urls": args.url, "duration_s": args.duration,
                   "interval_s": args.interval, "ended_utc": runlib.utc_now_iso(),
                   "csv_sha256": runlib.sha256_file(csv_path) if os.path.exists(csv_path) else None,
                   "per_url": summary}
    runlib.write_json(os.path.join(args.run_dir, "run{}_service_monitor.json".format(args.run_id)), summary_doc)
    for u, s in summary.items():
        if u.startswith("_"):
            continue
        print("monitor {}: availability={} p95={}ms worst={}".format(
            u, s["availability"], None if s["p95_latency_ms"] is None else round(s["p95_latency_ms"], 1),
            s["worst_http_code"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
