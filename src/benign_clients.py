#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
benign_clients.py — LEVEL 2 benign traffic: concurrent non-browser clients.  (v2)

WHY THIS EXISTS
---------------
benign_traffic.py drives real browsers through Selenium. That produces authentic
handshakes and page-load patterns, but one browser at a time caps it at ~70 sessions per
45-minute run. Measured on campaign nids4d-20260803: 189 benign TCP flows across SEVEN
runs, against 122.808 DoS flows. The benign class was effectively absent.

This module is the complement, not the replacement.

THE FOUR PROBLEMS IT SOLVES
---------------------------
1. VOLUME. Target >= 15.000 benign flows per run. Every client invocation opens a fresh
   connection, so one invocation == one flow.

2. THE JA3 BIJECTION. In v1, ja3 `284deaeae...` appeared ONLY with the attacker host and
   the attacker host ONLY with it — a one-line rule separated 9.167 attack flows
   perfectly, because benign == browsers and attack == Python tooling. The httpx and
   requests profiles deliberately use the SAME TLS stack as hydra and http_flood.py, so
   "non-browser fingerprint" stops meaning "attack". Do not drop them for convenience.

3. HTTP/3 FLOW COUNT. QUIC multiplexes: v1's 31 QUIC connections carried 6,9% of the
   PACKETS but 0,16% of the FLOWS. A flow-based dataset needs MANY SHORT QUIC
   connections, which is what a curl invocation produces.

4. DURATION SPREAD (new in v2). Measured on the lab LAN: p50 = 0,076 s, p95 = 0,152 s —
   a p95/p50 ratio of 2x, where real web traffic is 10-50x. A benign class packed into a
   tiny corner of the feature space is itself a shortcut: one threshold on flow_duration
   separates it. Bigger files do NOT fix this (100 KB crosses a gigabit LAN in
   milliseconds); two other mechanisms do:
     * connection REUSE  -> many requests, ONE flow, seconds instead of milliseconds
     * rate LIMITING     -> makes link speed a controlled variable, and is realistic
   Both are implemented on MORE THAN ONE TLS stack on purpose. If only curl produced long
   flows, "long flow" would imply "curl's JA3" and the v1 leak would be back under a
   different column name.

CONTRACT WITH finalize_run.py
-----------------------------
Records go into the SAME run<N>_benign.jsonl the browser generator writes, because that is
the file _check_benign_evidence validates. Required per record: campaign_id, run_id, seed,
attempt_id, session_id (unique positive int), browser, site, start, end, ok. `browser`
carries the CLIENT id here (e.g. "curl-h3"); `webdriver` carries the client version so
require_browser_evidence still passes. Document the widened meaning in the DATASHEET.

The file is opened in TRUNCATE mode. v1's generator opened it with "a", which left 67
sessions from a previous attempt inside run0's log — do not reintroduce that.

TEMPORAL: every session must fall inside the pcap's first..last packet interval. Start
this AFTER the capture is confirmed running and stop it BEFORE the capture ends;
--start-delay and --stop-margin give the margins, the orchestrator owns the ordering.

USAGE
-----
  python3 benign_clients.py --selftest --sites https://blog.lab https://shop.lab \\
      --campaign-id x --run-id 0 --attempt-id x-r0-a1 --seed 1 --log-jsonl /dev/null

  python3 benign_clients.py --minutes 45 --workers 30 \\
      --sites https://blog.lab https://shop.lab \\
      --campaign-id nids4d-20260901 --run-id 0 --attempt-id nids4d-20260901-r0-a1 \\
      --seed 1234 --log-jsonl /captures/run0/run0_benign.jsonl

SAFETY: requests only the lab victims passed in --sites. Not an attack tool: the per-worker
rate is human-scale and the total is far below the DoS profile by design.
"""

import argparse
import itertools
import json
import os
import queue
import random
import shutil
import subprocess
import sys
import threading
import time

# Paths exercised on each victim. /wp-content/themes/ was REMOVED in v2: it answers 200
# with a ZERO-byte body (directory listing off), so ~11% of benign flows were a full TLS
# handshake transferring nothing — degenerate flows that drag the duration distribution
# down and teach a classifier nothing. /wp-login.php stays: it is the endpoint BruteForce
# targets, and benign traffic must touch it or "anyone hitting wp-login" means "attack".
DEFAULT_PATHS = [
    "/", "/?p=1", "/?p=2", "/feed/", "/wp-login.php", "/?s=lab", "/sample-page/",
    "/wp-includes/js/jquery/jquery.min.js",
    "/wp-includes/css/dist/block-library/style.min.css",
]

# Set once in main() from --paths. Session profiles pick their own paths per request, so
# they read this instead of taking a full URL. Written before any worker starts.
ACTIVE_PATHS = list(DEFAULT_PATHS)


# --------------------------------------------------------------------- process helpers

def _run(argv, timeout):
    """Execute a client process. Returns (ok, detail). Never raises."""
    try:
        p = subprocess.run(argv, timeout=timeout, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
        return p.returncode == 0, (p.stdout or b"")[-40:].decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except OSError as exc:
        return False, "oserror: {}".format(exc)[:60]


# ------------------------------------------------------------- SHORT: single request

def c_curl_h3(url, timeout):
    """HTTP/3 over QUIC, forced. Each invocation is a fresh QUIC connection, which is what
    a flow-based dataset needs — a long browser session would be ONE flow. Requires a curl
    built with HTTP/3 support; preflight() checks that explicitly."""
    return _run(["curl", "--http3-only", "-sS", "-o", os.devnull,
                 "-k", "--max-time", str(timeout), url], timeout + 5)


def c_aioquic_h3(url, timeout):
    """HTTP/3 over QUIC via aioquic, run as a SUBPROCESS (h3_get.py) so its asyncio loop
    stays out of this generator's thread pool. A fresh QUIC connection per invocation is
    what gives the dataset MANY short H3 flows, instead of the browser's few multiplexed
    ones. Falls back cleanly if h3_get.py or aioquic is missing (preflight catches it)."""
    import os as _os
    helper = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "h3_get.py")
    if not _os.path.exists(helper):
        return False, "h3_get.py not found beside benign_clients.py"
    return _run([sys.executable, helper, url, str(timeout)], timeout + 5)


def c_curl_h2(url, timeout):
    """HTTP/2 over TCP, same binary as curl-h3 — so one fingerprint spans both transports,
    which is what stops `transport` from also predicting the client."""
    return _run(["curl", "--http2", "-sS", "-o", os.devnull,
                 "-k", "--max-time", str(timeout), url], timeout + 5)


def c_wget(url, timeout):
    """A third stack in the short region."""
    return _run(["wget", "-q", "-O", os.devnull, "--no-check-certificate",
                 "--timeout", str(timeout), url], timeout + 5)


def c_httpx(url, timeout):
    """Python httpx — the SAME TLS stack the attack tooling uses. Its JA3 colliding with
    the attacker's is the desired outcome, not a defect."""
    try:
        import httpx
    except ImportError:
        return False, "httpx not installed"
    try:
        with httpx.Client(verify=False, timeout=timeout) as cli:
            r = cli.get(url)
        return r.status_code < 500, str(r.status_code)
    except Exception as exc:
        return False, repr(exc)[:60]


def c_requests(url, timeout):
    """Python requests/urllib3 — a second non-browser stack, distinct from httpx."""
    try:
        import requests
        import urllib3
        urllib3.disable_warnings()
    except ImportError:
        return False, "requests not installed"
    try:
        r = requests.get(url, verify=False, timeout=timeout)
        return r.status_code < 500, str(r.status_code)
    except Exception as exc:
        return False, repr(exc)[:60]


# ------------------------------------------- MEDIUM: connection reuse (one flow, many requests)

def c_curl_session(site, timeout, rng):
    """Many requests over ONE reused TLS connection — how a browser loads a page with its
    sub-resources. Produces a single flow with tens of packets and seconds of duration."""
    n = rng.randint(8, 25)
    argv = ["curl", "-sS", "-k", "--max-time", str(timeout)]
    for _ in range(n):
        argv += ["-o", os.devnull, site.rstrip("/") + rng.choice(ACTIVE_PATHS)]
    ok, detail = _run(argv, timeout + 10)
    return ok, "{} reqs {}".format(n, detail)


def c_httpx_session(site, timeout, rng):
    """httpx.Client keeps the connection alive across requests: the Python-stack equivalent
    of curl-session. Keeps the medium-duration region populated by the SAME fingerprint
    family the attack tools use, instead of leaving it curl-only."""
    try:
        import httpx
    except ImportError:
        return False, "httpx not installed"
    n = rng.randint(8, 25)
    try:
        with httpx.Client(verify=False, timeout=timeout) as cli:
            codes = [cli.get(site.rstrip("/") + rng.choice(ACTIVE_PATHS)).status_code
                     for _ in range(n)]
        return all(c < 500 for c in codes), "{} reqs".format(n)
    except Exception as exc:
        return False, repr(exc)[:60]


def c_requests_session(site, timeout, rng):
    """requests.Session over urllib3 — a third stack in the medium-duration region."""
    try:
        import requests
        import urllib3
        urllib3.disable_warnings()
    except ImportError:
        return False, "requests not installed"
    n = rng.randint(8, 25)
    try:
        with requests.Session() as s:
            codes = [s.get(site.rstrip("/") + rng.choice(ACTIVE_PATHS),
                           verify=False, timeout=timeout).status_code for _ in range(n)]
        return all(c < 500 for c in codes), "{} reqs".format(n)
    except Exception as exc:
        return False, repr(exc)[:60]


# ------------------------------------------------------------- LONG: rate-limited

def c_curl_slow(url, timeout, rng):
    """Rate-limited single request: 100 KB at 16 kB/s is ~6 s of flow, with no large files
    needed. Randomised so the tail is a distribution, not a constant."""
    rate = rng.choice(["8k", "16k", "32k", "64k"])
    ok, detail = _run(["curl", "-sS", "-k", "--limit-rate", rate, "-o", os.devnull,
                       "--max-time", str(timeout), url], timeout + 10)
    return ok, "{} {}".format(rate, detail)


def c_wget_slow(url, timeout, rng):
    """Same idea on a different TLS stack, so the long-flow region is not curl-only."""
    rate = rng.choice(["8k", "24k", "48k"])
    ok, detail = _run(["wget", "-q", "-O", os.devnull, "--no-check-certificate",
                       "--limit-rate", rate, "--timeout", str(timeout), url], timeout + 10)
    return ok, "{} {}".format(rate, detail)


# --------------------------------------------------------------------------- registry
# name -> (callable, weight, needs_rng, takes_site)
#   needs_rng  : profile randomises internally (rate, request count) -> receives an rng
#   takes_site : receives the SITE and picks its own paths, instead of a full URL
#
# Target mix: ~50% short, ~35% medium, ~15% long. These weights are a REASONED PROPOSAL,
# not a calibration. Recalibrate against HIKARI's flow_duration percentiles when you have
# them — then the mix is a documented decision in the paper rather than a guess.
PROFILES = {
    # short: one request, full speed. Two H3 clients: curl-h3 (if the curl build has it)
    # and aioquic-h3 (always available once aioquic is installed) — together they carry
    # the QUIC share, so H3 does not depend on the curl build.
    "curl-h3":          (c_curl_h3,          10, False, False),
    "aioquic-h3":       (c_aioquic_h3,       20, False, False),
    "curl-h2":          (c_curl_h2,          10, False, False),
    "httpx":            (c_httpx,             8, False, False),
    "requests":         (c_requests,          6, False, False),
    "wget":             (c_wget,              4, False, False),
    # medium: connection reuse, three different TLS stacks
    "curl-session":     (c_curl_session,     13, True,  True),
    "httpx-session":    (c_httpx_session,    11, True,  True),
    "requests-session": (c_requests_session,  8, True,  True),
    # long: rate-limited, two different TLS stacks
    "curl-slow":        (c_curl_slow,         6, True,  False),
    "wget-slow":        (c_wget_slow,         4, True,  False),
}


def call_profile(name, site, url, timeout, rng):
    """Dispatch one session, hiding the signature differences between profile families."""
    fn, _w, needs_rng, takes_site = PROFILES[name]
    target = site if takes_site else url
    return fn(target, timeout, rng) if needs_rng else fn(target, timeout)


def client_version(profile):
    """Version string for the `webdriver` field, so require_browser_evidence passes."""
    base = profile.split("-")[0]
    if profile == "aioquic-h3":
        try:
            import aioquic
            return "aioquic {}".format(getattr(aioquic, "__version__", "?"))
        except ImportError:
            return "aioquic-h3"
    if base == "curl":
        exe = shutil.which("curl")
        if exe:
            ok, out = _run([exe, "--version"], 5)
            if ok and out.strip():
                return out.strip().splitlines()[0][:60]
        return "curl"
    if base == "wget":
        return "wget"
    try:
        mod = __import__(base)
        return "{} {}".format(base, getattr(mod, "__version__", "?"))
    except ImportError:
        return profile


# ------------------------------------------------------------------------- preflight

def preflight(sites, profiles):
    """Verify every enabled client can actually reach a victim BEFORE a 45-minute run.

    The expensive failure this prevents: Ubuntu's stock curl is built WITHOUT HTTP/3, so
    --http3-only fails on every invocation and the run silently produces zero QUIC while
    HTTP/3 is supposed to be central to the dataset. Find that out here, not afterwards.
    """
    problems, rng = [], random.Random(0)
    if any(p.split("-")[0] == "curl" for p in profiles) and not shutil.which("curl"):
        problems.append("curl not on PATH")
    if any(p.split("-")[0] == "wget" for p in profiles) and not shutil.which("wget"):
        problems.append("wget not on PATH")
    for mod in ("httpx", "requests"):
        if any(p.split("-")[0] == mod for p in profiles):
            try:
                __import__(mod)
            except ImportError:
                problems.append("{} not installed (pip install {})".format(mod, mod))

    if "curl-h3" in profiles and shutil.which("curl"):
        ok3, _ = _run(["curl", "--http3-only", "-sS", "-o", os.devnull, "-k",
                       "--max-time", "8", sites[0]], 15)
        if not ok3:
            problems.append("curl has no working HTTP/3 — remove curl-h3 and rely on "
                            "aioquic-h3, or build curl with ngtcp2/quiche")
    if "aioquic-h3" in profiles:
        try:
            __import__("aioquic")
            ok, detail = c_aioquic_h3(sites[0].rstrip("/") + "/", 10)
            if not ok:
                problems.append("aioquic-h3 could not reach {} ({}) — HTTP/3 is CENTRAL "
                                "to this dataset".format(sites[0], detail))
        except ImportError:
            problems.append("aioquic not installed (pip install aioquic) — needed for H3")

    for site in sites:
        base = site.rstrip("/") + "/"
        if not any(call_profile(name, site, base, 10, rng)[0] for name in profiles):
            problems.append("no enabled client could reach {}".format(site))
    return problems


# ------------------------------------------------------------------------ the workers

def worker(stop_at, sites, paths, profiles, weights, timeout, think, counter, lock,
           out_q, rng_seed, stats, stats_lock):
    """One concurrent client. Runs sessions until the deadline, one connection each."""
    rng = random.Random(rng_seed)
    while time.time() < stop_at:
        profile = rng.choices(profiles, weights=weights, k=1)[0]
        site = rng.choice(sites)
        url = site.rstrip("/") + rng.choice(paths)
        with lock:
            session_id = next(counter)               # unique across ALL workers
        start = time.time()
        _t0 = time.perf_counter()                       # ns-resolution duration clock
        ok, detail = call_profile(profile, site, url, timeout, rng)
        _dur = time.perf_counter() - _t0
        # httpx pooled/cached responses can finish inside one time.time() tick (dur==0),
        # which finalize_run rejects (end <= start). perf_counter measures the real
        # sub-tick duration; floor at 1 microsecond so end is ALWAYS strictly > start.
        end = start + max(_dur, 1e-6)
        # A session ending AFTER the capture stops must not be recorded: it would sit
        # outside the pcap interval and finalize_run rejects the WHOLE jsonl for it.
        if end > stop_at:
            break
        out_q.put({"profile": profile, "site": site, "url": url, "session_id": session_id,
                   "start": start, "end": end, "ok": ok, "detail": detail})
        with stats_lock:
            stats["attempted"] += 1
            stats["ok" if ok else "failed"] += 1
            stats.setdefault("by_profile", {}).setdefault(profile, 0)
            stats["by_profile"][profile] += 1
        time.sleep(rng.uniform(*think))              # human-scale spacing, never uniform


def writer(out_q, path, meta, done):
    """SINGLE writer thread: concurrent appends from N workers would interleave lines.

    Opens with "w" (truncate). v1 used "a" and carried a previous attempt's 67 sessions
    into run0 — that contamination cost a full re-analysis.
    """
    versions = {}
    with open(path, "w", encoding="utf-8") as fh:
        while not (done.is_set() and out_q.empty()):
            try:
                rec = out_q.get(timeout=0.5)
            except queue.Empty:
                continue
            profile = rec["profile"]
            if profile not in versions:
                versions[profile] = client_version(profile)
            fh.write(json.dumps({
                "campaign_id": meta["campaign_id"],
                "run_id": meta["run_id"],
                "attempt_id": meta["attempt_id"],
                "seed": meta["seed"],
                "session_id": rec["session_id"],
                # `browser` carries the CLIENT id: it is the field finalize_run validates.
                "browser": profile,
                "browser_name": profile,
                "browser_version": versions[profile],
                "webdriver": versions[profile],
                "tier": "level2-nonbrowser",       # tells level-1 and level-2 apart later
                "site": rec["site"],
                "url": rec["url"],
                "start": rec["start"],
                "end": rec["end"],
                "pages": 1,
                "ok": bool(rec["ok"]),
                "detail": rec["detail"],
            }) + "\n")
            fh.flush()


def main():
    ap = argparse.ArgumentParser(description="Level-2 benign traffic: concurrent non-browser clients.")
    ap.add_argument("--sites", nargs="+", required=True,
                    help="lab victims, e.g. https://blog.lab https://shop.lab")
    ap.add_argument("--paths", nargs="+", default=DEFAULT_PATHS)
    ap.add_argument("--profiles", nargs="+", default=sorted(PROFILES), choices=sorted(PROFILES))
    ap.add_argument("--workers", type=int, default=30)
    ap.add_argument("--minutes", type=float, default=45.0)
    ap.add_argument("--timeout", type=float, default=60.0,
                    help="per-session timeout (s); rate-limited profiles need headroom")
    ap.add_argument("--think", type=float, nargs=2, default=[0.5, 6.0],
                    metavar=("MIN", "MAX"), help="pause between sessions, per worker")
    ap.add_argument("--start-delay", type=float, default=5.0,
                    help="wait before the first session, so the capture is already running")
    ap.add_argument("--stop-margin", type=float, default=30.0,
                    help="stop this many seconds BEFORE the capture ends, so no session "
                         "falls outside the pcap interval")
    ap.add_argument("--campaign-id", required=True)
    ap.add_argument("--run-id", type=int, required=True)
    ap.add_argument("--attempt-id", required=True,
                    help="must match capture_start.attempt_id; finalize_run compares them")
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--log-jsonl", required=True)
    ap.add_argument("--selftest", action="store_true",
                    help="run preflight only and exit (do this before every campaign)")
    args = ap.parse_args()

    if not str(args.attempt_id).strip():
        sys.exit("ABORT: --attempt-id must be non-empty (finalize_run binds the run to it)")

    global ACTIVE_PATHS
    ACTIVE_PATHS = list(args.paths)                  # session profiles read this

    problems = preflight(args.sites, args.profiles)
    if problems:
        for p in problems:
            print("PREFLIGHT: {}".format(p), file=sys.stderr)
        sys.exit("ABORT: preflight failed — fix the above before capturing")
    print("preflight ok: {} client(s), {} site(s), {} path(s)".format(
        len(args.profiles), len(args.sites), len(ACTIVE_PATHS)))
    if args.selftest:
        return 0

    weights = [PROFILES[p][1] for p in args.profiles]
    counter, lock = itertools.count(1), threading.Lock()
    out_q, done = queue.Queue(), threading.Event()
    stats, stats_lock = {"attempted": 0, "ok": 0, "failed": 0}, threading.Lock()
    meta = {"campaign_id": args.campaign_id, "run_id": args.run_id,
            "attempt_id": args.attempt_id, "seed": args.seed}

    wt = threading.Thread(target=writer, args=(out_q, args.log_jsonl, meta, done))
    wt.start()

    time.sleep(args.start_delay)
    stop_at = time.time() + args.minutes * 60 - args.stop_margin
    threads = [threading.Thread(target=worker, args=(
        stop_at, args.sites, ACTIVE_PATHS, args.profiles, weights, args.timeout,
        tuple(args.think), counter, lock, out_q, args.seed + i, stats, stats_lock))
        for i in range(args.workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    done.set()
    wt.join()

    rate = stats["ok"] / max(stats["attempted"], 1)
    print("sessions: {attempted} | ok: {ok} | failed: {failed}".format(**stats))
    print("by profile:", stats.get("by_profile"))
    print("success rate: {:.3f}".format(rate))
    # A run whose benign side mostly failed is not benign background traffic. Fail loudly
    # so the orchestrator aborts instead of sealing a hollow run.
    if rate < 0.5:
        print("ABORT: benign success rate below 0.5", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
