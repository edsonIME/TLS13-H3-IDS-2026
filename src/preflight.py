#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
preflight.py — verify the lab BEFORE a run so you never burn a capture on a misconfig
[audit v20.26]. Each check returns PASS / FAIL / SKIP with a detail; the run proceeds only
if EVERY required check PASSes. Output: preflight_run<N>.json.

Checks (a check SKIPs when its inputs aren't supplied, so the same script serves NB1..NB4):
  tools present (tcpdump/zeek/nmap/hydra/slowhttptest…)   disk free on the sensor
  campaign manifest loads (reuses campaign.load)          pinned wordlist hashes match local files
  DNS resolves blog.lab / shop.lab                        victims answer HTTPS (and optionally HTTP/3)
  clock is synchronized                                   capture interface exists
  NO default route to the internet (air-gap)              switch mirroring sees NB2->NB1 (delegated to a probe)

The individual check functions are pure/injectable and unit-tested; the aggregator decides the
verdict and the exit code (0 only on overall PASS).
"""

import argparse
import os
import socket
import sys

import runlib

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


def _chk(name, status, detail, required=True):
    return {"name": name, "status": status, "detail": detail, "required": required}


def check_tools(tools, required=True):
    """Each named tool must be on PATH; report versions of those present."""
    present = {t: runlib.tool_version(t) for t in tools}
    missing = [t for t in tools if runlib.which(t) is None]
    return _chk("tools", PASS if not missing else FAIL,
                {"present": present, "missing": missing}, required)


def check_disk(path, min_gb, required=True):
    """The sensor needs room for the PCAP."""
    if not path or not os.path.isdir(path):
        return _chk("disk_free", SKIP, {"path": path, "reason": "no path"}, required)
    free_gb = runlib.disk_free_bytes(path) / (1 << 30)
    return _chk("disk_free", PASS if free_gb >= min_gb else FAIL,
                {"path": path, "free_gb": round(free_gb, 2), "min_gb": min_gb}, required)


def check_manifest(path, required=True):
    """The campaign manifest must load under the reproducible rules (reuses the analytical layer)."""
    if not path:
        return _chk("manifest", SKIP, {"reason": "no --campaign"}, required)
    try:
        import campaign as camp
        m = camp.load(path, require_reproducible=True)
        return _chk("manifest", PASS, {"path": path, "campaign_id": m.get("campaign_id"),
                                       "runs": len(m.get("runs") or {})}, required)
    except SystemExit as exc:
        return _chk("manifest", FAIL, {"path": path, "error": str(exc)}, required)
    except Exception as exc:                               # import error etc.
        return _chk("manifest", FAIL, {"path": path, "error": repr(exc)[:200]}, required)


def check_wordlists(manifest_path, wordlist_dir, required=True):
    """Every BruteForce run that PINS user/passlist sha256 must have a LOCAL file whose hash matches —
    the same evidence run_attacks enforces, checked before the run so a mismatch isn't found mid-attack."""
    if not (manifest_path and wordlist_dir):
        return _chk("wordlist_hashes", SKIP, {"reason": "need --campaign and --wordlist-dir"}, required)
    try:
        man = runlib.read_json(manifest_path)
    except (OSError, ValueError) as exc:
        return _chk("wordlist_hashes", FAIL, {"error": repr(exc)[:200]}, required)
    have = {}
    for f in os.listdir(wordlist_dir):
        p = os.path.join(wordlist_dir, f)
        if os.path.isfile(p):
            have[runlib.sha256_file(p)] = f
    pinned, missing = [], []
    for rid, spec in (man.get("runs") or {}).items():
        for key in ("userlist_sha256", "passlist_sha256"):
            h = spec.get(key)
            if not h:
                continue
            pinned.append(h)
            if h not in have:
                missing.append({"run": rid, "field": key, "sha256": h})
    if not pinned:
        return _chk("wordlist_hashes", SKIP, {"reason": "no pinned wordlists (pilot?)"}, required=False)
    return _chk("wordlist_hashes", PASS if not missing else FAIL,
                {"pinned": len(pinned), "missing": missing}, required)


def check_dns(hosts, required=True):
    """Each host must resolve (via the lab's dnsmasq / whatever the caller points resolv.conf at)."""
    if not hosts:
        return _chk("dns", SKIP, {"reason": "no --resolve"}, required)
    res, bad = {}, []
    for h in hosts:
        try:
            res[h] = socket.gethostbyname(h)
        except OSError:
            res[h] = None; bad.append(h)
    return _chk("dns", PASS if not bad else FAIL, {"resolved": res, "unresolved": bad}, required)


def check_https(urls, required=True):
    """Each victim URL must answer (2xx/3xx). Uses the monitor's probe (accepts the lab CA)."""
    if not urls:
        return _chk("https", SKIP, {"reason": "no --https"}, required)
    import service_monitor
    res, bad = {}, []
    for u in urls:
        s = service_monitor.sample_url(u, timeout=5.0)
        res[u] = {"http_code": s["http_code"], "ok": s["ok"], "error": s["error"]}
        if not s["ok"]:
            bad.append(u)
    return _chk("https", PASS if not bad else FAIL, {"probed": res, "failing": bad}, required)


def check_interface(iface, required=True):
    """The capture interface must exist on this host (NB4)."""
    if not iface:
        return _chk("interface", SKIP, {"reason": "no --interface"}, required)
    exists = os.path.isdir("/sys/class/net/{}".format(iface))
    return _chk("interface", PASS if exists else FAIL, {"interface": iface, "exists": exists}, required)


def check_clock_sync(max_offset_ms=50.0, required=True, _chrony_text=None, _timedatectl_text=None,
                     _w32tm_text=None):
    """The host clock must be SYNCHRONIZED and within `max_offset_ms` of NTP. Labels are assigned by
    TIME window, so a de-synced clock silently corrupts the ground truth — this makes clock sync a GATE,
    not merely recorded evidence [audit v20.28 §9]. Reads chronyc/timedatectl on Linux AND `w32tm` on
    Windows, so the gate actually applies to NB2 too [audit v20.29 §7]. Texts are injectable for unit
    tests. SKIPs (non-fatal) only when NONE of the three tools exists."""
    import clock_evidence as ce
    chrony = _chrony_text if _chrony_text is not None else (
        runlib.run_cmd(["chronyc", "tracking"], timeout=10).stdout if runlib.which("chronyc") else None)
    tdc = _timedatectl_text if _timedatectl_text is not None else (
        runlib.run_cmd(["timedatectl"], timeout=10).stdout if runlib.which("timedatectl") else None)
    w32 = _w32tm_text if _w32tm_text is not None else (
        runlib.run_cmd(["w32tm", "/query", "/status"], timeout=10).stdout if runlib.which("w32tm") else None)
    if not chrony and not tdc and not w32:
        # FAIL-CLOSED: if the gate is ACTIVE (required) and there is NO way to prove the clock is synced,
        # that is a FAIL, not a free pass — only --no-clock-gate (required=False) may SKIP [audit v20.30 §9].
        if required:
            return _chk("clock_sync", FAIL,
                        {"reason": "no chronyc/timedatectl/w32tm — cannot prove clock sync (fail-closed)"}, True)
        return _chk("clock_sync", SKIP, {"reason": "no clock tool; gate disabled"}, required=False)
    synced, offset_ms, detail = None, None, {"max_offset_ms": max_offset_ms}
    if tdc:
        t = ce.parse_timedatectl(tdc); synced = t.get("synchronized"); detail["timedatectl"] = t
    if chrony:
        c = ce.parse_chronyc_tracking(chrony); detail["chronyc"] = c
        off = c.get("rms_offset_s")
        if off is None:
            off = c.get("system_time_offset_s")
        if off is not None:
            offset_ms = abs(off) * 1000.0
        if synced is None:                                  # infer sync from chrony's leap status
            synced = (c.get("leap_status") or "").lower().startswith("normal")
    if w32:                                                 # Windows NB2
        w = ce.parse_w32tm_status(w32); detail["w32tm"] = w
        if w.get("phase_offset_s") is not None and offset_ms is None:
            offset_ms = abs(w["phase_offset_s"]) * 1000.0
        elif offset_ms is None and w.get("dispersion_s") is not None:
            # Windows w32tm does NOT expose a phase offset like chrony does. It DOES expose root
            # dispersion — the MAXIMUM estimated clock error. Dispersion is an upper bound on the true
            # offset, so if dispersion <= max_offset the offset is within tolerance too. Use it as the
            # gate value so a genuinely-synced Windows host (real NTP source) passes on the evidence it
            # provides, instead of FAILing on a field it never reports. Gate stays ACTIVE. [§9]
            offset_ms = abs(w["dispersion_s"]) * 1000.0
            detail["offset_from"] = "w32tm_dispersion_ceiling"
        if synced is None:                                  # a real source (not "Local CMOS Clock") => synced
            src = (w.get("source") or "").lower()
            synced = bool(src) and "local cmos" not in src and "free-running" not in src
    detail["synchronized"] = synced
    detail["offset_ms"] = None if offset_ms is None else round(offset_ms, 3)
    ok = bool(synced) and offset_ms is not None and offset_ms <= max_offset_ms
    return _chk("clock_sync", PASS if ok else FAIL, detail, required)


def check_interpreter(required=True):
    """SOME Python must be present — but Windows ships `python`/`py`, not `python3`, so a NB2 preflight
    must accept ANY of them instead of hard-failing on a missing `python3` [audit v20.29 §7]."""
    found = {name: runlib.which(name) for name in ("python3", "python", "py")}
    ok = any(found.values())
    return _chk("interpreter", PASS if ok else FAIL,
                {"found": {k: v for k, v in found.items() if v}}, required)


# Default tool set to check PER HOST, so preflight verifies each notebook's OWN role, not just the
# sensor's — a missing Hydra on NB3 or tcpdump on NB4 is caught before the run [audit v20.28 §8].
_PROFILE_TOOLS = {"nb1": ["docker"], "nb2": [], "nb3": ["nmap", "hydra"],
                  "nb4": ["tcpdump", "zeek"]}


def check_zeek_env(site_script, zeek="zeek", required=True):
    """Run the Zeek environment probe (JA3 + QUIC analyzers loaded, the versioned local.zeek exists + its
    SHA) BEFORE the run, so a whole capture isn't burned only to discover at process time that JA3/QUIC are
    missing or the site script is wrong [audit v20.31 §15]. Delegates to process_pcap.check_environment."""
    if not site_script:
        return _chk("zeek_env", SKIP, {"reason": "no --zeek-site-script"}, required=False)
    try:
        import process_pcap
    except Exception as exc:                                # pragma: no cover
        return _chk("zeek_env", FAIL, {"error": repr(exc)[:200]}, required)
    env = process_pcap.check_environment(zeek, site_script)
    return _chk("zeek_env", PASS if env["ok"] else FAIL,
                {"zeek_version": env.get("zeek_version"), "site_script": env.get("site_script"),
                 "site_script_sha256": env.get("site_script_sha256"), "problems": env.get("problems")},
                required)


def check_air_gap(required=False):
    """No default route -> no path to the internet during capture (air-gap). Linux /proc/net/route."""
    try:
        with open("/proc/net/route") as fh:
            for line in fh.readlines()[1:]:
                cols = line.split()
                if len(cols) > 2 and cols[1] == "00000000":     # destination 0.0.0.0 == default gateway
                    return _chk("air_gap", FAIL, {"default_route_iface": cols[0]}, required)
        return _chk("air_gap", PASS, {"default_route": None}, required)
    except OSError:
        return _chk("air_gap", SKIP, {"reason": "no /proc/net/route"}, required)


def build_report(checks):
    """Aggregate the checks into a verdict. Overall PASS only if NO required check FAILed (SKIP is ok)."""
    failed = [c["name"] for c in checks if c["required"] and c["status"] == FAIL]
    overall = PASS if not failed else FAIL
    return {"overall": overall, "generated_utc": runlib.utc_now_iso(),
            "failed_required": failed, "checks": checks}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Pre-run lab verification ({}).".format(runlib.TOOL_VERSION))
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--out-dir", default=".", help="where preflight_run<N>.json is written")
    ap.add_argument("--campaign", help="campaign manifest to validate + read wordlist pins from")
    ap.add_argument("--wordlist-dir", help="directory holding the real wordlists (hash-checked vs manifest)")
    ap.add_argument("--tool", action="append", default=[], help="tool that must be present (repeatable)")
    ap.add_argument("--disk-path", help="path whose filesystem must have free space (the sensor's data dir)")
    ap.add_argument("--min-disk-gb", type=float, default=10.0)
    ap.add_argument("--resolve", action="append", default=[], help="hostname that must resolve (repeatable)")
    ap.add_argument("--https", action="append", default=[], help="victim URL that must answer (repeatable)")
    ap.add_argument("--interface", help="capture interface that must exist (NB4)")
    ap.add_argument("--require-air-gap", action="store_true", help="FAIL if a default route exists")
    ap.add_argument("--zeek-site-script", help="verify the Zeek env (JA3/QUIC + this local.zeek exists+sha) "
                                               "before the run [audit v20.31 §15]")
    ap.add_argument("--zeek", default="zeek", help="zeek binary for the env probe")
    ap.add_argument("--profile", help="host role (nb1|nb2|nb3|nb4): picks a default tool set to verify "
                                      "this notebook's OWN role when --tool is not given [§8]")
    ap.add_argument("--max-clock-offset-ms", type=float, default=50.0,
                    help="clock-sync gate: FAIL if unsynchronized or offset exceeds this [§9]")
    ap.add_argument("--no-clock-gate", action="store_true", help="record clock sync but do not gate on it")
    args = ap.parse_args(argv)
    runlib.print_banner("preflight.py")

    # A profile that is present but EMPTY (e.g. nb2 Windows) means "no extra CLI tools to require" — it
    # must NOT fall through to demanding `python3`; the interpreter check accepts python/py instead [§7].
    if args.tool:
        tools = args.tool
    elif args.profile in _PROFILE_TOOLS:
        tools = _PROFILE_TOOLS[args.profile]
    else:
        tools = ["python3"]
    checks = [
        check_interpreter(),
        check_tools(tools),
        check_clock_sync(args.max_clock_offset_ms, required=not args.no_clock_gate),
        check_disk(args.disk_path, args.min_disk_gb, required=bool(args.disk_path)),
        check_manifest(args.campaign, required=bool(args.campaign)),
        check_wordlists(args.campaign, args.wordlist_dir),
        check_dns(args.resolve, required=bool(args.resolve)),
        check_https(args.https, required=bool(args.https)),
        check_interface(args.interface, required=bool(args.interface)),
        check_zeek_env(args.zeek_site_script, args.zeek, required=bool(args.zeek_site_script)),
        check_air_gap(required=args.require_air_gap),
    ]
    report = build_report(checks)
    report["profile"] = args.profile
    out = os.path.join(args.out_dir, "preflight_run{}.json".format(args.run_id))
    runlib.write_json(out, report)
    for c in checks:
        print("  [{}] {}: {}".format(c["status"], c["name"],
                                     c["detail"] if c["status"] != PASS else ""))
    print("PREFLIGHT {} -> {}".format(report["overall"], out))
    return 0 if report["overall"] == PASS else 2


if __name__ == "__main__":
    sys.exit(main())
