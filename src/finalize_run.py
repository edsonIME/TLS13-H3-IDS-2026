#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
finalize_run.py — seal ONE completed run [audit v20.26]. Kept separate from the orchestrator so
a run can be finalized (or re-finalized) after a crash without re-capturing.

It inventories every file in the run directory (name/size/sha256), confirms the REQUIRED
artifacts are present, validates the labeler status against status/v5 (reusing the analytical
provenance layer), optionally checks the status' campaign identity against the manifest, writes a
completion verdict, and bundles the run into a single tar.gz. The inventory hashes make any later
change to a sealed run DETECTABLE (re-run --verify).

Artifacts: run<N>_manifest.json (inventory), run<N>_hashes.json, run<N>_completion_status.json,
run<N>_bundle.tar.gz. Everything here is pure Python and unit-tested end to end.
"""

import argparse
import hashlib
import json
import math
import os
import shutil
import sys
import tarfile

import runlib

# Files a finalized run is expected to carry. Absent ones are reported (not silently ignored). An OFFICIAL
# run must also carry capture_start (start time/interface/initial clock) and the ground-truth annotations
# [audit v20.31 §12/§5]; both are produced by the orchestrator.
DEFAULT_REQUIRED = ["run{n}.pcap", "run{n}_capture_start.json", "run{n}_capture_end.json",
                    "run{n}_zeek_processing.json", "run{n}_run_status.json", "run{n}_annotations.csv"]


def _nonneg_int(s):
    """argparse type: a non-negative integer (rejects -1 and junk) [audit v20.30 §11]."""
    v = int(s)
    if v < 0:
        raise argparse.ArgumentTypeError("must be an integer >= 0")
    return v


def _frac01(s):
    """argparse type: a FINITE fraction in [0,1] — rejects NaN/inf/negatives/>1 so a bogus threshold
    can't silently disable the gate (NaN comparisons are always false) [audit v20.30 §11]."""
    v = float(s)
    if not math.isfinite(v) or not (0.0 <= v <= 1.0):
        raise argparse.ArgumentTypeError("must be a finite number in [0,1]")
    return v


def _validate_capture_quality_policy(cqp):
    """A well-formed manifest capture_quality_policy [audit v20.35 §12]: min_packets (non-negative int),
    max_drop_rate (finite [0,1] or null = no ceiling), require_effect (bool). Returns (ok, reason)."""
    if not isinstance(cqp, dict):
        return False, "not an object"
    mp = cqp.get("min_packets")
    if isinstance(mp, bool) or not isinstance(mp, int) or mp < 0:
        return False, "min_packets must be a non-negative int"
    md = cqp.get("max_drop_rate")
    if md is not None and (isinstance(md, bool) or not isinstance(md, (int, float))
                           or not math.isfinite(md) or not (0.0 <= md <= 1.0)):
        return False, "max_drop_rate must be a finite number in [0,1] or null"
    if not isinstance(cqp.get("require_effect"), bool):
        return False, "require_effect must be a boolean"
    return True, "ok"


def _validate_benign_quality_policy(bqp):
    """A well-formed manifest benign_quality_policy [audit v20.40 §5/§6] — a CLOSED schema pre-registering
    the benign-traffic floor an OFFICIAL run must clear. `min_benign_flows` is REQUIRED and must be a
    POSITIVE int: a run with no benign background is not a HIKARI-style dataset, and a non-positive/negative
    floor (the reproduced min=-1 hole) can no longer act as a vacuous 'always-true' gate. The richer session/
    evidence gates (min_successful_sessions / min_success_rate / require_benign_jsonl / require_browser_
    evidence) are OPTIONAL here and must be well-typed; when set, they are ACTUALLY ENFORCED against the
    sealed run<N>_benign.jsonl by _check_benign_evidence (schema + temporal window + session uniqueness +
    attempt identity), not merely type-checked [audit v20.42]. UNKNOWN keys abort so a typo can never
    silently disable a gate. Returns (ok, reason)."""
    if not isinstance(bqp, dict):
        return False, "not an object (an official run must pre-register one)"
    mbf = bqp.get("min_benign_flows")
    if isinstance(mbf, bool) or not isinstance(mbf, int) or mbf < 1:
        return False, "min_benign_flows must be a positive int"
    mss = bqp.get("min_successful_sessions")
    if mss is not None and (isinstance(mss, bool) or not isinstance(mss, int) or mss < 1):
        return False, "min_successful_sessions must be a positive int"
    msr = bqp.get("min_success_rate")
    if msr is not None and (isinstance(msr, bool) or not isinstance(msr, (int, float))
                            or not math.isfinite(msr) or not (0.0 <= msr <= 1.0)):
        return False, "min_success_rate must be a finite number in [0,1]"
    for k in ("require_benign_jsonl", "require_browser_evidence"):
        if bqp.get(k) is not None and not isinstance(bqp.get(k), bool):
            return False, "{} must be a boolean".format(k)
    known = {"min_benign_flows", "min_successful_sessions", "min_success_rate",
             "require_benign_jsonl", "require_browser_evidence"}
    extra = sorted(set(bqp) - known)
    if extra:
        return False, "unknown benign_quality_policy keys: {}".format(extra)
    return True, "ok"


def _effective_capture_thresholds(cli_min, cli_max_drop, cli_require_effect, cqp):
    """Combine the CLI thresholds with the manifest capture_quality_policy so the CLI can only TIGHTEN,
    never relax [audit v20.35 §12]: min_packets -> the HIGHER floor, max_drop_rate -> the LOWER (stricter)
    ceiling, require_effect -> OR. So a later --rotate-seal with a weaker CLI value cannot lower the bar."""
    if not isinstance(cqp, dict):
        return cli_min, cli_max_drop, cli_require_effect
    eff_min = max(int(cli_min or 0), int(cqp.get("min_packets") or 0))
    drops = [v for v in (cli_max_drop, cqp.get("max_drop_rate")) if v is not None]
    eff_drop = min(drops) if drops else None
    eff_effect = bool(cli_require_effect) or bool(cqp.get("require_effect"))
    return eff_min, eff_drop, eff_effect


def _is_sealing_artifact(name):
    """finalize's OWN outputs — excluded from the inventory so it is stable across finalize/--verify
    (they are written AFTER the inventory is taken and would otherwise look like 'new' files).

    NOTE: run<N>_orchestration.json is NO LONGER excluded — the orchestrator now writes it BEFORE
    calling finalize, so it is real run evidence and MUST be sealed like everything else [audit v20.28
    §14]."""
    return (name.endswith(("_manifest.json", "_hashes.json", "_completion_status.json",
                           "_bundle.tar.gz")) or name.endswith(".tmp"))


def inventory(run_dir):
    """List every EVIDENCE file under `run_dir` (recursively) with size + sha256, excluding finalize's
    own sealing artifacts so the inventory is stable when re-run (--verify)."""
    items = []
    for root, _dirs, files in os.walk(run_dir):
        for f in sorted(files):
            if _is_sealing_artifact(f):
                continue
            p = os.path.join(root, f)
            rel = os.path.relpath(p, run_dir)
            items.append({"path": rel, "size_bytes": os.path.getsize(p), "sha256": runlib.sha256_file(p)})
    return sorted(items, key=lambda d: d["path"])


def check_required(run_dir, run_id, required):
    """Which required artifacts are present/absent (names may use '{n}' for the run id)."""
    present, missing = [], []
    for pat in required:
        name = pat.replace("{n}", str(run_id))
        (present if os.path.exists(os.path.join(run_dir, name)) else missing).append(name)
    return present, missing


def validate_status(run_dir, run_id, campaign_path=None):
    """Validate run<N>_run_status.json against status/v5 and (if a manifest is given) confirm its
    campaign identity. Returns (status_str, detail). Reuses the analytical provenance layer."""
    sp = os.path.join(run_dir, "run{}_run_status.json".format(run_id))
    if not os.path.exists(sp):
        return "SKIP", {"reason": "no status file"}
    try:
        import provenance as prov
        js = runlib.read_json(sp)
        prov.enforce_status_schema(sp, js)
        prov.validate_status_v5(sp, js, require_campaign_fields=bool(campaign_path))
        detail = {"diagnostic": js.get("diagnostic"), "run_id": js.get("run_id"),
                  "code_version": js.get("code_version")}
        if campaign_path:
            man = runlib.read_json(campaign_path)
            if str(js.get("campaign_id")) != str(man.get("campaign_id")):
                return "FAIL", {"error": "status campaign_id {!r} != manifest {!r}".format(
                    js.get("campaign_id"), man.get("campaign_id"))}
            detail["campaign_id"] = js.get("campaign_id")
        return "PASS", detail
    except SystemExit as exc:
        return "FAIL", {"error": str(exc)}
    except Exception as exc:
        return "FAIL", {"error": repr(exc)[:200]}


def verify(run_dir, manifest_path):
    """Re-verify a sealed run: recompute hashes and compare to the recorded run<N>_manifest.json.
    Returns (ok, changed_list)."""
    recorded = runlib.read_json(manifest_path)["inventory"]
    now = {d["path"]: d["sha256"] for d in inventory(run_dir)}
    changed = []
    for d in recorded:
        if now.get(d["path"]) != d["sha256"]:
            changed.append(d["path"])
    for path in now:
        if path not in {d["path"] for d in recorded}:
            changed.append("+" + path)                     # a NEW file appeared after sealing
    return (not changed), changed


def _pcap_info(path):
    """Parse a classic .pcap in PURE PYTHON and return (info, error). Validates the 24-byte global header
    (magic + plausible version 2.x + snaplen) and WALKS every packet record (16-byte header: ts_sec,
    ts_usec, incl_len, orig_len + payload), so a file whose bytes merely START with the pcap magic but is
    not a real capture is rejected, and the REAL packet count is RECOMPUTED rather than trusted from the
    tcpdump JSON [audit v20.33 §11]. Returns ({magic, version, snaplen, linktype, packets, first_ts,
    last_ts}, None) or (None, reason)."""
    import struct
    try:
        with open(path, "rb") as fh:
            gh = fh.read(24)
            if len(gh) < 24:
                return None, "shorter than a 24-byte pcap global header"
            magic = gh[:4]
            if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                endian = "<"                                 # little-endian (usec / nsec)
            elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                endian = ">"                                 # big-endian
            else:
                return None, "not a pcap (bad magic {})".format(magic.hex())
            ver_major, ver_minor, _tz, _sig, snaplen, linktype = struct.unpack(endian + "HHiIII", gh[4:24])
            if ver_major != 2:                               # every classic pcap is v2.4 — 30840 etc is junk
                return None, "implausible pcap version {}.{}".format(ver_major, ver_minor)
            if not (0 < snaplen <= 262144):
                return None, "implausible snaplen {}".format(snaplen)
            packets, first_ts, last_ts = 0, None, None
            while True:
                rh = fh.read(16)
                if not rh:
                    break                                    # clean EOF
                if len(rh) < 16:
                    return None, "truncated record header at packet {}".format(packets + 1)
                ts_sec, ts_usec, incl_len, _orig = struct.unpack(endian + "IIII", rh)
                if incl_len > snaplen:
                    return None, "record {} incl_len {} > snaplen {}".format(packets + 1, incl_len, snaplen)
                if len(fh.read(incl_len)) < incl_len:
                    return None, "truncated packet data at packet {}".format(packets + 1)
                ts = ts_sec + ts_usec / 1e6
                first_ts = ts if first_ts is None else first_ts
                last_ts = ts
                packets += 1
            return {"magic": magic.hex(), "version": "{}.{}".format(ver_major, ver_minor),
                    "snaplen": snaplen, "linktype": linktype, "packets": packets,
                    "first_ts": first_ts, "last_ts": last_ts}, None
    except OSError as exc:                                    # pragma: no cover
        return None, repr(exc)[:80]


def check_capture_semantics(run_dir, run_id, min_packets=0, max_drop_rate=None, strict=True):
    """Open run<N>_capture_end.json and confirm the capture is not merely PRESENT but VALID: tcpdump
    SUCCEEDED, captured enough packets, and its drop rate is under the ceiling. CRUCIALLY, the declared
    PCAP size/sha256 are RE-COMPUTED from the real run<N>.pcap and must MATCH — the JSON is a claim to be
    verified, not the source of truth, so a fabricated capture_end.json can't fake a good capture [audit
    v20.30 §6]. In `strict` (official) mode the tcpdump stats (packets/drops) and the declared pcap
    identity must be PRESENT — a capture_end.json that simply omits them can no longer seal official
    [audit v20.32 §8]. min_packets/max_drop_rate are validated as finite/in-range by the CLI [§11]."""
    p = os.path.join(run_dir, "run{}_capture_end.json".format(run_id))
    if not os.path.exists(p):
        return "SKIP", {"reason": "no capture_end.json"}
    try:
        js = runlib.read_json(p)
    except (OSError, ValueError) as exc:
        return "FAIL", {"error": repr(exc)[:200]}
    stats = js.get("tcpdump_stats") or {}
    rc, packets, drop = js.get("tcpdump_returncode"), stats.get("packets_captured"), stats.get("drop_rate")
    declared = js.get("pcap") or {}
    problems = []
    if rc not in (0,):
        problems.append("tcpdump_returncode={}".format(rc))
    # OFFICIAL: the capture must PROVE itself — the stats block and the declared pcap identity must be
    # PRESENT, not "checked only if provided". A capture without stats/pcap-hash can't seal official [§8].
    if strict:
        if js.get("tcpdump_stats") is None:
            problems.append("tcpdump_stats missing (official capture must record packets/drops)")
        else:
            if packets is None:
                problems.append("tcpdump_stats.packets_captured missing")
            if drop is None:
                problems.append("tcpdump_stats.drop_rate missing")
            # §9: the OBSERVED stats must be in-DOMAIN, not merely present — a NEGATIVE drop_rate slips past
            # the ceiling (-1 > 0.02 is False) and negative packet counts are impossible [audit v20.36 §9].
            for k in ("packets_captured", "packets_received", "packets_dropped"):
                val = stats.get(k)
                if val is not None and (isinstance(val, bool) or not isinstance(val, int) or val < 0):
                    problems.append("tcpdump_stats.{} must be a non-negative integer (got {!r})".format(k, val))
            if drop is not None and (isinstance(drop, bool) or not isinstance(drop, (int, float))
                                     or not math.isfinite(drop) or not (0.0 <= drop <= 1.0)):
                problems.append("tcpdump_stats.drop_rate must be finite in [0,1] (got {!r})".format(drop))
            # §9: the stats must also be internally CONSISTENT [audit v20.37/v20.38 §9]: you cannot capture
            # more than were received; received==0 forces captured==0 and dropped==0; and the DECLARED
            # drop_rate must equal the RECOMPUTED packets_dropped/packets_received to serialization precision
            # (1e-6, not 1%). The GATE below is applied to the RECOMPUTED rate, so a capture can no longer
            # slip a 3% drop past a 2% ceiling by declaring 0.02.
            recv, drop_ct = stats.get("packets_received"), stats.get("packets_dropped")
            _intok = lambda v: isinstance(v, int) and not isinstance(v, bool)
            if _intok(packets) and _intok(recv) and packets > recv:
                problems.append("packets_captured {} > packets_received {} (impossible)".format(packets, recv))
            if _intok(recv) and recv == 0 and ((_intok(packets) and packets != 0) or (_intok(drop_ct) and drop_ct != 0)):
                problems.append("packets_received==0 but captured/dropped != 0")
            if _intok(recv) and _intok(drop_ct) and isinstance(drop, (int, float)) and not isinstance(drop, bool) \
                    and math.isfinite(drop):
                recomputed_drop = (drop_ct / recv) if recv > 0 else 0.0
                if abs(float(drop) - recomputed_drop) > 1e-6:
                    problems.append("drop_rate {} != packets_dropped/received {:.6f}".format(drop, recomputed_drop))
        if declared.get("size_bytes") is None:
            problems.append("pcap.size_bytes not declared")
        if not declared.get("sha256"):
            problems.append("pcap.sha256 not declared")

    # RE-COMPUTE from the real PCAP and confront the declaration.
    pcap = os.path.join(run_dir, "run{}.pcap".format(run_id))
    real = {"exists": os.path.exists(pcap)}
    if real["exists"]:
        real["size_bytes"] = os.path.getsize(pcap)
        real["sha256"] = runlib.sha256_file(pcap)
    if not real["exists"]:
        problems.append("run{}.pcap not on disk".format(run_id))
    else:
        if declared.get("size_bytes") is not None and declared["size_bytes"] != real["size_bytes"]:
            problems.append("declared pcap size {} != real {}".format(declared["size_bytes"], real["size_bytes"]))
        if declared.get("sha256") and declared["sha256"] != real["sha256"]:
            problems.append("declared pcap sha256 != real")
        if real["size_bytes"] == 0:
            problems.append("real pcap is empty")

    # §11: in OFFICIAL mode, PARSE the PCAP (pure Python) — a file whose bytes merely start with the magic
    # but is not a real capture is rejected, and the REAL packet count (recomputed here) must EQUAL the
    # tcpdump packets_captured, so a fabricated "5000 packets" over a tiny file no longer passes [v20.33 §11].
    real_pkts = None
    if strict and real["exists"]:
        info, perr = _pcap_info(pcap)
        if perr:
            problems.append("pcap not a valid capture: {}".format(perr))
        else:
            real_pkts = info["packets"]
            if packets is not None and int(packets) != real_pkts:
                problems.append("declared packets_captured {} != real pcap packets {}".format(packets, real_pkts))

    if min_packets and (packets is None or packets < min_packets):
        problems.append("packets {} < min {}".format(packets, min_packets))
    # §9: apply the ceiling to the RECOMPUTED drop rate (dropped/received) when the counts are present, so a
    # capture cannot slip a real 3% drop past a 2% ceiling by declaring 0.02 [audit v20.38 §9]. Fall back to
    # the declared value only when the counts are unavailable.
    _rv, _dc = stats.get("packets_received"), stats.get("packets_dropped")
    gate_drop = (_dc / _rv) if (isinstance(_rv, int) and not isinstance(_rv, bool) and _rv > 0
                                and isinstance(_dc, int) and not isinstance(_dc, bool)) else drop
    if max_drop_rate is not None and gate_drop is not None and gate_drop > max_drop_rate:
        problems.append("drop_rate {} (real) > max {}".format(gate_drop, max_drop_rate))
    detail = {"returncode": rc, "packets": packets, "drop_rate": drop, "real_pcap_packets": real_pkts,
              "declared_size": declared.get("size_bytes"), "real_size": real.get("size_bytes")}
    if problems:
        detail["problems"] = problems
        return "FAIL", detail
    return "PASS", detail


def _zeek_log_nonempty(path):
    """True if a Zeek TSV log EXISTS on disk and has at least one DATA row (non-comment). Reads the real
    file — the finalizer must not trust a JSON that merely CLAIMS the log is fine [audit v20.30 §6]."""
    if not os.path.exists(path):
        return False
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip() and not line.startswith("#"):
                return True
    return False


def _zeek_log_records(path):
    """Count DATA rows (non-comment, non-blank) in a Zeek TSV log on disk, or None if the file is absent.
    Lets the finalizer RE-COUNT the logs and confront the count the processing JSON claims [audit v20.32 §9]."""
    if not os.path.exists(path):
        return None
    n = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip() and not line.startswith("#"):
                n += 1
    return n


def check_zeek_semantics(run_dir, run_id, strict=True):
    """Confirm the REQUIRED Zeek logs exist and are NON-EMPTY and Zeek exited 0. The log presence/rows
    are read from the ACTUAL files under zeek_logs/ (not taken from the processing JSON's self-report),
    so a fabricated zeek_processing.json can't fake logs that were never produced [audit v20.30 §6]. In
    `strict` (official) mode Zeek's return code must be EXACTLY 0 (an ABSENT/None code no longer passes)
    and each declared logs[*].records must EQUAL the count RE-COMPUTED from the real log [audit v20.32 §9].
    If the JSON is absent AND there are no logs, it SKIPs (a capture-only smoke)."""
    p = os.path.join(run_dir, "run{}_zeek_processing.json".format(run_id))
    log_dir = os.path.join(run_dir, "zeek_logs")
    real = {n: _zeek_log_nonempty(os.path.join(log_dir, n)) for n in ("conn.log", "ssl.log", "quic.log")}
    if not os.path.exists(p) and not any(real.values()):
        return "SKIP", {"reason": "no zeek_processing.json and no zeek logs"}
    problems = []
    if os.path.exists(p):
        try:
            js = runlib.read_json(p)
        except (OSError, ValueError) as exc:
            return "FAIL", {"error": repr(exc)[:200]}
        zrc = js.get("zeek_returncode")
        if strict:
            if zrc != 0:                                        # official: an absent/None code is NOT ok [§9]
                problems.append("zeek_returncode={} (official requires exactly 0)".format(zrc))
        elif zrc not in (0, None):
            problems.append("zeek_returncode={}".format(zrc))
        # If a versioned site script was recorded, its sha256 must still match — verified against EITHER the
        # external path OR the internal run<N>_local.zeek copy, so a run moved away from the lab tree still
        # verifies [audit v20.34 §9]. Only a genuine mismatch (or both copies gone) FAILs.
        ss, ss_sha = js.get("site_script"), js.get("site_script_sha256")
        if ss_sha:
            internal = os.path.join(run_dir, "run{}_local.zeek".format(run_id))
            candidates = [p for p in (ss, internal) if p and os.path.exists(p)]
            if not candidates:
                problems.append("site_script missing on disk (and no internal run{}_local.zeek)".format(run_id))
            elif not any(runlib.sha256_file(p) == ss_sha for p in candidates):
                problems.append("site_script sha256 changed")
        # RE-COUNT the real logs and confront the declared record counts [§9]: a processing JSON that
        # claims more records than the log actually holds is a fabricated self-report.
        if strict:
            zlogs = js.get("logs") or {}
            for ln in ("conn.log", "ssl.log", "quic.log"):
                declared_rec = (zlogs.get(ln) or {}).get("records")
                real_rec = _zeek_log_records(os.path.join(log_dir, ln))
                if declared_rec is None:
                    problems.append("zeek_processing.logs.{}.records missing".format(ln))
                elif real_rec != declared_rec:
                    problems.append("zeek_processing.logs.{}.records={} != real {}".format(
                        ln, declared_rec, real_rec))
    # §12: PARSE each required log with the SAME strict reader the labeler uses — a row whose column count
    # does not match the #fields header (a truncated/corrupt log the labeler would abort on) is caught HERE,
    # at sealing, not discovered later mid-label [audit v20.33 §12]. §6: it is not enough that the TSV is
    # well-formed — the logs must carry the fields the labeler NEEDS: conn.log its join/label essentials
    # (uid/orig_h/resp_h/proto/resp_p, via validate_conn_essentials) and ssl/quic at least a `uid` to join
    # on [audit v20.34 §6]. A conn.log of only ts/uid/id.orig_h — which the labeler itself aborts on —
    # can no longer seal official.
    if strict:
        # §6/§10: conn.log must carry the join/label essentials (validate_conn_essentials); ssl.log and
        # quic.log must carry the fields feature_schema consumes (TLS version/SNI/JA3/JA3S/ALPN, QUIC
        # version/SNI), so a status can't advertise TLS features the sealed logs never contained. §7-uid:
        # every ssl/quic uid must be a REAL conn.log uid (the join can't reference a flow that isn't there).
        _SSL_REQ = {"uid", "version", "server_name", "ja3", "ja3s", "next_protocol"}
        _QUIC_REQ = {"uid", "version", "server_name"}
        try:
            import label_flows as lf
            conn_path = os.path.join(log_dir, "conn.log")
            conn_rows = lf.read_zeek_log(conn_path) if os.path.exists(conn_path) else []
            lf.validate_conn_essentials(conn_rows)              # SystemExit if a row lacks uid/endpoints/proto/port
            conn_uids = {str(r.get("uid")) for r in conn_rows if r.get("uid")}
            for ln, req in (("ssl.log", _SSL_REQ), ("quic.log", _QUIC_REQ)):
                lp = os.path.join(log_dir, ln)
                if not os.path.exists(lp):
                    continue
                rows = lf.read_zeek_log(lp)                      # SystemExit on a malformed/truncated row
                with open(lp, encoding="utf-8", errors="replace") as fh:
                    header = next((l for l in fh if l.startswith("#fields")), "")
                fields = set(header.split()[1:])                # column names after the '#fields' token
                missing = req - fields
                if missing:
                    problems.append("{} missing field(s) {} the labeler/feature_schema need".format(ln, sorted(missing)))
                foreign = [str(r.get("uid")) for r in rows if r.get("uid") and str(r.get("uid")) not in conn_uids]
                if foreign:
                    problems.append("{} uid(s) {} not present in conn.log".format(ln, foreign[:2]))
        except SystemExit as exc:
            problems.append("zeek log not usable by the labeler: {}".format(str(exc)[:160]))
    bad = [n for n, ok in real.items() if not ok]           # verified against the REAL logs
    if bad:
        problems.append("missing/empty logs on disk: {}".format(bad))
    if problems:
        return "FAIL", {"problems": problems, "real_logs_nonempty": real}
    return "PASS", {"logs": ["conn.log", "ssl.log", "quic.log"]}


def _iso_to_epoch(s):
    """ISO-8601 UTC -> epoch seconds via the labeler's strict parser, or None if unparseable/empty."""
    if not s:
        return None
    try:
        import label_flows as lf
        return lf.to_epoch(str(s).strip())
    except Exception:
        return None


def _isfloat(x):
    try:
        float(x); return True
    except (TypeError, ValueError):
        return False


def _ts_failclosed_rows(raw_list, has_ts_field, lo, hi, where):
    """FAIL-CLOSED timestamp check for a Zeek log's records [audit v20.36 §5]: the log MUST declare a `ts`
    field, and EVERY record's ts must be present, numeric, finite and inside [lo, hi]. Returns a problem
    string on the FIRST violation (a missing/'BAD' ts is a FAIL, never silently skipped), or None."""
    if not has_ts_field:
        return "{} has no 'ts' field".format(where)
    for i, raw in enumerate(raw_list, start=1):
        if raw is None or not _isfloat(raw) or not math.isfinite(float(raw)):
            return "{} row {} ts {!r} is missing/non-numeric/non-finite".format(where, i, raw)
        if not (lo <= float(raw) <= hi):
            return "{} row {} ts {} outside pcap interval [{}, {}]".format(where, i, float(raw), lo, hi)
    return None


def _csv_ts_failclosed(path, col, lo, hi, where):
    """FAIL-CLOSED timestamp check for a CSV column [audit v20.36 §5]: the column MUST exist and EVERY value
    must be present, numeric, finite and inside [lo, hi]. Returns a problem string, or None."""
    import csv as _csv
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = _csv.DictReader(fh)
            if not reader.fieldnames or col not in reader.fieldnames:
                return "{} has no '{}' column".format(where, col)
            for i, r in enumerate(reader, start=1):
                raw = r.get(col)
                if raw is None or not _isfloat(raw) or not math.isfinite(float(raw)):
                    return "{} row {} {} {!r} is missing/non-numeric/non-finite".format(where, i, col, raw)
                if not (lo <= float(raw) <= hi):
                    return "{} row {} {} {} outside pcap interval [{}, {}]".format(where, i, col, float(raw), lo, hi)
    except (OSError, UnicodeDecodeError, _csv.Error) as exc:
        return "{}: {}".format(where, repr(exc)[:60])
    return None


def check_temporal_coherence(run_dir, run_id, strict=True):
    """Prove the artifacts describe the SAME capture in TIME, not just by hash [audit v20.34 §7 / v20.35
    §5-§11]. The hashes prove WHICH files were used; this proves they belong to the same interval. The
    PCAP's real first/last packet timestamps must fall within the declared window (capture_start.started_utc
    .. capture_end.ended_utc, both REQUIRED and ended>started in official mode); the declared duration_s
    must match the observed window; EVERY timestamped artifact — conn/ssl/quic.log records, the
    split-ready and audit CSV timestamps — must fall within the PCAP interval; and every annotation window
    must be CONTAINED in it (not merely intersect). A PCAP from 2033 stitched onto 2020 logs/CSVs/annotations
    is rejected even when every hash lines up. Non-strict (diagnostic) SKIPs when a piece is absent."""
    P = lambda name: os.path.join(run_dir, name)
    pcap = P("run{}.pcap".format(run_id))
    if not os.path.exists(pcap):
        return ("FAIL", {"error": "no pcap"}) if strict else ("SKIP", {"reason": "no pcap"})
    info, err = _pcap_info(pcap)
    if err or info is None or info.get("first_ts") is None:
        return ("FAIL", {"error": "pcap unparseable: {}".format(err)}) if strict else ("SKIP", {"reason": err})
    first, last, tol, problems = info["first_ts"], info["last_ts"], 5.0, []
    lo, hi = first - tol, last + tol
    cap_start = _read_json_safe(P("run{}_capture_start.json".format(run_id))) or {}
    cap_end = _read_json_safe(P("run{}_capture_end.json".format(run_id))) or {}
    started, ended = _iso_to_epoch(cap_start.get("started_utc")), _iso_to_epoch(cap_end.get("ended_utc"))

    # §8: an official run REQUIRES a parseable capture window, with ended strictly AFTER started.
    if strict and started is None:
        problems.append("capture_start.started_utc missing/unparseable")
    if strict and ended is None:
        problems.append("capture_end.ended_utc missing/unparseable (required in official mode)")
    if started is not None and ended is not None and started >= ended:
        problems.append("capture window empty/reversed (started {} >= ended {})".format(started, ended))
    if started is not None and first + tol < started:
        problems.append("pcap first packet {} precedes capture_start {}".format(first, started))
    if ended is not None and last - tol > ended:
        problems.append("pcap last packet {} follows capture_end {}".format(last, ended))
    # §9/§10: the DECLARED duration_s must match the OBSERVED window with a TIGHT tolerance (the old
    # max(30, 50%) allowed ~18 min of slop on a 36-min capture) [audit v20.36 §10].
    dur = cap_start.get("duration_s")
    if strict and started is not None and ended is not None and isinstance(dur, (int, float)) \
            and not isinstance(dur, bool) and math.isfinite(dur):
        observed = ended - started
        if abs(observed - float(dur)) > max(5.0, 0.01 * abs(float(dur))):
            problems.append("declared duration_s {} != observed window {:.1f}s".format(dur, observed))

    # §5 FAIL-CLOSED: EVERY timestamped artifact must PRESENT a numeric, finite, in-range ts on EVERY row —
    # no more silently skipping unparseable values (which read 'no valid ts' as 'nothing out of range' and
    # let ts=BAD / a missing ts column seal official) [audit v20.36 §5]. Only in official (strict) mode.
    if strict:
        import label_flows as lf
        for logname in ("conn.log", "ssl.log", "quic.log"):
            lp = P(os.path.join("zeek_logs", logname))
            if not os.path.exists(lp):
                continue
            try:
                rows = lf.read_zeek_log(lp)
            except SystemExit:
                continue                                         # malformed -> check_zeek_semantics FAILs it
            with open(lp, encoding="utf-8", errors="replace") as fh:
                fields = set(next((l for l in fh if l.startswith("#fields")), "").split()[1:])
            why = _ts_failclosed_rows([r.get("ts") for r in rows], "ts" in fields, lo, hi, logname)
            if why:
                problems.append(why)
        files = (_read_json_safe(P("run{}_run_status.json".format(run_id))) or {}).get("files") or {}
        for key, col in (("split_ready", "timestamp"), ("audit", "ts")):
            decl = files.get(key)
            p = P(os.path.basename(decl)) if decl else None
            if p and os.path.exists(p):
                why = _csv_ts_failclosed(p, col, lo, hi, key)
                if why:
                    problems.append(why)

    # §11: every annotation window must be CONTAINED in the pcap interval — a mostly-outside attack window
    # that only clips the capture is not "the whole attack was captured".
    ann = P("run{}_annotations.csv".format(run_id))
    if os.path.exists(ann):
        try:
            import label_flows as lf
            windows, _rid = lf.load_annotations(ann)
            for w in windows:
                if w["start"] < lo or w["end"] > hi:
                    problems.append("annotation {} window [{}, {}] not contained in pcap [{}, {}]".format(
                        w.get("event_id"), w["start"], w["end"], first, last))
                    break
        except SystemExit:
            pass
    detail = {"pcap_first_ts": first, "pcap_last_ts": last, "capture_start": started, "capture_end": ended}
    if problems:
        detail["problems"] = problems
        return "FAIL", detail
    return "PASS", detail


def _read_json_safe(path):
    try:
        return runlib.read_json(path)
    except (OSError, ValueError):
        return None


def _sha(path):
    return runlib.sha256_file(path) if os.path.exists(path) else None


# The core columns EVERY annotations file carries, even one with zero attack rows (a benign run). A
# single-line 'THIS IS NOT ANNOTATIONS' has none of these, so it is rejected before load_annotations
# (which, seeing one header line and no data rows, would otherwise return cleanly) [audit v20.32 §5].
_ANNOTATION_COLS = {"event_id", "run_id", "label", "attacker_ip", "target_ip", "protocol",
                    "target_port", "start_utc", "end_utc", "tool", "command", "status", "return_code"}


def _reconcile_counts(path, df, kind, status):
    """The sealed status must DESCRIBE THIS FILE's rows [audit v20.32 §6.8]: the ML/audit row counts and
    the split-ready per-class counts recomputed HERE must EQUAL what the status claims. A status that says
    100 flows over a 1-row CSV can no longer seal official. Returns (ok, reason). A claim that is absent
    (a diagnostic status may omit it) is skipped — official status/v5 always carries these fields."""
    n = len(df)
    if kind == "ml":
        claim = status.get("flows_written_ml")
        if claim is not None and int(claim) != n:
            return False, "ml rows {} != status.flows_written_ml {}".format(n, claim)
    elif kind == "audit":
        claim = status.get("flows_audit")
        if claim is not None and int(claim) != n:
            return False, "audit rows {} != status.flows_audit {}".format(n, claim)
    elif kind == "split_ready":
        claim = status.get("class_counts_split_ready")
        if isinstance(claim, dict):
            import provenance as prov
            actual = prov.csv_class_counts(path)                 # per-class recomputed from the CSV
            norm = {str(k): int(v) for k, v in claim.items()}
            if norm != actual:
                return False, "split_ready class counts {} != status {}".format(actual, norm)
    return True, "ok"


def _validate_dataset_csv(path, run_id, kind, status):
    """Prove a declared labeler CSV is REALLY the dataset THIS run produced — not arbitrary bytes that
    merely hash to the declared value — by REUSING the analytical validators instead of a shallow header
    scan [audit v20.32 §6]. This is the crux of the audit: "a file with the expected hash and some columns"
    is NOT "the dataset the experiment produced". Returns (ok, reason).

    For the machine-consumable ML/split-ready files (exact COMMON schema) it enforces, via feature_schema:
      * read_common_csv            -> schema-aware read (tls_version '1.3' stays a string, not float 1.3)
      * >= 1 data row              -> an EMPTY ML file is not a dataset [§6.1]
      * check_official_columns     -> the required COMMON columns are PRESENT and carry no non-numeric junk
                                      like 'BAD'/'NOTNUM' (to_numeric-coerce would hide it) [§6.4/§6.6]
      * EXACT schema               -> NO extra columns; an ML file with a leaked id.orig_h is NOT the ML
                                      dataset [§6.7]
      * common_contract_violations -> impossible/inconsistent values (inf, negative like -999, fractional
                                      counts, a rate finite over duration<=0) are rejected [§6.6]
      * require_valid_labels       -> a blank or 'EVIL' label aborts [§6.5]
      * provenance.csv_run_ids     -> run_id present, integer, and EQUAL to this run (rejects an EMPTY
                                      run_id that the old scan accepted) [§6.3]
      * timestamp numeric + finite -> a 'BAD' timestamp is not a real capture time [§6.4]
      * _reconcile_counts          -> the real row/class counts equal the sealed status [§6.8]

    The AUDIT file is intentionally a SUPERSET (uid + raw Zeek fields + audit columns, NOT the COMMON
    names), so it is validated more loosely: it must carry a `label` column with only valid labels, be
    non-empty, and reconcile its row count with the status — but a file with ONLY a label column (the
    audit's §6.2) fails the minimal-schema check below."""
    import feature_schema as fs
    label_col = fs.LABEL

    # ---- AUDIT: raw-Zeek superset. Do NOT impose the COMMON schema, but it must be a REAL audit trail —
    # not four arbitrary columns [audit v20.33 §9]. Require the evidence columns the labeler actually
    # writes (uid + ts + endpoints + proto + label + matched_event_id + ambiguous), a boolean `ambiguous`,
    # valid labels, >=1 row, and the row count reconciled with the status. --------------------------------
    if kind == "audit":
        import csv as _csv
        # A meaningful subset of the labeler's real audit header (uid + CONN_FIELDS + AUDIT_EXTRA). Only a
        # label column [§6.2] or four arbitrary columns [audit v20.33 §9] fail this.
        need_cols = ("uid", "ts", "id.orig_h", "id.resp_h", "id.resp_p", "proto",
                     "label", "matched_event_id", "ambiguous")
        bool_domain = {"t", "f", "true", "false", "0", "1", ""}
        try:
            with open(path, newline="", encoding="utf-8") as fh:
                reader = _csv.DictReader(fh)
                cols = reader.fieldnames or []
                missing = [c for c in need_cols if c not in cols]
                if missing:
                    return False, "audit file missing evidence column(s) {}".format(missing)
                labels, rows = [], 0
                for r in reader:
                    rows += 1
                    labels.append((r.get(label_col) or "").strip())
                    amb = (r.get("ambiguous") or "").strip().lower()
                    if amb not in bool_domain:
                        return False, "audit ambiguous={!r} is not boolean".format(r.get("ambiguous"))
                if rows == 0:
                    return False, "no data rows"
        except (OSError, UnicodeDecodeError, _csv.Error) as exc:
            return False, repr(exc)[:120]
        try:
            fs.require_valid_labels(labels, where="audit of run {}".format(run_id))
        except SystemExit as exc:
            return False, str(exc)
        claim = status.get("flows_audit")
        if claim is not None and int(claim) != rows:
            return False, "audit rows {} != status.flows_audit {}".format(rows, claim)
        return True, "ok"

    # ---- ML / SPLIT-READY: exact COMMON schema, validated by the analytical layer. --------------------
    try:
        df = fs.read_common_csv(path)
    except Exception as exc:                                     # EmptyDataError, ParserError, OSError…
        return False, "unreadable CSV: {}".format(repr(exc)[:120])
    if len(df) < 1:
        return False, "no data rows"                             # empty ML file [§6.1]

    require_time = (kind == "split_ready")
    errs = fs.check_official_columns(df, require_time=require_time)   # missing cols + non-numeric junk
    if errs:
        return False, "; ".join(errs)

    # EXTENDED = COMMON + flowmeter features: the schema the split-ready CSV carries by design
    # (feature_schema L56-66). COMMON alone would reject the flowmeter columns as "extra".
    allowed = ({"run_id", "timestamp"} if require_time else set()) | set(fs.EXTENDED) | {label_col}
    extra = [c for c in df.columns if c not in allowed]
    if extra:                                                    # a leaked id.orig_h is NOT the dataset [§6.7]
        return False, "unexpected column(s) {} — schema is not exactly the {} dataset".format(
            sorted(extra), kind)

    verrs, _w = fs.common_contract_violations(df)                # inf/negative/fractional/inconsistent
    if verrs:
        return False, "; ".join(verrs)
    try:
        fs.require_valid_labels(df[label_col], where="{} of run {}".format(kind, run_id))
    except SystemExit as exc:                                    # blank or 'EVIL' label [§6.5]
        return False, str(exc)

    if "run_id" in df.columns:                                   # split-ready: run_id present, int, == run
        try:
            import provenance as prov
            ids = prov.csv_run_ids(path)                         # SystemExit on empty/non-int/negative [§6.3]
        except SystemExit as exc:
            return False, str(exc)
        if ids != [int(run_id)]:
            return False, "run_id values {} != [{}]".format(ids, run_id)
    if "timestamp" in df.columns:                               # a 'BAD' timestamp is not a capture time [§6.4]
        import numpy as np
        import pandas as pd
        ts = pd.to_numeric(df["timestamp"], errors="coerce").to_numpy(dtype=float)
        if ts.size == 0 or np.isnan(ts).any() or not np.isfinite(ts).all():
            return False, "timestamp column has non-numeric/non-finite values"

    return _reconcile_counts(path, df, kind, status)             # real counts vs the sealed status [§6.8]


def _validate_annotations(path, run_id):
    """Prove run<N>_annotations.csv is REALLY ground truth for THIS run — not text that merely hash-matches
    — by REUSING label_flows.load_annotations (the SAME strict parser the labeler trusts) [audit v20.32 §5].
    A benign run legitimately has zero attack rows, so an empty-but-well-formed file is accepted; but the
    header must carry the annotation columns (so a single-line 'THIS IS NOT ANNOTATIONS', which has no data
    rows and would slip past load_annotations, is rejected), and any rows present must validate and share
    THIS run_id. Returns (ok, reason)."""
    import csv as _csv
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            header = next(_csv.reader(fh), None)
    except (OSError, UnicodeDecodeError, _csv.Error) as exc:
        return False, repr(exc)[:120]
    cols = {h.strip() for h in (header or [])}
    missing = _ANNOTATION_COLS - cols
    if missing:
        return False, "annotations header missing columns {}".format(sorted(missing))
    try:
        import label_flows as lf
        _windows, file_run_id = lf.load_annotations(path)        # strict row validation (SystemExit on bad)
    except SystemExit as exc:
        return False, str(exc)
    except Exception as exc:                                      # pragma: no cover
        return False, repr(exc)[:120]
    if file_run_id is not None and int(file_run_id) != int(run_id):
        return False, "annotations run_id {} != {}".format(file_run_id, run_id)
    return True, "ok"


def _check_audit_events(audit_path, ann_path):
    """PROVE the audit's matched_event_id values are REAL — every non-empty one must be an event_id that
    exists in the annotations (an unmatched/benign flow carries an EMPTY matched_event_id) [audit v20.34 §5].
    An audit that points at NO_SUCH_EVENT is not this run's ground truth. Returns (ok, reason)."""
    import csv as _csv
    try:
        import label_flows as lf
        windows, _rid = lf.load_annotations(ann_path)            # the run's SUCCESS attack events
    except SystemExit as exc:
        return False, "annotations unreadable: {}".format(str(exc)[:80])
    valid = {w["event_id"] for w in windows}
    try:
        with open(audit_path, newline="", encoding="utf-8") as fh:
            for r in _csv.DictReader(fh):
                ev = (r.get("matched_event_id") or "").strip()
                if ev and ev not in valid:
                    return False, "matched_event_id {!r} is not an annotation event {}".format(
                        ev, sorted(valid)[:5])
    except (OSError, UnicodeDecodeError, _csv.Error) as exc:
        return False, repr(exc)[:80]
    return True, "ok"


def _check_event_identity(status, ann_path, audit_path):
    """Prove the EVENTS line up across annotations, status and audit — not merely 'some DoS exists' [audit
    v20.38 §6]:
      * a BIJECTION between status.events keys and the annotations' SUCCESS event_ids (no status id that
        isn't an annotation event; no extra success event that the status never counted);
      * per event, status.events[eid].label == the annotation's label, and the window matches;
      * every audit ATTACK row (label != BENIGN) carries a matched_event_id that is one of those events
        (a DoS audit row can't have an empty matched_event_id).
    Returns (ok, reason). Skipped when the status carries no events map (diagnostic/older status)."""
    import csv as _csv
    events = status.get("events")
    if not isinstance(events, dict):
        return True, "no status.events to reconcile"
    try:
        import label_flows as lf
        windows, _r = lf.load_annotations(ann_path)              # SUCCESS attack events only
    except SystemExit as exc:
        return False, "annotations unreadable: {}".format(str(exc)[:80])
    ann_by_id = {w["event_id"]: w for w in windows}
    if set(events.keys()) != set(ann_by_id.keys()):
        return False, "status.events {} != annotation success events {}".format(
            sorted(events.keys()), sorted(ann_by_id.keys()))
    for eid, ev in events.items():
        if not isinstance(ev, dict):                            # adversarial status -> clean FAIL, not a crash
            return False, "status.events[{}] is not an object".format(eid)
        w = ann_by_id[eid]
        if str(ev.get("label")) != str(w["label"]):
            return False, "event {} label status={} != annotation {}".format(eid, ev.get("label"), w["label"])
        for sk, wk in (("window_start", "start"), ("window_end", "end")):
            sv = ev.get(sk)
            if sv is not None and (not _isfloat(sv) or abs(float(sv) - float(w[wk])) > 1.0):
                return False, "event {} {} status={} != annotation {}".format(eid, sk, sv, w[wk])
    if os.path.exists(audit_path):
        try:
            with open(audit_path, newline="", encoding="utf-8") as fh:
                for r in _csv.DictReader(fh):
                    lab = (r.get("label") or "").strip()
                    mev = (r.get("matched_event_id") or "").strip()
                    if lab and lab != "BENIGN":
                        if not mev:
                            return False, "audit {} row has no matched_event_id".format(lab)
                        if mev not in events:
                            return False, "audit matched_event_id {!r} is not a status event".format(mev)
        except (OSError, UnicodeDecodeError, _csv.Error) as exc:
            return False, repr(exc)[:80]
    return True, "ok"


def _check_audit_flow_identity(run_dir, run_id, status, ann_path, audit_path):
    """Bind each audit ROW to the flow, event and log it claims — the 'flows' half of identity [audit
    v20.39 §5-§8]. The audit carries a `uid`, and conn.log carries uid + endpoints, so they JOIN by uid
    (no labeler flow_row_id needed for this half):
      * (§8) the row's id.orig_h / id.orig_p / id.resp_h / id.resp_p / proto must EQUAL the conn.log record
        for its uid — the WHOLE 5-tuple (both ports), and each element is MANDATORY (an empty audit field
        can no longer fail-open past the comparison) [v20.40 §7/§8];
      * (§9) a uid may appear on at most ONE audit row (a flow cannot be labeled twice) [v20.40 §9];
      * (§7) an attack row (label != BENIGN) must carry a matched_event_id whose status event has the SAME
        label; a BENIGN row must carry NO matched_event_id;
      * (§6) the row's ts must fall inside that event's [window_start, window_end], with the tolerance TAKEN
        from the authenticated labeling policy (window_padding_ms), default 0 — not a hardcoded 5 s [§10];
      * (§5) the per-event usable/ambiguous flow COUNTS recomputed from the audit must equal status.events.
    Returns (ok, reason). (Linking the leak-free split-ready/ML rows to the audit still needs a labeler-
    emitted flow_row_id — roadmap.)"""
    import csv as _csv
    import label_flows as lf
    events = status.get("events")
    if not isinstance(events, dict):
        return True, "no status.events"
    try:
        conn = {str(r["uid"]): r for r in lf.read_zeek_log(os.path.join(run_dir, "zeek_logs", "conn.log"))
                if r.get("uid")}
        windows, _r = lf.load_annotations(ann_path)
    except SystemExit as exc:
        return False, "logs/annotations unreadable: {}".format(str(exc)[:80])
    ann_by_id = {w["event_id"]: w for w in windows}
    # §10 [v20.40]: the temporal tolerance is DERIVED from the AUTHENTICATED labeling policy the labeler
    # sealed into the status (window_padding_ms / 1000), not a hardcoded 5 s. When the policy pins 0 (the
    # official default) the tolerance is 0 — a flow one second past the event window is out of it. Absent/
    # out-of-domain policy -> 0.0 (fail-closed): never invent a laxer window than the run pre-registered.
    _lp = status.get("labeling_policy") or {}
    _pad = _lp.get("window_padding_ms")
    tol = (float(_pad) / 1000.0) if isinstance(_pad, (int, float)) and not isinstance(_pad, bool) and _pad >= 0 else 0.0
    recomputed, seen = {}, set()
    try:
        with open(audit_path, newline="", encoding="utf-8") as fh:
            for i, r in enumerate(_csv.DictReader(fh), start=2):
                uid = (r.get("uid") or "").strip()
                lab = (r.get("label") or "").strip()
                mev = (r.get("matched_event_id") or "").strip()
                amb = (r.get("ambiguous") or "").strip().lower() in ("t", "true", "1")
                if uid:                                          # §9: one flow = one uid = one audit row.
                    if uid in seen:                              # a duplicated uid double-counts a single flow
                        return False, "audit row {} repeats uid {!r} (a flow cannot be labeled twice)".format(i, uid)
                    seen.add(uid)
                c = conn.get(uid)                                # §7/§8: endpoints/proto/PORTS vs conn.log
                if c is not None:
                    # BOTH ports now (orig AND resp) plus hosts+proto; an EMPTY audit field can no longer
                    # bypass the comparison — for a real flow every tuple element is MANDATORY [§7/§8].
                    for f in ("id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto"):
                        av, cv = (r.get(f) or "").strip(), (c.get(f) or "").strip()
                        if not av:
                            return False, "audit row {} has an empty {} for uid {}".format(i, f, uid)
                        if cv and str(av).lower() != str(cv).lower():
                            return False, "audit row {} {}={!r} != conn.log {!r}".format(i, f, av, cv)
                if lab and lab != "BENIGN":                      # §7/§6: attack row bound to a real, on-time event
                    if not mev:
                        return False, "audit {} row has no matched_event_id".format(lab)
                    ev = events.get(mev)
                    if ev is None:
                        return False, "audit matched_event_id {!r} is not a status event".format(mev)
                    if str((ev or {}).get("label")) != lab:
                        return False, "audit label {} != event {} label {}".format(lab, mev, (ev or {}).get("label"))
                    w = ann_by_id.get(mev)
                    if w is not None and _isfloat(r.get("ts")):
                        tv = float(r["ts"])
                        if tv < w["start"] - tol or tv > w["end"] + tol:
                            return False, "audit row {} ts {} outside event {} window [{}, {}]".format(
                                i, tv, mev, w["start"], w["end"])
                    recomputed.setdefault(mev, {"usable": 0, "ambiguous": 0})
                    recomputed[mev]["ambiguous" if amb else "usable"] += 1
                elif lab == "BENIGN" and mev:                    # §7 inverse: BENIGN must not carry an event
                    return False, "BENIGN audit row carries matched_event_id {!r}".format(mev)
                # §7.1 [v20.41]: the row's ts must be the ts of THAT conn.log flow — an audit whose uid and
                # 5-tuple match but whose ts is shifted describes a different moment (or a different flow).
                # Checked AFTER the event window so a genuinely out-of-window row still reads as a window fault.
                if c is not None:
                    _ats, _cts = r.get("ts"), c.get("ts")
                    if _isfloat(_ats) and _isfloat(_cts) and abs(float(_ats) - float(_cts)) > 1e-3:
                        return False, "audit row {} ts {} != conn.log ts {} for uid {}".format(i, _ats, _cts, uid)
    except (OSError, UnicodeDecodeError, _csv.Error) as exc:
        return False, repr(exc)[:80]
    for eid, ev in events.items():                              # §5: per-event counts vs the recomputed audit
        if not isinstance(ev, dict):
            return False, "status.events[{}] is not an object".format(eid)
        rc = recomputed.get(eid, {"usable": 0, "ambiguous": 0})
        for sk, rk in (("usable_flows", "usable"), ("ambiguous_flows", "ambiguous")):
            if ev.get(sk) is not None and int(ev[sk]) != rc[rk]:
                return False, "event {} {} status={} != audit-recomputed {}".format(eid, sk, ev.get(sk), rc[rk])
    return True, "ok"


def _check_audit_conn_uids(audit_path, conn_path):
    """PROVE the audit describes the SAME flows the Zeek capture produced: every audit `uid` must exist in
    conn.log [audit v20.35 §6]. An audit whose uid is GHOST_UID (absent from conn.log) is a different set
    of flows stitched onto a coherent split-ready/ML. Returns (ok, reason)."""
    import csv as _csv
    try:
        import label_flows as lf
        conn_uids = {str(r.get("uid")) for r in lf.read_zeek_log(conn_path) if r.get("uid")}
    except SystemExit as exc:
        return False, "conn.log unreadable: {}".format(str(exc)[:80])
    try:
        with open(audit_path, newline="", encoding="utf-8") as fh:
            reader = _csv.DictReader(fh)
            if not reader.fieldnames or "uid" not in reader.fieldnames:
                return False, "audit has no uid column"
            for r in reader:
                u = (r.get("uid") or "").strip()
                if not u:                                        # an empty uid can't be tied to any flow [§6]
                    return False, "audit row has an empty uid"
                if u not in conn_uids:
                    return False, "audit uid {!r} not in conn.log".format(u)
    except (OSError, UnicodeDecodeError, _csv.Error) as exc:
        return False, repr(exc)[:80]
    return True, "ok"


def _check_conn_uid_unique(conn_path):
    """A uid must identify exactly ONE flow, so conn.log itself must not REPEAT one [audit v20.42 §11]. The
    join dicts here key by uid ({uid: row}) and would silently let a duplicated row overwrite its twin —
    masking a second flow (or a stitched record) while every hash/count still reconciles. Returns
    (ok, reason)."""
    import label_flows as lf
    try:
        rows = lf.read_zeek_log(conn_path)
    except SystemExit as exc:
        return False, "conn.log unreadable: {}".format(str(exc)[:80])
    seen = set()
    for r in rows:
        u = r.get("uid")
        if not u:
            continue
        if str(u) in seen:
            return False, "conn.log repeats uid {!r} (a uid must identify one flow)".format(u)
        seen.add(str(u))
    return True, "ok"


def _check_audit_split_labels(audit_path, status):
    """PROVE the audit's NON-AMBIGUOUS rows describe the SAME labeling as the split-ready dataset: their
    per-class counts must equal status.class_counts_split_ready (itself reconciled with the split-ready CSV)
    [audit v20.36 §6]. An audit that is all-BENIGN while the split-ready is all-DoS is a different labeling
    stitched onto a coherent ML/split. Returns (ok, reason). (Full line-by-line linkage needs a per-flow
    row id from the labeler — roadmap.)"""
    claim = status.get("class_counts_split_ready")
    if not isinstance(claim, dict):
        return True, "no class_counts to reconcile"
    import csv as _csv
    counts = {}
    try:
        with open(audit_path, newline="", encoding="utf-8") as fh:
            reader = _csv.DictReader(fh)
            cols = reader.fieldnames or []
            if "label" not in cols or "ambiguous" not in cols:
                return False, "audit lacks label/ambiguous columns"
            for r in reader:
                if (r.get("ambiguous") or "").strip().lower() in ("t", "true", "1"):
                    continue                                     # ambiguous rows are dropped from split-ready
                lab = (r.get("label") or "").strip()
                counts[lab] = counts.get(lab, 0) + 1
    except (OSError, UnicodeDecodeError, _csv.Error) as exc:
        return False, repr(exc)[:80]
    norm = {str(k): int(v) for k, v in claim.items()}
    if counts != norm:
        return False, "audit non-ambiguous class counts {} != split-ready {}".format(counts, norm)
    return True, "ok"


def _check_join_counts(run_dir, run_id, status):
    """RECOMPUTE the SSL/QUIC join stats from the REAL logs and confront status.ssl_join / status.quic_join
    [audit v20.36 §8] — the same per-record count the labeler does. A status that claims 999 joining records
    over a 1-record log is rejected. Returns (ok, reason)."""
    import label_flows as lf
    log_dir = os.path.join(run_dir, "zeek_logs")
    try:
        conn_uids = {str(r.get("uid")) for r in lf.read_zeek_log(os.path.join(log_dir, "conn.log")) if r.get("uid")}
    except SystemExit as exc:
        return False, "conn.log unreadable: {}".format(str(exc)[:80])

    def real_stats(name):
        try:
            rows = lf.read_zeek_log(os.path.join(log_dir, name))
        except SystemExit:
            return None
        matching = missing = 0
        for r in rows:
            u = r.get("uid")
            if not u:
                missing += 1
            elif str(u) in conn_uids:
                matching += 1
        records = len(rows)
        return {"records": records, "records_matching_conn": matching,
                "orphan_records": records - matching - missing, "missing_uid_records": missing,
                "join_rate": round((matching / records) if records else 0.0, 4)}

    for key, logname in (("ssl_join", "ssl.log"), ("quic_join", "quic.log")):
        claim = status.get(key)
        if not isinstance(claim, dict):
            continue
        real = real_stats(logname)
        if real is None:
            return False, "{}: {} unreadable".format(key, logname)
        for f in ("records", "records_matching_conn", "orphan_records", "missing_uid_records"):
            if int(claim.get(f, -1)) != real[f]:
                return False, "{}.{} status={} != real {}".format(key, f, claim.get(f), real[f])
        if abs(float(claim.get("join_rate", -1)) - real["join_rate"]) > 0.001:
            return False, "{}.join_rate status={} != real {}".format(key, claim.get("join_rate"), real["join_rate"])
    return True, "ok"


def _check_tls_evidence(run_dir, sr_path):
    """The split-ready dataset's TLS/QUIC/transport VALUES must be BACKED by the sealed logs [audit v20.36
    §7 / v20.41 §7.2/§7.3], at two levels:
      * PRESENCE — if it declares tls_version != none or sni_present=1, the ssl/quic logs must carry a
        corresponding value. tls_version/server_name are NORMALIZED in the dataset (TLSv13 -> '1.3'), so
        only presence is checked for those.
      * VALUE MEMBERSHIP — ja3/ja3s/alpn are copied VERBATIM from the logs, so EVERY distinct value the
        dataset declares must actually APPEAR in the ssl/quic logs; likewise every `transport` must appear
        in conn.log's proto set. A dataset advertising `ja3=TOTALLY_DIFFERENT` or `transport=UDP` with no
        such value in the logs is rejected — not merely 'some ja3 exists somewhere'.
    (Binding each dataset ROW to its specific flow by value still needs the labeler's flow_row_id — the
    split-ready/ML rows are leak-free and carry no uid; this proves set membership, not per-line identity.)
    Returns (ok, reason)."""
    import feature_schema as fs
    import label_flows as lf
    try:
        df = fs.read_common_csv(sr_path)
    except Exception:                                            # pragma: no cover (schema checked elsewhere)
        return True, "split-ready unreadable (checked elsewhere)"
    log_dir = os.path.join(run_dir, "zeek_logs")

    def log_values(logname, *keys):
        try:
            rows = lf.read_zeek_log(os.path.join(log_dir, logname))
        except SystemExit:
            return set()
        return {str(r.get(k)) for r in rows for k in keys if r.get(k) not in (None, "", "-")}

    def declared_values(col):
        if col not in df.columns:
            return set()
        return {str(v) for v in df[col].tolist() if str(v) not in ("none", "nan", "", "None")}

    # PRESENCE for the NORMALIZED fields (dataset value != raw log value, so value-match is not possible here).
    if declared_values("tls_version") and not (log_values("ssl.log", "version") or log_values("quic.log", "version")):
        return False, "split-ready declares tls_version but no ssl/quic log carries a version"
    if "sni_present" in df.columns and any(str(v) in ("1", "1.0") for v in df["sni_present"].tolist()) \
            and not (log_values("ssl.log", "server_name") or log_values("quic.log", "server_name")):
        return False, "split-ready declares sni_present but no ssl/quic log carries a server_name"

    # VALUE MEMBERSHIP for the VERBATIM fields (+ transport vs conn.log proto, case-normalized).
    member = [
        ("ja3", log_values("ssl.log", "ja3")),
        ("ja3s", log_values("ssl.log", "ja3s")),
        ("alpn", log_values("ssl.log", "next_protocol") | log_values("quic.log", "client_protocol")),
        ("transport", {v.upper() for v in log_values("conn.log", "proto")}),
    ]
    for col, logvals in member:
        missing = declared_values(col) - logvals
        if missing:
            return False, "split-ready {} value(s) {} not present in the logs".format(col, sorted(missing))
    return True, "ok"


def _check_benign_evidence(run_dir, run_id, bqp, campaign, spec, status):
    """ENFORCE the benign_quality_policy's evidence gates against a WELL-FORMED, IN-WINDOW, NON-REPLAYED
    run<N>_benign.jsonl [audit v20.41 §5 / v20.42 §6-§9,§12]. When the policy asks for benign evidence, the
    run must ship the jsonl and it must actually BACK its numbers:
      * closed per-record SCHEMA — campaign_id/run_id/seed/attempt_id/session_id/browser/site/start/end/ok
        present and well-typed (site non-empty, ok a REAL boolean, session_id a positive int) [§9];
      * TEMPORAL — start/end are finite epochs (or ISO), end > start, and the session falls INSIDE the
        capture window [capture_start.started_utc, capture_end.ended_utc]; a 2033 session over a 2020
        capture is rejected [§6];
      * UNIQUENESS — session_id is unique, so N copies of one session no longer count as N sessions [§7];
      * IDENTITY — campaign_id/run_id/seed match the manifest AND attempt_id matches THIS attempt's
        status.attempt_id, so a previous attempt's jsonl left in staging is rejected [§12];
      * COUNTS — successful sessions / success-rate are RECOMPUTED from the file (never a declared summary),
        and require_browser_evidence needs a non-empty browser AND webdriver [§8].
    Returns (ok, reason). (Proving the browser/driver ACTUALLY ran — observed binary/driver versions — and
    full attempt_id PROPAGATION through the orchestrator are still lab/producer work — roadmap.)"""
    need = (bool(bqp.get("require_benign_jsonl")) or bqp.get("min_successful_sessions") is not None
            or bqp.get("min_success_rate") is not None or bool(bqp.get("require_browser_evidence")))
    if not need:
        return True, "no benign-evidence gates"
    path = os.path.join(run_dir, "run{}_benign.jsonl".format(run_id))
    if not os.path.exists(path):
        return False, "benign_quality_policy asks for benign evidence but run{}_benign.jsonl is absent".format(run_id)
    import json as _json
    records = []
    try:
        with open(path, encoding="utf-8") as fh:
            for ln, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = _json.loads(line)
                except ValueError:
                    return False, "benign jsonl line {} is not valid JSON".format(ln)
                if not isinstance(rec, dict):
                    return False, "benign jsonl line {} is not an object".format(ln)
                records.append(rec)
    except (OSError, UnicodeDecodeError) as exc:
        return False, repr(exc)[:80]
    if not records:
        return False, "benign jsonl is empty"
    # the window each session must fall INSIDE. Prefer the REAL packet interval (pcap first..last packet),
    # which is tighter and authenticated, over the WIDE declared capture window — a session inside
    # capture_start..capture_end but with NO packets in its interval is not evidence of captured traffic
    # [audit v20.42 §6 / v20.43 §13]. Fall back to the declared window if the pcap is unreadable.
    cap_start = _read_json_safe(os.path.join(run_dir, "run{}_capture_start.json".format(run_id))) or {}
    cap_end = _read_json_safe(os.path.join(run_dir, "run{}_capture_end.json".format(run_id))) or {}
    win_lo, win_hi, win_src = _iso_to_epoch(cap_start.get("started_utc")), _iso_to_epoch(cap_end.get("ended_utc")), "capture window"
    _pinfo, _ = _pcap_info(os.path.join(run_dir, "run{}.pcap".format(run_id)))
    pcap_lo = pcap_hi = None
    if _pinfo and _pinfo.get("first_ts") is not None and _pinfo.get("last_ts") is not None:
        pcap_lo, pcap_hi = _pinfo["first_ts"], _pinfo["last_ts"]
        win_lo, win_hi, win_src = pcap_lo - 5.0, pcap_hi + 5.0, "pcap packet window"

    def _sess_epoch(v):
        if isinstance(v, bool):
            return None
        if isinstance(v, (int, float)):
            return float(v) if math.isfinite(v) else None
        return _iso_to_epoch(v)

    req_fields = ("campaign_id", "run_id", "seed", "attempt_id", "session_id",
                  "browser", "site", "start", "end", "ok")
    seen_sids = set()
    for i, rec in enumerate(records, start=1):
        miss = [f for f in req_fields if f not in rec]
        if miss:
            return False, "benign jsonl record {} missing fields {}".format(i, miss)
        # closed SCHEMA [§9]
        if not str(rec.get("site") or "").strip():
            return False, "benign jsonl record {} has an empty site".format(i)
        if type(rec.get("ok")) is not bool:
            return False, "benign jsonl record {} ok is not a real boolean".format(i)
        if rec.get("ok") is True:                                  # a SUCCESSFUL session must SHOW pages [§8]
            pg = rec.get("pages")
            if isinstance(pg, bool) or not isinstance(pg, int) or pg < 1:
                return False, "benign jsonl record {} is ok=true but pages is not a positive int".format(i)
        if not str(rec.get("attempt_id") or "").strip():
            return False, "benign jsonl record {} has an empty attempt_id".format(i)
        sid = rec.get("session_id")
        if isinstance(sid, bool) or not isinstance(sid, int) or sid < 1:
            return False, "benign jsonl record {} session_id must be a positive int".format(i)
        if sid in seen_sids:                                       # UNIQUENESS [§7]
            return False, "benign jsonl repeats session_id {} (a replayed session is not a new one)".format(sid)
        seen_sids.add(sid)
        if bqp.get("require_browser_evidence"):                    # browser AND webdriver evidence [§8/§10]
            if not str(rec.get("browser") or "").strip():
                return False, "benign jsonl record {} has an empty browser (require_browser_evidence)".format(i)
            if not str(rec.get("webdriver") or "").strip():
                return False, "benign jsonl record {} has no webdriver evidence (require_browser_evidence)".format(i)
            # SEMANTIC browser/driver evidence [audit v20.44 §10]: the OBSERVED capabilities must name a KNOWN
            # browser, a non-empty version, and a MATCHING driver — 'banana-browser 999' / 'magicdriver' no
            # longer pass just by being non-empty strings.
            _drv = {"firefox": "geckodriver", "chrome": "chromedriver"}
            bn = str(rec.get("browser_name") or "").strip().lower()
            if bn not in _drv:
                return False, "benign jsonl record {} browser_name {!r} not in {}".format(i, rec.get("browser_name"), sorted(_drv))
            if not str(rec.get("browser_version") or "").strip():
                return False, "benign jsonl record {} has an empty browser_version".format(i)
            wn = str(rec.get("webdriver_name") or "").strip().lower()
            if wn != _drv[bn]:
                return False, "benign jsonl record {} webdriver_name {!r} does not match browser {} (expected {})".format(i, rec.get("webdriver_name"), bn, _drv[bn])
            if not str(rec.get("webdriver_version") or "").strip():
                return False, "benign jsonl record {} has an empty webdriver_version".format(i)
        # TEMPORAL [§6]
        st, en = _sess_epoch(rec.get("start")), _sess_epoch(rec.get("end"))
        if st is None or en is None:
            return False, "benign jsonl record {} has a non-finite start/end".format(i)
        if en <= st:
            return False, "benign jsonl record {} end {} <= start {}".format(i, en, st)
        if bqp.get("require_browser_evidence") and en - st < 0.1:  # §11: page-load floor — BROWSER traffic only
            # Level-2 non-browser clients (curl/httpx/aioquic) make sub-100ms connections BY DESIGN; the floor
            # only applies when the benign source is a browser. Universal temporal checks (window, order) stay.
            return False, "benign jsonl record {} lasts only {:.4f}s — implausibly short for a browser session".format(i, en - st)
        if win_lo is not None and st < win_lo - 1e-6:
            return False, "benign jsonl record {} start {} is before the {} start {}".format(i, st, win_src, win_lo)
        if win_hi is not None and en > win_hi + 1e-6:
            return False, "benign jsonl record {} end {} is after the {} end {}".format(i, en, win_src, win_hi)
        if pcap_lo is not None and not (st <= pcap_hi and en >= pcap_lo):   # must OVERLAP real packets [audit v20.44 §9]
            return False, "benign jsonl record {} [{}, {}] does not overlap the captured packets [{}, {}]".format(
                i, st, en, pcap_lo, pcap_hi)
    # §11 [v20.43/v20.44]: reject CLONED sessions — identical CONTENT under a different session_id is ONE
    # session replayed, not N independent ones. The digest EXCLUDES `pages` so bumping an unauthenticated
    # page counter can no longer disguise a clone [audit v20.44 §7]; a real run's sessions differ at least in
    # their wall-clock start.
    # Level-2 clients issue MANY identical GETs (same site/path) concurrently; identical (site,start,end)
    # tuples are expected, not a replay. The clone check assumes a browser's unique per-session content,
    # so it applies to BROWSER traffic only. session_id uniqueness above still holds for every source.
    if bqp.get("require_browser_evidence"):
        seen_digests = set()
        for i, rec in enumerate(records, start=1):
            dig = (str(rec.get("attempt_id")), str(rec.get("browser")), str(rec.get("site")),
                   str(rec.get("start")), str(rec.get("end")))
            if dig in seen_digests:
                return False, "benign jsonl record {} is a CLONE of an earlier session (same content, new session_id)".format(i)
            seen_digests.add(dig)
    # §9 [audit v20.47]: a single-browser producer runs sessions SEQUENTIALLY, so they must NOT OVERLAP.
    # Two near-identical sessions shifted by a millisecond overlap almost entirely and are rejected — a
    # duration floor alone can't catch them. (A producer-issued session_nonce + linkage to the captured
    # BENIGN flows is the robust identity — roadmap.)
    # A SINGLE-browser producer runs sessions sequentially; Level-2 runs 30 CONCURRENT workers BY DESIGN,
    # so overlap is the expected shape, not a replay. Sequentiality applies to BROWSER traffic only. Every
    # session is still pinned to the capture window individually above, so concurrency can't smuggle in
    # out-of-window sessions.
    if bqp.get("require_browser_evidence"):
        _spans = sorted((( _sess_epoch(r.get("start")), _sess_epoch(r.get("end"))) for r in records),
                        key=lambda p: (p[0] if p[0] is not None else 0.0))
        for _k in range(1, len(_spans)):
            _pe, _cs = _spans[_k - 1][1], _spans[_k][0]
            if _pe is not None and _cs is not None and _cs < _pe - 1e-6:
                return False, "benign sessions OVERLAP (a session starts at {} before the previous ended at {}) — sessions must be sequential".format(_cs, _pe)
    # RECOMPUTE the session/success numbers from the artifact — do not trust a declared summary.
    sessions = len(records)
    ok_sessions = sum(1 for r in records if r.get("ok") is True)
    rate = ok_sessions / sessions if sessions else 0.0
    mss = bqp.get("min_successful_sessions")
    if mss is not None and ok_sessions < mss:
        return False, "benign successful sessions {} < min_successful_sessions {}".format(ok_sessions, mss)
    msr = bqp.get("min_success_rate")
    if msr is not None and rate < float(msr):
        return False, "benign success rate {:.3f} < min_success_rate {}".format(rate, msr)
    # IDENTITY: the sessions must belong to THIS run/campaign/ATTEMPT (not another attempt's log) [§12].
    cid = (campaign or {}).get("campaign_id")
    seed = (spec or {}).get("seed")
    att = (status or {}).get("attempt_id")
    for i, rec in enumerate(records, start=1):
        if cid is not None and str(rec.get("campaign_id")) != str(cid):
            return False, "benign jsonl record {} campaign_id {!r} != manifest {!r}".format(i, rec.get("campaign_id"), cid)
        if str(rec.get("run_id")) != str(run_id):
            return False, "benign jsonl record {} run_id {!r} != {!r}".format(i, rec.get("run_id"), run_id)
        if seed is not None and str(rec.get("seed")) != str(seed):
            return False, "benign jsonl record {} seed {!r} != manifest {!r}".format(i, rec.get("seed"), seed)
        if att is not None and str(rec.get("attempt_id")) != str(att):
            return False, "benign jsonl record {} attempt_id {!r} != status {!r} (stale/replayed log)".format(i, rec.get("attempt_id"), att)
    return True, "ok"


def _check_ml_splitready_projection(ml_path, sr_path):
    """PROVE the ML file is the PROJECTION of the split-ready file — same rows, same order, identical
    COMMON+label values (split-ready merely adds run_id + timestamp) [audit v20.33 §10]. Individually-valid
    files that describe DIFFERENT flows (e.g. ja3 differs between them) must NOT both seal: validating each
    file in isolation never proved they are the SAME experiment. Reuses feature_schema.read_common_csv so
    the dtypes line up. Returns (ok, reason)."""
    import feature_schema as fs
    try:
        ml = fs.read_common_csv(ml_path)
        sr = fs.read_common_csv(sr_path)
    except Exception as exc:                                     # pragma: no cover
        return False, "unreadable: {}".format(repr(exc)[:80])
    cols = list(fs.COMMON) + [fs.LABEL]
    if len(ml) != len(sr):
        return False, "row counts differ (ml {} vs split_ready {})".format(len(ml), len(sr))
    missing = [c for c in cols if c not in ml.columns or c not in sr.columns]
    if missing:
        return False, "missing shared column(s) {}".format(missing)
    a = ml[cols].reset_index(drop=True).astype(str)
    b = sr[cols].reset_index(drop=True).astype(str)
    if not a.equals(b):
        ne = (a != b)
        diffs = [(int(i), c) for c in cols for i in a.index if ne.at[i, c]]
        return False, "ML != split-ready on COMMON+label (e.g. row/col {})".format(diffs[:3])
    return True, "ok"


def check_binding(run_dir, run_id, campaign_path=None, strict=True):
    """PROVE every sealed artifact belongs to the SAME run and campaign — FAIL-CLOSED. In `strict`
    (official) mode a MISSING file/field/hash, non-distinct outputs, an unbound campaign, or a CSV that is
    not really a dataset are ALL a FAIL — never "skip the comparison" [audit v20.31 §4-§8]. In non-strict
    (diagnostic) mode absent pieces are tolerated. The chain proven:

        run<N>.pcap --sha--> zeek_processing.pcap_sha256
        zeek_logs/*.log --sha--> zeek_processing.logs[*].sha256  AND  status.input_hashes.{conn,ssl,quic}
        run<N>_annotations.csv --sha--> status.input_hashes.annotations
        status.files.{ml,split_ready,audit} (3 DISTINCT real datasets) --sha--> status.output_hashes.{...}
        run_id equal across capture_start/end + zeek + status + the CLI, and campaign sha/config/split."""
    rid = str(run_id)
    P = lambda name: os.path.join(run_dir, name)
    status = _read_json_safe(P("run{}_run_status.json".format(rid)))
    if status is None:
        return ("FAIL", {"error": "no run_status.json to bind"}) if strict else ("SKIP", {"reason": "no status"})
    cap_start = _read_json_safe(P("run{}_capture_start.json".format(rid)))
    cap_end = _read_json_safe(P("run{}_capture_end.json".format(rid)))
    zeek = _read_json_safe(P("run{}_zeek_processing.json".format(rid)))
    problems = []

    def need(cond, msg):                                       # in strict mode a FALSE condition is a FAIL
        if strict and not cond:
            problems.append(msg)

    def cmp_hash(declared, real, msg):
        """FAIL-CLOSED hash compare: a missing declaration OR a missing file OR a mismatch all FAIL."""
        if declared is None:
            need(False, msg + " (declared hash missing)")
        elif real is None:
            problems.append(msg + " (file missing on disk)")
        elif declared != real:
            problems.append(msg + " (hash mismatch)")

    # capture_start is REQUIRED for an official run (start time / interface / filter / initial clock) [§12].
    need(cap_start is not None, "run{}_capture_start.json missing".format(rid))
    # §13/§8: it must be a REAL start record, not just {"run_id": 0}, and its fields must have the right
    # TYPES/domains — not merely be present [audit v20.33 §13 / v20.34 §8]. interface: non-empty string;
    # filter: string OR null (a list is invalid); duration_s: a finite POSITIVE number; started_utc: a
    # parseable ISO-8601 UTC instant; tcpdump_version: non-empty string.
    if strict and cap_start is not None:
        iface = cap_start.get("interface")
        if not isinstance(iface, str) or not iface.strip():
            problems.append("capture_start.interface must be a non-empty string")
        if "filter" not in cap_start:
            problems.append("capture_start.filter key missing (use null for no BPF)")
        elif cap_start.get("filter") is not None and not isinstance(cap_start.get("filter"), str):
            problems.append("capture_start.filter must be a string or null")
        dur = cap_start.get("duration_s")
        if isinstance(dur, bool) or not isinstance(dur, (int, float)) or not math.isfinite(dur) or dur <= 0:
            problems.append("capture_start.duration_s must be a finite positive number (got {!r})".format(dur))
        if _iso_to_epoch(cap_start.get("started_utc")) is None:
            problems.append("capture_start.started_utc is not a parseable ISO-8601 UTC instant")
        tv = cap_start.get("tcpdump_version")
        if not isinstance(tv, str) or not tv.strip():
            problems.append("capture_start.tcpdump_version must be a non-empty string")

    # (1) run_id coherence — every artifact that should carry one MUST, and equal rid [§7].
    for name, js in (("capture_start", cap_start), ("capture_end", cap_end),
                     ("zeek_processing", zeek), ("run_status", status)):
        if js is None:
            need(False, "{} missing (cannot bind run_id)".format(name))
        elif str(js.get("run_id")) != rid:
            problems.append("{}.run_id={!r} != {}".format(name, js.get("run_id"), rid))

    # (2) PCAP -> Zeek: zeek MUST declare pcap_sha256 + each log sha (+ site script sha) and they MUST
    #     equal the real files [§6/§8]. Omitting a field is a FAIL, not a free pass.
    real_pcap = _sha(P("run{}.pcap".format(rid)))
    if zeek is None:
        need(False, "zeek_processing missing")
    else:
        cmp_hash(zeek.get("pcap_sha256"), real_pcap, "zeek_processing.pcap_sha256 vs run{}.pcap".format(rid))
        zlogs = zeek.get("logs") or {}
        for ln in ("conn.log", "ssl.log", "quic.log"):
            cmp_hash((zlogs.get(ln) or {}).get("sha256"), _sha(P(os.path.join("zeek_logs", ln))),
                     "zeek_processing.logs.{}".format(ln))
        need(zeek.get("site_script_sha256") is not None, "zeek_processing.site_script_sha256 missing")

    # (3) Zeek logs + annotations -> labeler INPUTS: status.input_hashes MUST match the real files [§5].
    ih = status.get("input_hashes") or {}
    for key, fname in (("conn", "conn.log"), ("ssl", "ssl.log"), ("quic", "quic.log")):
        cmp_hash(ih.get(key), _sha(P(os.path.join("zeek_logs", fname))), "status.input_hashes.{}".format(key))
    ann_path = P("run{}_annotations.csv".format(rid))
    cmp_hash(ih.get("annotations"), _sha(ann_path), "status.input_hashes.annotations")
    # ANNOTATIONS content — not merely the hash: REUSE the labeler's strict parser so arbitrary text that
    # happens to hash-match is rejected [audit v20.32 §5].
    if strict:
        if not os.path.exists(ann_path):
            need(False, "run{}_annotations.csv missing (cannot validate ground truth)".format(rid))
        else:
            ok_ann, why_ann = _validate_annotations(ann_path, run_id)
            if not ok_ann:
                problems.append("annotations are not valid ground truth: {}".format(why_ann))

    # (4) labeler OUTPUTS: 3 DISTINCT files [§8], each present, hash-matched [§5], AND a real dataset [§7].
    files, oh = status.get("files") or {}, status.get("output_hashes") or {}
    bases = {}
    for key in ("ml", "split_ready", "audit"):
        decl = files.get(key)
        base = os.path.basename(decl) if decl else None
        bases[key] = base
        cand = P(base) if base else None
        if not base:
            need(False, "status.files.{} missing".format(key))
            continue
        real = _sha(cand) if (cand and os.path.exists(cand)) else None
        cmp_hash(oh.get(key), real, "output_hashes.{} vs {}".format(key, base))
        if real is None:
            continue
        ok, why = _validate_dataset_csv(cand, run_id, key, status)   # must be the DATASET, not just hash-match [§6]
        if not ok:
            problems.append("'{}' ({}) is not a valid {} dataset: {}".format(key, base, key, why))
    present_bases = [b for b in bases.values() if b]
    if len(set(present_bases)) != len(present_bases):
        problems.append("files.ml/split_ready/audit must be DISTINCT files (got {})".format(bases))

    # §10: PROVE the RELATION between the outputs — the ML file must be the projection of the split-ready
    # file (same rows/order, identical COMMON+label). Two individually-valid files describing DIFFERENT
    # flows must not both seal [audit v20.33 §10].
    if strict and bases.get("ml") and bases.get("split_ready") and bases["ml"] != bases["split_ready"]:
        ml_p, sr_p = P(bases["ml"]), P(bases["split_ready"])
        if os.path.exists(ml_p) and os.path.exists(sr_p):
            ok_proj, why_proj = _check_ml_splitready_projection(ml_p, sr_p)
            if not ok_proj:
                problems.append("ML is not the projection of split-ready: {}".format(why_proj))

    # §5: the audit's matched_event_id values must be REAL annotation events (or empty) — an audit that
    # points at NO_SUCH_EVENT is not this run's ground truth [audit v20.34 §5].
    if strict and bases.get("audit") and os.path.exists(ann_path):
        au_p = P(bases["audit"])
        if os.path.exists(au_p):
            ok_ev, why_ev = _check_audit_events(au_p, ann_path)
            if not ok_ev:
                problems.append("audit is not bound to the annotation events: {}".format(why_ev))
            # §6 [v20.38]: EVENT identity — status.events <-> annotation events bijection + per-event label/
            # window + every audit attack row references a real event.
            if os.path.exists(ann_path):
                ok_id, why_id = _check_event_identity(status, ann_path, au_p)
                if not ok_id:
                    problems.append("event identity broken: {}".format(why_id))
                # §5-§8 [v20.39]: FLOW identity — join each audit row to its conn.log flow (by uid) and its
                # event; recompute the per-event flow counts from the audit.
                ok_fl, why_fl = _check_audit_flow_identity(run_dir, run_id, status, ann_path, au_p)
                if not ok_fl:
                    problems.append("audit flow identity broken: {}".format(why_fl))

    # §6: the audit's uids must be REAL conn.log flows — an audit describing flows that aren't in the Zeek
    # logs (GHOST_UID / empty uid) is a different flow set stitched onto a coherent split-ready/ML [v20.35/
    # v20.36 §6]. And its NON-ambiguous per-class label counts must equal the split-ready's, so an audit
    # that relabels the same flows (all-BENIGN vs a DoS split-ready) is rejected.
    if strict and bases.get("audit"):
        au_p, conn_p = P(bases["audit"]), P(os.path.join("zeek_logs", "conn.log"))
        if os.path.exists(au_p) and os.path.exists(conn_p):
            ok_uid, why_uid = _check_audit_conn_uids(au_p, conn_p)
            if not ok_uid:
                problems.append("audit flows are not in the Zeek logs: {}".format(why_uid))
        if os.path.exists(conn_p):                                # §11 [v20.42]: a uid identifies ONE flow
            ok_cu, why_cu = _check_conn_uid_unique(conn_p)
            if not ok_cu:
                problems.append("conn.log uid not unique: {}".format(why_cu))
        if os.path.exists(au_p):
            ok_lab, why_lab = _check_audit_split_labels(au_p, status)
            if not ok_lab:
                problems.append("audit labeling != split-ready labeling: {}".format(why_lab))

    # §8: the status' SSL/QUIC join stats must MATCH the real logs (records/matching/orphan/missing/rate).
    if strict:
        ok_jn, why_jn = _check_join_counts(run_dir, run_id, status)
        if not ok_jn:
            problems.append("status ssl/quic join stats != real logs: {}".format(why_jn))

    # §7: TLS/QUIC features declared in the split-ready must have real evidence in the sealed logs.
    if strict and bases.get("split_ready"):
        sr_p = P(bases["split_ready"])
        if os.path.exists(sr_p):
            ok_tls, why_tls = _check_tls_evidence(run_dir, sr_p)
            if not ok_tls:
                problems.append("declared TLS/QUIC features lack log evidence: {}".format(why_tls))

    # §5/§6 [v20.44]: an OFFICIAL run must ship its ORCHESTRATION report, and that report's attempt_id must
    # MATCH the status. This binds the sealed evidence to the ATTEMPT whose plan actually ran, so merely
    # renaming status.attempt_id + benign.attempt_id ('rebatizing' the run) no longer yields a valid seal —
    # the report (which is itself sealed in the inventory) still names the original attempt.
    if strict:
        orch_p = P("run{}_orchestration.json".format(rid))
        orch = _read_json_safe(orch_p) if os.path.exists(orch_p) else None
        if not isinstance(orch, dict):
            problems.append("official seal needs run{}_orchestration.json (proof of the executed plan)".format(rid))
        else:
            if not orch.get("attempt_id"):
                problems.append("run{}_orchestration.json has no attempt_id".format(rid))
            elif status.get("attempt_id") and str(orch["attempt_id"]) != str(status["attempt_id"]):
                problems.append("orchestration.attempt_id {!r} != status.attempt_id {!r} (rebatized run)".format(
                    orch["attempt_id"], status.get("attempt_id")))
            # §7 [v20.46]: the plan must have actually SUCCEEDED — a report that itself says overall != PASS,
            # that ABORTED, or whose REQUIRED steps didn't all pass can NEVER back an official seal. A real
            # official run is only sealed after a clean pipeline; a direct finalize must be just as strict.
            if orch.get("overall") != "PASS":
                problems.append("orchestration.overall={!r} is not PASS".format(orch.get("overall")))
            if orch.get("aborted_at") is not None:
                problems.append("orchestration aborted at {!r} — an aborted run is not official".format(orch.get("aborted_at")))
            # §7 [v20.47]: only a KNOWN automation may seal — a report whose tool_version isn't the current
            # banner is refused (a 'bogus' version no longer slips through).
            if str(orch.get("tool_version")) != runlib.TOOL_VERSION:
                problems.append("orchestration.tool_version {!r} != {!r}".format(orch.get("tool_version"), runlib.TOOL_VERSION))
            osteps = orch.get("steps")
            if not isinstance(osteps, list) or not osteps:
                problems.append("run{}_orchestration.json has no steps (no evidence of the executed plan)".format(rid))
            else:
                # §6 [v20.47]: DERIVE which steps are CRITICAL from the KNOWN plan — do NOT trust the report's
                # own `required` flags. A report that marks capture optional, or fills `steps` with non-object
                # junk, cannot hide that these steps must have RUN and PASSED for the run to be real.
                _by = {str(s.get("step") or s.get("name")): s for s in osteps if isinstance(s, dict)}
                for _need in ("start_capture", "attacks", "process_pcap", "label_flows"):
                    _s = _by.get(_need)
                    if not isinstance(_s, dict):
                        problems.append("orchestration is missing the critical step {!r}".format(_need))
                    elif _s.get("ok") is not True or _s.get("skipped"):
                        problems.append("orchestration required step {!r} did not pass (ok={}, skipped={})".format(
                            _need, _s.get("ok"), _s.get("skipped")))
            # §8 [v20.46]: the report must be THIS campaign + run — not another's reused under the same
            # attempt_id. Confront the campaign hash and run_id against the status/run.
            if not orch.get("campaign_sha256"):
                problems.append("run{}_orchestration.json has no campaign_sha256".format(rid))
            elif status.get("campaign_sha256") and str(orch["campaign_sha256"]) != str(status["campaign_sha256"]):
                problems.append("orchestration.campaign_sha256 != status.campaign_sha256")
            if str(orch.get("run_id")) != str(run_id):
                problems.append("orchestration.run_id {!r} != {!r}".format(orch.get("run_id"), run_id))

    # §9/§10 [v20.46]: the SAME attempt_id must also be stamped on the CAPTURE and ZEEK-processing evidence,
    # so a COORDINATED rebatization (renaming only status + benign + orchestration) is caught — capture_start/
    # end and zeek_processing still name the ORIGINAL attempt. (Extending this to annotations/clocks/monitor
    # is the remaining propagation — roadmap.)
    if strict and status.get("attempt_id"):
        _sa = str(status["attempt_id"])
        for _fn in ("run{}_capture_start.json", "run{}_capture_end.json", "run{}_zeek_processing.json"):
            _p = P(_fn.format(rid))
            _j = _read_json_safe(_p) if os.path.exists(_p) else None
            if isinstance(_j, dict):
                if not _j.get("attempt_id"):
                    problems.append("{} has no attempt_id".format(_fn.format(rid)))
                elif str(_j["attempt_id"]) != _sa:
                    problems.append("{}.attempt_id {!r} != status {!r}".format(_fn.format(rid), _j["attempt_id"], _sa))

    # (5) campaign identity — MANDATORY in official mode, and the manifest must be a VALID campaign [§4].
    # REUSE campaign.load (the SAME strict loader the labeler/merge trust) instead of a generic JSON read,
    # so a manifest missing expected_labels / with an out-of-matrix config can no longer bind an official
    # seal. In diagnostic mode a loose manifest is tolerated (fall back to a plain read).
    if strict and not campaign_path:
        problems.append("no --campaign: an official seal must be bound to the manifest")
    if campaign_path and os.path.exists(campaign_path):
        man = None
        try:
            import campaign as camp
            # §7: an OFFICIAL seal needs a REPRODUCIBLE campaign (every run has seed AND day AND the full
            # plan) — not merely a syntactically-valid manifest [audit v20.33 §7]. Diagnostic mode stays
            # lenient.
            man = camp.load(campaign_path, require_reproducible=strict)
        except SystemExit as exc:
            if strict:
                problems.append("--campaign is not a valid REPRODUCIBLE manifest: {}".format(str(exc)[:160]))
            else:
                man = _read_json_safe(campaign_path) or {}
        except Exception as exc:                                # pragma: no cover
            problems.append("--campaign unreadable: {}".format(repr(exc)[:120]))
        if man is not None:
            cmp_hash(status.get("campaign_sha256"), runlib.sha256_file(campaign_path),
                     "status.campaign_sha256 vs manifest")
            spec = (man.get("runs") or {}).get(rid) or {}
            need(bool(spec), "manifest has no run {} entry".format(rid))
            if spec.get("config_id") is not None and status.get("config_id") is not None \
                    and int(status["config_id"]) != int(spec["config_id"]):
                problems.append("status.config_id={} != manifest {}".format(status.get("config_id"), spec.get("config_id")))
            if spec.get("split") and status.get("split") and status["split"] != spec["split"]:
                problems.append("status.split={!r} != manifest {!r}".format(status.get("split"), spec.get("split")))
            # §8: the annotations must BELONG to this campaign — reuse the campaign-aware validator
            # (campaign_id / campaign_sha256 / config_id / split per row + pinned endpoints + config
            # protocol/port/tool semantics). Annotations from another campaign/config/split are rejected
            # even though each row is individually well-formed [audit v20.33 §8].
            if strict and os.path.exists(ann_path):
                try:
                    import label_flows as lf
                    lf.validate_annotations_campaign(ann_path, campaign_path, require_complete_manifest=True)
                except SystemExit as exc:
                    problems.append("annotations not bound to this campaign: {}".format(str(exc)[:160]))
            # §12: an OFFICIAL run's capture-quality thresholds must be PRE-REGISTERED in the manifest
            # (capture_quality_policy), so they cannot be chosen AFTER seeing the results — and a later
            # --rotate-seal cannot relax them [audit v20.35 §12]. The finalizer floors the CLI thresholds
            # against this policy; here we just require it to be present and well-formed.
            if strict:
                ok_cqp, why_cqp = _validate_capture_quality_policy(man.get("capture_quality_policy"))
                if not ok_cqp:
                    problems.append("manifest.capture_quality_policy invalid/absent: {}".format(why_cqp))
            # §6 [v20.37]: every attack the manifest PLANS for this run must actually be PRESENT — a SUCCESS
            # annotation event AND >=1 split-ready row of that class. A campaign that plans DoS but produced
            # zero annotations / only BENIGN (run_attacks crashed, or the attack silently failed) can NOT
            # seal official — the seal must not certify an experiment that did not happen. A genuinely
            # failed attack belongs in a --diagnostic seal, not an official one.
            if strict:
                planned = [str(a) for a in (spec.get("attacks") or [])]
                ccsr = status.get("class_counts_split_ready") or {}
                ann_labels = set()
                if os.path.exists(ann_path):
                    try:
                        import label_flows as lf
                        windows, _r = lf.load_annotations(ann_path)
                        ann_labels = {w["label"] for w in windows}
                    except SystemExit:
                        pass
                for atk in planned:
                    if int((ccsr or {}).get(atk, 0)) <= 0:
                        problems.append("run plans attack {} but split-ready has 0 {} rows".format(atk, atk))
                    if atk not in ann_labels:
                        problems.append("run plans attack {} but annotations carry no successful {} event".format(atk, atk))
                # §5/§6 [v20.40/v20.41]: an OFFICIAL run must PRE-REGISTER a benign_quality_policy (positive
                # min_benign_flows), the run must CARRY that many BENIGN flows, AND — new in v20.41 — the
                # policy's EVIDENCE gates are actually ENFORCED against run<N>_benign.jsonl (sessions,
                # success rate, browser, identity), not merely type-checked.
                bqp = man.get("benign_quality_policy")
                ok_bqp, why_bqp = _validate_benign_quality_policy(bqp)
                if not ok_bqp:
                    problems.append("manifest.benign_quality_policy invalid/absent: {}".format(why_bqp))
                else:
                    have = int((ccsr or {}).get("BENIGN", 0))
                    if have < bqp["min_benign_flows"]:
                        problems.append("benign_quality_policy needs >= {} BENIGN flows but split-ready has {}".format(
                            bqp["min_benign_flows"], have))
                    ok_be, why_be = _check_benign_evidence(run_dir, rid, bqp, man, spec, status)
                    if not ok_be:
                        problems.append("benign evidence missing/insufficient: {}".format(why_be))
                # §6 [v20.41]: the campaign must PRE-REGISTER its labeling policy, and the status' ACTUAL
                # labeling_policy must MEET it — otherwise a custom manifest can omit the policy and let the
                # status declare weak gates (e.g. window_padding_ms=10000), which is exactly what the flow-
                # window tolerance now trusts. REUSE provenance.policy_violations (the labeler's comparator).
                rlp = man.get("required_labeling_policy")
                if not isinstance(rlp, dict) or not rlp:
                    problems.append("official seal needs the campaign to declare required_labeling_policy "
                                    "(or required_policy_profile)")
                else:
                    import provenance as prov
                    viol = prov.policy_violations(status.get("labeling_policy"), rlp)
                    if viol:
                        problems.append("status.labeling_policy relaxes the campaign's required policy: {}".format(
                            ["{}={!r} needs {}".format(k, o, r) for k, o, r in viol][:6]))

    detail = {"run_id": rid, "status_diagnostic": status.get("diagnostic"), "outputs": bases}
    if problems:
        detail["problems"] = problems
        return "FAIL", detail
    return "PASS", detail


def _required_eff(required, diagnostic):
    """The effective required-artifact set. Official mode ALWAYS keeps the 4 defaults (a caller can only
    ADD); diagnostic mode may use a reduced set [audit v20.30 §5]."""
    extra = required or []
    if diagnostic:
        return list(extra) if extra else list(DEFAULT_REQUIRED)
    return list(DEFAULT_REQUIRED) + [r for r in extra if r not in DEFAULT_REQUIRED]


def _verdict(run_dir, run_id, required_eff, campaign_path, min_packets, max_drop_rate,
             require_effect, diagnostic):
    """Compute the PASS/FAIL + official verdict from the artifacts WITHOUT writing anything. Shared by
    finalize (to seal) and --verify (to RE-DERIVE and detect a tampered completion) [audit v20.31 §9]."""
    present, missing = check_required(run_dir, run_id, required_eff)
    status_state, status_detail = validate_status(run_dir, run_id, campaign_path)
    cap_state, cap_detail = check_capture_semantics(run_dir, run_id, min_packets, max_drop_rate,
                                                    strict=not diagnostic)                          # [§8]
    zeek_state, zeek_detail = check_zeek_semantics(run_dir, run_id, strict=not diagnostic)          # [§9]
    bind_state, bind_detail = check_binding(run_dir, run_id, campaign_path, strict=not diagnostic)  # [§4-§6]
    temporal_state, temporal_detail = check_temporal_coherence(run_dir, run_id, strict=not diagnostic)  # [§7]
    semantics = {"capture": {"state": cap_state, "detail": cap_detail},
                 "zeek": {"state": zeek_state, "detail": zeek_detail},
                 "binding": {"state": bind_state, "detail": bind_detail},
                 "temporal": {"state": temporal_state, "detail": temporal_detail}}
    if require_effect:
        ep = os.path.join(run_dir, "run{}_service_effect.json".format(run_id))
        eff = _read_json_safe(ep)
        # NOT just presence: the DoS effect must be CONFIRMED [audit v20.31 §13]. A report saying
        # effect_confirmed=false does not satisfy the gate (relabel to SlowHTTPDoSAttempt instead).
        confirmed = bool(eff) and eff.get("effect_confirmed") is True
        semantics["effect"] = {"state": "PASS" if confirmed else "FAIL",
                               "detail": {"present": eff is not None,
                                          "effect_confirmed": (eff or {}).get("effect_confirmed")}}
    status_js = _read_json_safe(os.path.join(run_dir, "run{}_run_status.json".format(run_id))) or {}
    status_is_diagnostic = bool(status_js.get("diagnostic")) or bool(status_js.get("diagnostic_reasons"))

    def _ok(state):
        return state == "PASS" or (state == "SKIP" and diagnostic)
    sem_ok = all(_ok(v["state"]) for v in semantics.values())
    # OFFICIAL requires everything PASS AND the status itself non-diagnostic [§6].
    overall = "PASS" if (not missing and _ok(status_state) and sem_ok
                         and (diagnostic or not status_is_diagnostic)) else "FAIL"
    return {"overall": overall, "official": (not diagnostic) and overall == "PASS",
            "status_is_diagnostic": status_is_diagnostic, "required_present": present,
            "required_missing": missing,
            "status_validation": {"state": status_state, "detail": status_detail}, "semantics": semantics}


def _copy_external_evidence(run_dir, run_id, campaign_path):
    """Copy the campaign manifest and the Zeek site script (local.zeek) INTO the run as run<N>_campaign.json
    and run<N>_local.zeek BEFORE the inventory, so the sealed bundle is SELF-CONTAINED [audit v20.32 §14]:
    a reviewer holding ONLY run<N>_bundle.tar.gz can re-verify the campaign identity and the exact analyzer
    set (JA3/QUIC) without the surrounding lab tree. Returns the internal copy names actually written."""
    copies = {}
    if campaign_path and os.path.exists(campaign_path):
        dst = os.path.join(run_dir, "run{}_campaign.json".format(run_id))
        try:
            shutil.copyfile(campaign_path, dst); copies["campaign"] = os.path.basename(dst)
        except OSError:                                          # pragma: no cover
            pass
    zeek = _read_json_safe(os.path.join(run_dir, "run{}_zeek_processing.json".format(run_id))) or {}
    ss = zeek.get("site_script")
    if ss and os.path.exists(ss):
        dst = os.path.join(run_dir, "run{}_local.zeek".format(run_id))
        try:
            shutil.copyfile(ss, dst); copies["site_script"] = os.path.basename(dst)
        except OSError:                                          # pragma: no cover
            pass
    return copies


def _verdict_mismatches(rederived, comp):
    """Compare the RE-DERIVED verdict to what the completion recorded, across the CANONICAL fields (not
    merely overall/official) so a completion edited in ANY of them is caught by --verify [audit v20.32 §13]."""
    out = []
    for k in ("overall", "official", "status_is_diagnostic", "required_missing"):
        if rederived.get(k) != comp.get(k):
            out.append("{} {!r}!={!r}".format(k, comp.get(k), rederived.get(k)))
    re_states = {n: v.get("state") for n, v in (rederived.get("semantics") or {}).items()}
    comp_states = {n: v.get("state") for n, v in (comp.get("semantics") or {}).items()}
    if re_states != comp_states:
        out.append("semantic states {}!={}".format(comp_states, re_states))
    return out


def _verify_bundle_structure(run_dir, run_id, man_path, comp):
    """Open run<N>_bundle.tar.gz and prove it STRUCTURALLY matches the manifest [audit v20.32 §12]. Merely
    re-hashing the outer file (the old check) does not open it, so a bundle whose bytes were swapped for a
    non-TAR — or whose members were tampered — could pass once the completion's recorded hash was updated.
    Here we OPEN the tar and require: no absolute or '..' members (a path-traversal tar), no duplicates,
    no non-file members, the member set EQUALS the manifest inventory (+ the manifest/hashes the finalizer
    adds), and every inventoried member's sha256 recomputed FROM THE TAR equals the manifest. Returns
    (state, note)."""
    bpath = os.path.join(run_dir, (comp.get("bundle") or {}).get("path")
                         or "run{}_bundle.tar.gz".format(run_id))
    if not os.path.exists(bpath):
        return "FAIL", "bundle missing on disk"
    if _sha(bpath) != (comp.get("bundle") or {}).get("sha256"):
        return "FAIL", "bundle sha256 changed"
    manifest = _read_json_safe(man_path) or {}
    inv = {d["path"]: d["sha256"] for d in manifest.get("inventory", [])}
    expected = set(inv) | {"run{}_manifest.json".format(run_id), "run{}_hashes.json".format(run_id)}
    try:
        with tarfile.open(bpath, "r:gz") as tar:
            names = []
            for m in tar.getmembers():
                nm = m.name
                if nm.startswith("/") or os.path.isabs(nm) or ".." in nm.replace("\\", "/").split("/"):
                    return "FAIL", "bundle has unsafe member {!r}".format(nm)
                if not m.isfile():
                    return "FAIL", "bundle has non-file member {!r}".format(nm)
                names.append(nm)
            if len(names) != len(set(names)):
                return "FAIL", "bundle has duplicate members"
            if set(names) != expected:
                miss, extra = sorted(expected - set(names)), sorted(set(names) - expected)
                return "FAIL", "bundle members != manifest (missing {}, extra {})".format(miss, extra)
            for nm, want in inv.items():                        # recompute each member's hash FROM the tar
                fh = tar.extractfile(nm)
                if fh is None:
                    return "FAIL", "bundle member {!r} unreadable".format(nm)
                h = hashlib.sha256()
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
                if h.hexdigest() != want:
                    return "FAIL", "bundle member {!r} hash != manifest".format(nm)

            # (§16) The manifest + hashes carried INSIDE the tar must themselves be AUTHENTIC — not merely
            # present. Extract and validate them, so a bundle handed to a reviewer can't carry a tampered
            # internal manifest/hashes while every data member still looks fine. The internal manifest must
            # be BYTE-identical to the external one (same sha256) which must equal completion.manifest_sha256,
            # and the internal hashes.json must equal the {path: sha256} map derived from the inventory.
            im = tar.extractfile("run{}_manifest.json".format(run_id))
            ih = tar.extractfile("run{}_hashes.json".format(run_id))
            if im is None or ih is None:
                return "FAIL", "bundle missing internal manifest/hashes"
            internal_man_sha = hashlib.sha256(im.read()).hexdigest()
            if internal_man_sha != _sha(man_path):
                return "FAIL", "bundle internal manifest != external manifest"
            if _sha(man_path) != comp.get("manifest_sha256"):
                return "FAIL", "external manifest != completion.manifest_sha256"
            try:
                internal_hashes = json.loads(ih.read().decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return "FAIL", "bundle internal hashes.json is not JSON"
            if internal_hashes != inv:
                return "FAIL", "bundle internal hashes.json != manifest inventory map"
    except (tarfile.TarError, OSError) as exc:
        return "FAIL", "bundle is not a valid tar: {}".format(repr(exc)[:80])
    return "OK", "bundle structure OK"


def _archive_existing_seal(run_dir, run_id):
    """Preserve the PRIOR seal before a --rotate-seal re-finalization, so a weaker re-seal cannot silently
    erase the record of the first attempt [audit v20.33 §18]. The whole prior seal is packed into ONE
    run<N>_prior_seal_<utc>.tar.gz (NOT a directory of loose files): that single archive is a normal file,
    so it enters the NEW inventory and is hash-protected in the new manifest/bundle — you can no longer
    delete the prior completion/manifest/hashes/bundle and have the new seal still verify [audit v20.34 §10]."""
    stamp = runlib.utc_now_iso().replace(":", "").replace("-", "").replace(".", "")
    members = []
    for suffix in ("_completion_status.json", "_manifest.json", "_hashes.json", "_seal_policy.json",
                   "_bundle.tar.gz"):
        src = os.path.join(run_dir, "run{}{}".format(run_id, suffix))
        if os.path.exists(src):
            members.append(src)
    if not members:
        return None
    arc = os.path.join(run_dir, "run{}_prior_seal_{}.tar.gz".format(run_id, stamp))
    with tarfile.open(arc, "w:gz") as tar:
        for m in members:
            tar.add(m, arcname=os.path.basename(m))
    for m in members:                                            # remove the loose originals (now inside arc)
        try:
            os.remove(m)
        except OSError:                                          # pragma: no cover
            pass
    return arc


def finalize(run_dir, run_id, required=None, campaign_path=None, bundle=True, min_packets=0,
             max_drop_rate=None, require_effect=False, diagnostic=False, rotate_seal=False):
    """Do the sealing and return the completion verdict dict (also writes all artifacts).

    OFFICIAL (default) sealing is fail-closed: the four standard artifacts are ALWAYS required (a caller
    can only ADD to them via `required`, never remove them); a SKIP on status/capture/zeek/binding is a
    FAIL; a status that DECLARES itself diagnostic can't back an official seal; and every artifact is BOUND
    to the same run and campaign by content hash [audit v20.30/31 §5-§8]. Weakening the requirement demands
    `diagnostic=True`, recorded as `official=false`. `official` is derived from EVIDENCE, not the CLI flag.

    A run that is ALREADY sealed is NOT re-finalized silently: re-running with a WEAKER policy (e.g. a lower
    --min-packets) would otherwise flip a FAIL seal to PASS by overwriting seal_policy/manifest/hashes/
    completion. Re-finalization requires `rotate_seal=True`, which ARCHIVES the prior seal first so it is
    preserved, not erased [audit v20.33 §18]."""
    completion_path = os.path.join(run_dir, "run{}_completion_status.json".format(run_id))
    if os.path.exists(completion_path):
        if not rotate_seal:
            sys.exit("ABORT: run {} is already sealed (run{}_completion_status.json exists). Re-finalizing "
                     "would OVERWRITE the seal and could RELAX its policy. Pass --rotate-seal to archive the "
                     "existing seal and record a NEW attempt. [audit v20.33 §18]".format(run_id, run_id))
        _archive_existing_seal(run_dir, run_id)
    # §12: FLOOR the capture thresholds against the manifest's capture_quality_policy so the CLI — and any
    # later --rotate-seal — can only TIGHTEN, never relax them [audit v20.35 §12]. The floored values are
    # what get written into the immutable seal_policy and re-derived by --verify.
    _man = _read_json_safe(campaign_path) if campaign_path else None
    _cqp = _man.get("capture_quality_policy") if isinstance(_man, dict) else None
    min_packets, max_drop_rate, require_effect = _effective_capture_thresholds(
        min_packets, max_drop_rate, require_effect, _cqp)
    required_eff = _required_eff(required, diagnostic)
    # Copy the campaign manifest + Zeek site script INTO the run FIRST, so both are inventoried, hashed and
    # bundled — the sealed bundle becomes self-contained evidence [audit v20.32 §14].
    evidence_copies = _copy_external_evidence(run_dir, run_id, campaign_path)
    # Write the IMMUTABLE seal policy, so it is part of the inventory (hash-protected in the manifest).
    # --verify RE-DERIVES the verdict using the thresholds from HERE, not from the editable completion, so
    # editing a threshold in the completion can no longer change the re-derived verdict [audit v20.31 §9].
    # `bundle_written` lets --verify know whether a bundle is REQUIRED to exist (a --no-bundle diagnostic
    # legitimately has none) [audit v20.32 §10].
    policy = {"min_packets": min_packets, "max_drop_rate": max_drop_rate, "require_effect": require_effect,
              "diagnostic_mode": diagnostic, "required": required_eff, "bundle_written": bool(bundle),
              "campaign_sha256": (runlib.sha256_file(campaign_path)
                                  if campaign_path and os.path.exists(campaign_path) else None)}
    runlib.write_json(os.path.join(run_dir, "run{}_seal_policy.json".format(run_id)), policy)

    inv = inventory(run_dir)                                # now INCLUDES seal_policy + evidence copies
    v = _verdict(run_dir, run_id, required_eff, campaign_path, min_packets, max_drop_rate,
                 require_effect, diagnostic)

    man = {"run_id": run_id, "sealed_utc": runlib.utc_now_iso(), "file_count": len(inv), "inventory": inv}
    man_path = os.path.join(run_dir, "run{}_manifest.json".format(run_id))
    runlib.write_json(man_path, man)
    runlib.write_json(os.path.join(run_dir, "run{}_hashes.json".format(run_id)),
                      {d["path"]: d["sha256"] for d in inv})
    completion = {"run_id": run_id, "overall": v["overall"], "official": v["official"],
                  "status_is_diagnostic": v["status_is_diagnostic"], "diagnostic_mode": diagnostic,
                  "sealed_utc": man["sealed_utc"], "required": required_eff,
                  "required_present": v["required_present"], "required_missing": v["required_missing"],
                  "applied_thresholds": {"min_packets": min_packets, "max_drop_rate": max_drop_rate,
                                         "require_effect": require_effect, "campaign": campaign_path},
                  "status_validation": v["status_validation"],
                  "semantics": v["semantics"],             # capture/zeek/binding validated by CONTENT [§5-§8]
                  "evidence_copies": evidence_copies,      # campaign + local.zeek copied INTO the run [§14]
                  "manifest_sha256": runlib.sha256_file(man_path), "bundle": None}

    if bundle:
        # Bundle the run BEFORE writing the completion file so the completion records the bundle hash
        # (the bundle itself excludes the completion file, which references it — no self-reference).
        bundle_path = os.path.join(run_dir, "run{}_bundle.tar.gz".format(run_id))
        with tarfile.open(bundle_path, "w:gz") as tar:
            for item in inv:
                tar.add(os.path.join(run_dir, item["path"]), arcname=item["path"])
            for extra in ("run{}_manifest.json", "run{}_hashes.json"):
                tar.add(os.path.join(run_dir, extra.format(run_id)), arcname=extra.format(run_id))
        completion["bundle"] = {"path": os.path.basename(bundle_path),
                                "sha256": runlib.sha256_file(bundle_path)}
    runlib.write_json(os.path.join(run_dir, "run{}_completion_status.json".format(run_id)), completion)
    return completion


def main(argv=None):
    ap = argparse.ArgumentParser(description="Seal + verify one run ({}).".format(runlib.TOOL_VERSION))
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--campaign", help="manifest to check the status' campaign identity against")
    ap.add_argument("--require", action="append", default=None,
                    help="EXTRA required artifact name (use {n} for the run id; repeatable). In official "
                         "mode this ADDS to the standard PCAP/capture/zeek/status set (never removes it); "
                         "only --diagnostic lets a reduced set be used.")
    ap.add_argument("--diagnostic", action="store_true",
                    help="DIAGNOSTIC seal: allow a reduced --require set and tolerate a SKIP on "
                         "status/capture/zeek. Recorded as official=false so it can't pass as official "
                         "[audit v20.30 §5]")
    ap.add_argument("--no-bundle", action="store_true", help="skip the tar.gz bundle")
    ap.add_argument("--min-packets", type=_nonneg_int, default=0,
                    help="semantic gate: FAIL if the capture recorded fewer packets (0 = off) [§16]")
    ap.add_argument("--max-drop-rate", type=_frac01, default=None,
                    help="semantic gate: FAIL if the capture drop rate exceeds this finite [0,1] fraction [§16]")
    ap.add_argument("--require-effect", action="store_true",
                    help="semantic gate: FAIL if run<N>_service_effect.json is absent [§16]")
    ap.add_argument("--verify", action="store_true",
                    help="re-verify a SEALED run against its run<N>_manifest.json and exit")
    ap.add_argument("--rotate-seal", action="store_true",
                    help="re-finalize a run that is ALREADY sealed: the prior seal is ARCHIVED (not erased) "
                         "and a new attempt is recorded. Without this, re-finalizing an already-sealed run "
                         "is REFUSED so a weaker policy can't silently overwrite a FAIL seal [audit v20.33 §18]")
    args = ap.parse_args(argv)
    runlib.print_banner("finalize_run.py")

    if args.verify:
        rd, rid = args.run_dir, args.run_id
        P = lambda name: os.path.join(rd, name)
        man_path = P("run{}_manifest.json".format(rid))
        if not os.path.exists(man_path):
            sys.exit("ABORT: no {} to verify against.".format(man_path))
        ok, changed = verify(rd, man_path)                          # (1) inventory hashes unchanged
        comp = _read_json_safe(P("run{}_completion_status.json".format(rid)))
        pol = _read_json_safe(P("run{}_seal_policy.json".format(rid)))
        notes, tamper = [], False

        # (§10) the sealing artifacts must ALL still be present. A --verify with the completion, hashes or
        # immutable policy DELETED is TAMPERED, not OK (a deletion is a tamper). The bundle is required
        # only when the SEALED policy says one was produced (a --no-bundle diagnostic legitimately has none).
        for name, pth in (("completion", P("run{}_completion_status.json".format(rid))),
                          ("hashes", P("run{}_hashes.json".format(rid))),
                          ("seal_policy", P("run{}_seal_policy.json".format(rid)))):
            if not os.path.exists(pth):
                tamper = True; notes.append("missing {}".format(name))
        bundle_required = bool((pol or {}).get("bundle_written"))
        canon_bundle = "run{}_bundle.tar.gz".format(rid)
        if bundle_required and not os.path.exists(P(canon_bundle)):
            tamper = True; notes.append("missing bundle (sealed policy required it)")

        # (§11) the manifest must still hash to what the completion sealed (a re-inventoried manifest that
        # dropped a file would otherwise re-derive cleanly against its own smaller inventory).
        man_js = _read_json_safe(man_path) or {}
        if comp is not None:
            real_man = _sha(man_path)
            if comp.get("manifest_sha256") != real_man:
                tamper = True; notes.append("manifest_sha256 {}!={}".format(comp.get("manifest_sha256"), real_man))

        # (§15) run<N>_hashes.json must EQUAL the {path: sha256} map DERIVED from the manifest inventory —
        # not merely EXIST. Editing it to arbitrary content ({"FAKE":"FAKE"}) was previously undetected.
        derived_hashes = {d["path"]: d["sha256"] for d in man_js.get("inventory", [])}
        hashes_js = _read_json_safe(P("run{}_hashes.json".format(rid)))
        if hashes_js is not None and hashes_js != derived_hashes:
            tamper = True; notes.append("hashes.json != manifest-derived hash map")

        # (2/§13) RE-DERIVE the verdict from the IMMUTABLE seal_policy (not the editable completion) and
        # compare the FULL canonical verdict, not merely overall/official. Editing the policy file itself
        # breaks the inventory hash (1).
        if comp is not None:
            src = pol if pol is not None else (comp.get("applied_thresholds") or {})   # prefer immutable policy
            camp = args.campaign or (comp.get("applied_thresholds") or {}).get("campaign")
            diag = src.get("diagnostic_mode", comp.get("diagnostic_mode", False))
            rederived = _verdict(rd, rid, _required_eff(src.get("required"), diag), camp,
                                 src.get("min_packets", 0), src.get("max_drop_rate"),
                                 src.get("require_effect", False), diag)
            mism = _verdict_mismatches(rederived, comp)
            if mism:
                tamper = True; notes.append("verdict mismatch: " + "; ".join(mism))
            else:
                notes.append("verdict OK")
        else:
            tamper = True; notes.append("no completion to re-derive")   # §10: an absent completion is TAMPERED

        # (§12/§14) OPEN the bundle and verify its STRUCTURE whenever the SEALED POLICY says one was written.
        # The decision does NOT depend on the editable completion.bundle field: setting completion.bundle to
        # null previously SKIPPED this check entirely, so a bundle swapped for junk bytes passed. The bundle
        # must exist under its CANONICAL name, the completion must NAME that canonical bundle, and the
        # structural check (members / safety / per-member hashes / internal manifest+hashes) must pass.
        if bundle_required:
            if not (comp and (comp.get("bundle") or {}).get("path") == canon_bundle):
                tamper = True
                notes.append("completion.bundle must name {} (sealed policy wrote a bundle)".format(canon_bundle))
            bstate, bnote = _verify_bundle_structure(rd, rid, man_path, comp or {})
            notes.append(bnote)
            if bstate != "OK":
                tamper = True

        verdict_ok = ok and not tamper
        print("VERIFY {} — inventory:{}; {}".format(
            "OK" if verdict_ok else "TAMPERED", changed or "no changes", "; ".join(notes)))
        return 0 if verdict_ok else 3

    completion = finalize(args.run_dir, args.run_id, args.require,
                          campaign_path=args.campaign, bundle=not args.no_bundle,
                          min_packets=args.min_packets, max_drop_rate=args.max_drop_rate,
                          require_effect=args.require_effect, diagnostic=args.diagnostic,
                          rotate_seal=args.rotate_seal)
    sem = completion.get("semantics", {})
    print("FINALIZE run{} -> {} ({}, missing={}, status={}, capture={}, zeek={})".format(
        args.run_id, completion["overall"], "official" if completion["official"] else "DIAGNOSTIC",
        completion["required_missing"], completion["status_validation"]["state"],
        sem.get("capture", {}).get("state"), sem.get("zeek", {}).get("state")))
    return 0 if completion["overall"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
