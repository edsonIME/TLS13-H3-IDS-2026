#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
label_flows.py  (labeler version: LABELER_CODE_VERSION in versions.py — leak-free ML
output + audit output)
=========================================================

Join Zeek logs into a labeled dataset and write THREE files:

  * <out>                    : ML file. ONLY the common feature schema + label.
                               No identifiers, no timestamp, no metadata. Train
                               the FINAL model on this.
  * <out>_split_ready.csv    : split-ready. run_id + timestamp + common + label,
                               non-ambiguous flows only. Feed THIS to
                               merge_and_split.py / validate / evaluate — it has
                               the timestamp to verify chronology but none of the
                               audit noise. merge_and_split strips run_id/
                               timestamp when writing the final train/test.
  * <out>_audit.csv          : audit file. Everything (uid, ts, raw Zeek fields,
                               matched_event_id / ambiguous / ambiguity_reason)
                               for inspection/debugging only.

WHAT CHANGED vs v2 (addresses the audit)
----------------------------------------
  * Fixes the leakage: the ML file no longer contains `ts`, `matched_event_id`,
    `ambiguous`, `ambiguity_reason`, uid, IPs or raw ports — those live only in
    the audit file [audit 2.1/2.2/2.3].
  * Common feature schema (feature_schema.py) so the ML file matches the
    synthetic generator's columns [audit 7].
  * Overlapping windows: all candidate windows are considered; an EXACT
    protocol+port match wins; only if none matches is the flow ambiguous
    [audit 5].
  * Terminology: the match key is 4-tuple (proto + src IP + dst IP + dst port) +
    time window, with the SOURCE PORT treated as wildcard (attack tools use many
    ephemeral source ports). This is documented honestly, not called a "true
    5-tuple" [audit 3].

USAGE
-----
  python3 label_flows.py --conn conn.log --ssl ssl.log --quic quic.log \
      --annotations annotations.csv --out labeled_run0.csv
"""

import argparse
import csv
import hashlib
import ipaddress
import json
import math
import os
import shlex
import sys
import uuid
from datetime import datetime, timezone

import attack_scenarios as scen         # expected_annotation_semantics per config [audit v20.8 P0-7]
import campaign as camp
import feature_schema as fs
import provenance as prov               # compare labeling policy to the campaign's [audit v20.4 P0-5]
import versions                         # ONE source of truth for producer/schema versions [§11/§15]
import flowmeter_schema as fms          # flowmeter feature set + TCP-only NaN policy

# Attack labels an ANNOTATION may carry = the dataset vocabulary minus BENIGN
# (annotations only describe attacks). Derived from feature_schema so the whole
# pipeline shares ONE label vocabulary [audit 8].
ALLOWED_LABELS = {l for l in fs.ALLOWED_LABELS if l != "BENIGN"}
# The protocol + tool each attack must declare are SOURCED from attack_scenarios (the single
# source of truth the orchestrator's builders also feed), NOT a second local copy — a duplicate
# map here once drifted (DoS stayed tcp after the H3 migration) and broke real labeling. protocol
# and tool do NOT depend on config_id (a DoS is udp under every config; only PortScan's target_port
# varies), so config 0 is a safe probe. An annotation claiming e.g. BruteForce over UDP, or a tool
# outside its family, is still semantically impossible and rejected [audit v20.7 P0-3 / v20.8 P0-8].
def _expected_proto_tool(label):
    """(protocol, tool_basename) the annotation for `label` must declare, from attack_scenarios;
    (None, None) for an unknown label so the caller skips the check."""
    sem = scen.expected_annotation_semantics(0, str(label))
    if not sem:
        return None, None
    return sem.get("protocol"), sem.get("tool")
CODE_VERSION = versions.LABELER_CODE_VERSION            # single source of truth: versions.py
# The status schema id is bumped in versions.py whenever the status JSON SHAPE or its invariants
# change; a policy-enforcing campaign rejects a status without it (old/incomplete) [audit v19 P0-2].
STATUS_SCHEMA_VERSION = versions.STATUS_SCHEMA_VERSION

# Annotation PRODUCER versions the labeler accepts. A capture labeled from an unknown
# scenario/orchestrator version is not officially reproducible, so the labeler records the
# versions in the status and refuses an unsupported one [audit v20.4 §12].
SUPPORTED_SCENARIO_VERSIONS = versions.SUPPORTED_SCENARIO_VERSIONS
SUPPORTED_ORCHESTRATOR_VERSIONS = versions.SUPPORTED_ORCHESTRATOR_VERSIONS


# Raw Zeek numeric fields split by TYPE so the labeler enforces the SAME
# contract the merge enforces later. `duration` is a real interval (fractional
# ok); the rest are COUNTS (packets/bytes) and must be whole numbers — a
# fractional count is corrupt and would make the merge abort AFTER this labeler
# already reported success [audit 4].
_RAW_INTERVAL = ["duration"]
_RAW_COUNTS = ["orig_pkts", "resp_pkts", "orig_ip_bytes",
               "resp_ip_bytes", "orig_bytes", "resp_bytes"]
_RAW_NUMERIC = _RAW_INTERVAL + _RAW_COUNTS
_RAW_PORTS = ["id.orig_p", "id.resp_p"]


def _fraction(value):
    """argparse type: a FINITE number in [0,1]. Rejects nan/inf/out-of-range so a bogus
    gate value can never be written into the status and satisfy the policy [audit v20.3 P0-3]."""
    try:
        x = float(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("expected a number, got {!r}".format(value))
    if not math.isfinite(x) or not (0.0 <= x <= 1.0):
        raise argparse.ArgumentTypeError("expected a finite value in [0,1], got {!r}".format(value))
    return x


def build_labeling_policy(args):
    """The 13-gate labeling policy this run applied — the exact object written into the
    status. Shared so the EARLY campaign check and the status write can never diverge
    [audit v20.4 P0-5]."""
    return {
        "use_failed": bool(args.use_failed),
        "allow_empty": bool(args.allow_empty),
        "ambiguous_policy": args.ambiguous_policy,
        "allow_overlapping_windows": bool(args.allow_overlapping_windows),
        "ignore_annotation_campaign": bool(args.ignore_annotation_campaign),
        "min_matches_per_event": int(args.min_matches_per_event),
        "min_port_coverage": float(args.min_port_coverage),
        "require_ip_bytes": bool(args.require_ip_bytes),
        "require_ssl_log": bool(args.require_ssl_log),
        "require_quic_log": bool(args.require_quic_log),
        "min_ssl_join_rate": float(args.min_ssl_join_rate),
        "min_quic_join_rate": float(args.min_quic_join_rate),
        "window_padding_ms": int(args.window_padding_ms),
    }


def validate_raw_conn(rows):
    """Abort on CORRUPT raw Zeek values BEFORE mapping [audit 11, 4].

    read_zeek_log turns '-'/'(empty)' into None (legitimate missing). Anything
    else present must be sane: numeric fields finite and >= 0; COUNT fields must
    additionally be whole numbers (fractional packets/bytes are impossible and
    would make merge_and_split abort on the COMMON contract while this labeler
    had already published success) [audit 4]; ports integer in 1..65535.
    """
    count_set = set(_RAW_COUNTS)
    for i, c in enumerate(rows, start=2):            # line 1 == header
        for f in _RAW_NUMERIC:
            v = c.get(f)
            if v is None:
                continue
            try:
                x = float(v)
            except (TypeError, ValueError):
                sys.exit("ABORT: conn.log line {} field '{}'='{}' is not numeric "
                         "(corrupt, not missing). [audit 11]".format(i, f, v))
            if not math.isfinite(x):
                sys.exit("ABORT: conn.log line {} field '{}'='{}' is non-finite. "
                         "[audit 11]".format(i, f, v))
            if x < 0:
                sys.exit("ABORT: conn.log line {} field '{}'='{}' is negative. "
                         "[audit 11]".format(i, f, v))
            if f in count_set and x != math.floor(x):   # fractional count = corrupt [audit 4]
                sys.exit("ABORT: conn.log line {} count field '{}'='{}' is not an "
                         "integer; fractional packets/bytes are impossible and the "
                         "merge would reject this later. [audit 4]".format(i, f, v))
        for f in _RAW_PORTS:
            v = c.get(f)
            if v is None:
                continue
            try:
                p = int(v)
            except (TypeError, ValueError):
                sys.exit("ABORT: conn.log line {} port '{}'='{}' is not an integer. "
                         "[audit 11]".format(i, f, v))
            if not (1 <= p <= 65535):
                sys.exit("ABORT: conn.log line {} port '{}'='{}' out of 1-65535. "
                         "[audit 11]".format(i, f, v))


def _valid_num(x):
    """True only if x parses to a FINITE float (not None/''/'BAD'/NaN/inf).

    Used so --require-ip-bytes cannot be fooled by a present-but-invalid value:
    a truthiness test (`not x`) treats 'BAD' as OK, but 'BAD' silently forces the
    payload-bytes fallback downstream [audit 4].
    """
    try:
        return math.isfinite(float(x))
    except (TypeError, ValueError):
        return False
# Core Zeek conn.log fields the labeler cannot work without [audit 10]. IP-byte
# fields are recommended but optional (a warned fallback is allowed) [audit 12].
REQUIRED_CONN = ["ts", "uid", "id.orig_h", "id.resp_h", "id.resp_p", "proto",
                 "duration", "orig_pkts", "resp_pkts"]

# Fields the labeler labels BY: the uid (join key) + the 5-tuple endpoints/proto/port. A row
# where the COLUMN exists but the VALUE is missing (Zeek writes '-' -> None) cannot be honestly
# joined or matched to an attack window, so it is a corrupt capture, not a legit omission [§14].
_CONN_ESSENTIAL = ["uid", "id.orig_h", "id.resp_h", "proto", "id.resp_p"]


def validate_conn_essentials(rows):
    """Abort if any conn.log row is missing an essential value (uid/orig_h/resp_h/proto/resp_p)
    — a flow the labeler cannot honestly join or label [audit v20.5 §14]."""
    bad = []
    for i, c in enumerate(rows, start=2):              # line 1 == header
        miss = [f for f in _CONN_ESSENTIAL if not str(c.get(f) or "").strip()]
        if miss:
            bad.append((i, miss))
            if len(bad) >= 5:
                break
    if bad:
        sys.exit("ABORT: {} conn.log row(s) miss essential value(s) (first: line {} missing {}). "
                 "A flow with no uid/endpoints/proto/port cannot be labeled — fix the capture. "
                 "[audit v20.5 §14]".format(len(bad), bad[0][0], bad[0][1]))


def read_zeek_log(path):
    rows, fields, sep = [], None, "\t"
    if not path:
        return rows
    try:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return rows
    with fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.rstrip("\n")
            if line.startswith("#separator"):
                sep = line.split(" ", 1)[1].encode().decode("unicode_escape")
            elif line.startswith("#fields"):
                fields = line.split(sep)[1:]
            elif line.startswith("#") or not line:
                continue
            elif fields is not None:
                vals = line.split(sep)
                if len(vals) != len(fields):        # truncated/corrupt row [audit 10]
                    sys.exit("ABORT: malformed Zeek row {}:{} — expected {} fields, "
                             "found {}. [audit 10]".format(path, lineno, len(fields), len(vals)))
                rows.append({k: (None if v in ("-", "(empty)") else v)
                             for k, v in zip(fields, vals)})
    return rows


def to_epoch(iso_utc):
    """Parse an ISO-8601 instant to epoch seconds, requiring an explicit timezone.

    A NAIVE timestamp (no 'Z' and no offset) is REJECTED: fromisoformat would
    otherwise treat it as local time, and on a machine set to e.g.
    America/Sao_Paulo the same string would land 3 h away from UTC, silently
    shifting every attack window [audit 11]. The auto-generated pipeline always
    writes 'Z'; this guard protects hand-edited / externally produced files.
    """
    dt = datetime.fromisoformat(iso_utc.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp has no timezone (use 'Z' or '+00:00')")
    return dt.astimezone(timezone.utc).timestamp()


def _finite_ts(x):
    """True if x parses to a finite float (Zeek flow start time)."""
    try:
        return math.isfinite(float(x))
    except (TypeError, ValueError):
        return False


def _bad(path, line, field, value, reason):
    sys.exit("ABORT annotations: {}:{}  field '{}'='{}'  -- {}. "
             "No output written. [audit]".format(path, line, field, value, reason))


def _valid_port_spec(spec):
    try:
        if "-" in spec:
            a, b = spec.split("-", 1)
            a, b = int(a), int(b)
            return 1 <= a <= b <= 65535
        p = int(spec)
        return 1 <= p <= 65535
    except (ValueError, AttributeError):
        return False


def load_annotations(path, use_failed=False):
    """Load AND strictly validate every annotation row; abort on any bad field.

    Returns (windows, file_run_id). file_run_id is the single run_id of the file
    (or None if empty); the file must NOT mix run_ids [audit 2]. Also enforces
    success/return_code coherence and required tool/command [audit 4].
    """
    windows, seen, file_run_ids = [], set(), set()
    with open(path, newline="", encoding="utf-8") as fh:
        for i, r in enumerate(csv.DictReader(fh), start=2):     # line 1 == header
            ev = (r.get("event_id") or "").strip()
            if not ev:
                _bad(path, i, "event_id", ev, "required")
            if ev in seen:
                _bad(path, i, "event_id", ev, "duplicate")
            seen.add(ev)
            rid_raw = (r.get("run_id") or "").strip()
            if not rid_raw.isdigit():
                _bad(path, i, "run_id", rid_raw, "must be a non-negative integer")
            file_run_ids.add(int(rid_raw))
            lab = (r.get("label") or "").strip()
            if lab not in ALLOWED_LABELS:
                _bad(path, i, "label", lab, "not in " + str(sorted(ALLOWED_LABELS)))
            proto = (r.get("protocol") or "").strip().lower()
            if proto not in ("tcp", "udp"):
                _bad(path, i, "protocol", proto, "must be tcp or udp")
            # SEMANTIC coherence: the protocol/tool must actually fit the attack — a BruteForce
            # over UDP, or a scan driven by an unknown tool, is impossible ground truth even if
            # its campaign identity is correct [audit v20.7 P0-3].
            exp_proto, exp_tool = _expected_proto_tool(lab)
            if exp_proto and proto != exp_proto:
                _bad(path, i, "protocol", proto, "{} must be over {} in this testbed".format(
                    lab, exp_proto.upper()))
            tool = os.path.basename((r.get("tool") or "").strip()).lower()
            if exp_tool and tool != exp_tool:
                _bad(path, i, "tool", r.get("tool"),
                     "{} must be driven by '{}' (basename must EQUAL it, got {!r})".format(
                         lab, exp_tool, tool))
            port = (r.get("target_port") or "").strip()
            if not _valid_port_spec(port):
                _bad(path, i, "target_port", port, "invalid port/range (1-65535, a<=b)")
            status = (r.get("status") or "").strip()
            if status not in ("success", "failed"):
                _bad(path, i, "status", status, "must be success or failed")
            try:
                rc = int((r.get("return_code") or "").strip())
            except ValueError:
                _bad(path, i, "return_code", r.get("return_code"), "must be an integer")
            etype = (r.get("error_type") or "").strip()
            if status == "success" and (rc != 0 or etype):
                _bad(path, i, "status", "success", "success requires return_code=0 "
                     "and empty error_type (got rc={}, error_type='{}')".format(rc, etype))
            if status == "failed" and rc == 0 and not etype:
                _bad(path, i, "status", "failed",
                     "failed requires return_code!=0 or a non-empty error_type")
            if not (r.get("tool") or "").strip():
                _bad(path, i, "tool", "", "required")
            if not (r.get("command") or "").strip():
                _bad(path, i, "command", "", "required")
            for ipf in ("attacker_ip", "target_ip"):
                v = (r.get(ipf) or "").strip()
                try:
                    ipaddress.ip_address(v)
                except ValueError:
                    _bad(path, i, ipf, v, "invalid IP address")
            try:
                start, end = to_epoch(r["start_utc"].strip()), to_epoch(r["end_utc"].strip())
            except (KeyError, ValueError, AttributeError):
                _bad(path, i, "start_utc/end_utc", r.get("start_utc"), "unparseable UTC timestamp")
            if not (start < end):
                _bad(path, i, "end_utc", r.get("end_utc"), "end must be strictly after start")

            if not use_failed and status != "success":
                continue
            windows.append({"event_id": ev, "run_id": int(rid_raw), "label": lab,
                            "attacker_ip": r["attacker_ip"].strip(),
                            "target_ip": r["target_ip"].strip(),
                            "protocol": proto, "port_spec": port,
                            "start": start, "end": end})
    if len(file_run_ids) > 1:
        sys.exit("ABORT annotations: file mixes run_ids {} — one capture = one run. "
                 "[audit 2]".format(sorted(file_run_ids)))
    return windows, (next(iter(file_run_ids)) if file_run_ids else None)


def _parse_kv(s):
    """Parse a ';'-separated key=value string (the annotation `parameters` field) into a dict of
    stripped strings. STRICT [audit v20.9 P0-8]: raises ValueError on a DUPLICATE key (so
    `conns=1;conns=500` can no longer let the last value silently win a comparison), an EMPTY key,
    or any non-empty fragment WITHOUT '='. Only truly empty fragments (from a trailing/again ';')
    are skipped. The orchestrator emits a canonical, duplicate-free field, so a manually forged
    contradictory `parameters` is rejected rather than silently collapsed."""
    out = {}
    for frag in str(s or "").split(";"):
        frag = frag.strip()
        if not frag:                                  # tolerate trailing ';' / blank fragments
            continue
        if "=" not in frag:
            raise ValueError("parameters fragment without '=': {!r}".format(frag))
        k, v = frag.split("=", 1)
        k = k.strip()
        if not k:
            raise ValueError("parameters fragment with empty key: {!r}".format(frag))
        if k in out:
            raise ValueError("duplicate parameters key: {!r}".format(k))
        out[k] = v.strip()
    return out


def read_annotation_versions(path, require_per_line=False):
    """Read + validate the producer versions the annotations were made with. Returns
    (scenario_version, orchestrator_version); either is None only if the column is absent.
    Mixed or UNSUPPORTED versions abort — a reproducible run records exactly ONE known
    scenario and orchestrator version [audit v20.4 §12]. With require_per_line (campaign mode),
    EVERY row must carry BOTH non-empty, so a blank line cannot inherit a sibling's version
    [audit v20.5 §12]."""
    scen, orch = set(), set()
    with open(path, newline="", encoding="utf-8") as fh:
        for i, r in enumerate(csv.DictReader(fh), start=2):     # line 1 == header
            s = (r.get("scenario_version") or "").strip()
            o = (r.get("orchestrator_version") or "").strip()
            if require_per_line and (not s or not o):
                sys.exit("ABORT: annotations line {} is missing scenario_version and/or "
                         "orchestrator_version; campaign runs must stamp both on EVERY row. "
                         "[audit v20.5 §12]".format(i))
            if s:
                scen.add(s)
            if o:
                orch.add(o)
    if len(scen) > 1 or len(orch) > 1:
        sys.exit("ABORT: annotations mix producer versions (scenario={}, orchestrator={}); "
                 "one capture = one producer. [audit v20.4 §12]".format(sorted(scen), sorted(orch)))
    sv = next(iter(scen)) if scen else None
    ov = next(iter(orch)) if orch else None
    if sv is not None and sv not in SUPPORTED_SCENARIO_VERSIONS:
        sys.exit("ABORT: annotation scenario_version {!r} is not supported {} — relabel with a "
                 "known scenarios version. [audit v20.4 §12]".format(
                     sv, sorted(SUPPORTED_SCENARIO_VERSIONS)))
    if ov is not None and ov not in SUPPORTED_ORCHESTRATOR_VERSIONS:
        sys.exit("ABORT: annotation orchestrator_version {!r} is not supported {}. "
                 "[audit v20.4 §12]".format(ov, sorted(SUPPORTED_ORCHESTRATOR_VERSIONS)))
    return sv, ov


# Annotation columns that carry campaign identity. If ANY of them is present and
# non-empty, the annotations were produced by a campaign-aware orchestrator and
# MUST be checked against a manifest — otherwise --campaign can be bypassed just
# by omitting the flag, exactly what the documented command used to do [audit 5].
_CAMPAIGN_ANNOTATION_FIELDS = ("campaign_id", "campaign_sha256", "config_id", "split")


def annotations_are_campaign_aware(ann_path):
    """True if the annotations carry any non-empty campaign identity field [audit 5]."""
    try:
        with open(ann_path, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                for fld in _CAMPAIGN_ANNOTATION_FIELDS:
                    if (r.get(fld) or "").strip():
                        return True
    except OSError:
        return False
    return False


def validate_annotations_campaign(ann_path, campaign_path, require_complete_manifest=False):
    """Every annotation row must match the campaign manifest [audit 5]: its config_id and split must
    be what the manifest assigns to that run_id, and its campaign_id / campaign_sha256 must equal the
    manifest's. The EVIDENCE checks that do not need a complete manifest — command_argv presence /
    JSON shape / tool / length / non-flag-like wordlist paths / command==shlex.join(argv) coherence
    and the config-semantics (protocol/port/tool) — run for EVERY campaign annotation, so
    --allow-incomplete-campaign can no longer silently switch them off [audit v20.13 §6]. Only the
    exact per-position argv VALUE comparison and the full `parameters` dict, which need the complete
    manifest (e.g. dos_seconds), are gated on `require_complete_manifest`."""
    manifest = camp.load(campaign_path, require_reproducible=require_complete_manifest)
    m_id, m_sha = str(manifest.get("campaign_id") or ""), _sha256(campaign_path)
    with open(ann_path, newline="", encoding="utf-8") as fh:
        for i, r in enumerate(csv.DictReader(fh), start=2):
            rid = (r.get("run_id") or "").strip()
            try:
                rid_i = int(rid)
            except ValueError:
                continue                              # bad run_id caught by load_annotations
            exp_cfg = camp.config_of_run(manifest, rid_i)
            if exp_cfg is None:
                sys.exit("ABORT: annotations line {}: run_id {} not in the campaign "
                         "manifest. [audit 5]".format(i, rid))
            for fld, exp in (("campaign_id", m_id), ("campaign_sha256", m_sha),
                             ("config_id", str(exp_cfg)),
                             ("split", str(camp.split_of_run(manifest, rid_i)))):
                if (r.get(fld) or "").strip() != str(exp):
                    sys.exit("ABORT: annotations line {}: {}={!r} != campaign {!r}. "
                             "[audit 5]".format(i, fld, (r.get(fld) or "").strip(), exp))
            # If the manifest PINS the target, the ground truth must have hit exactly it — a
            # capture against a different host/IP is not this campaign's run [audit v20.5 §13].
            spec = (manifest.get("runs") or {}).get(str(rid_i)) or {}
            for a_fld, m_fld in (("target_ip", "target_ip"), ("target_hostname", "target_host"),
                                 ("attacker_ip", "attacker_ip")):   # attacker pinned too [P0-4]
                pinned = spec.get(m_fld)
                if pinned not in (None, ""):
                    got = (r.get(a_fld) or "").strip()
                    if got != str(pinned):
                        sys.exit("ABORT: annotations line {}: {}={!r} != campaign run {} {}={!r} "
                                 "(the ground truth used an endpoint the manifest did not pin). "
                                 "[audit v20.5 §13 / v20.7 P0-4]".format(
                                     i, a_fld, got, rid_i, m_fld, pinned))
            # The protocol/port/tool must match what the CONFIG plans for this attack — NOT the
            # annotation's own claim. A PortScan that declares range=443 to fake 100% coverage of
            # the planned 1-{ps_hi} range, or a BruteForce on port 9999, is rejected [P0-7/P0-8].
            exp_sem = scen.expected_annotation_semantics(exp_cfg, (r.get("label") or "").strip())
            if exp_sem is not None:
                got_map = {"protocol": (r.get("protocol") or "").strip().lower(),
                           "target_port": (r.get("target_port") or "").strip(),
                           "tool": os.path.basename((r.get("tool") or "").strip()).lower()}
                for nm, exp in exp_sem.items():
                    if got_map[nm] != exp:
                        sys.exit("ABORT: annotations line {}: {}={!r} != the config_id={} plan for "
                                 "{} (expected {!r}) — coverage/semantics are judged against the "
                                 "PLAN, not the annotation. [audit v20.8 P0-7/P0-8]".format(
                                     i, nm, got_map[nm], exp_cfg, r.get("label"), exp))
            # ---- EVIDENCE checks: run for EVERY campaign annotation (manifest-INDEPENDENT), so
            # --allow-incomplete-campaign cannot silently disable them [audit v20.13 §6]. ----
            lab = (r.get("label") or "").strip()
            cc = scen.expected_command_argv(exp_cfg, lab, spec, (r.get("target_ip") or "").strip(),
                                            (r.get("target_hostname") or "").strip())
            if cc is not None:
                exp_argv, wild = cc
                # A campaign annotation MUST carry the STRUCTURED command_argv (a JSON list) — the
                # lossy `command.split()` is never trusted here [audit v20.12 §7]. Its absence is
                # exactly the forge vector, so it is rejected even under an incomplete manifest.
                argv_raw = str(r.get("command_argv") or "").strip()
                if not argv_raw:
                    sys.exit("ABORT: annotations line {}: a campaign annotation requires command_argv "
                             "(the structured argv evidence); a row without it is not a reproduction. "
                             "[audit v20.12 §7 / v20.13 §6]".format(i))
                try:
                    argv = json.loads(argv_raw)
                    if not (isinstance(argv, list) and all(isinstance(x, str) for x in argv)):
                        raise ValueError("not a list of strings")
                except ValueError:
                    sys.exit("ABORT: annotations line {}: command_argv is not a JSON list of strings: "
                             "{!r}. [audit v20.11 §11]".format(i, argv_raw))
                # tool + argv length are config-determined and do NOT need a complete manifest.
                if not argv or os.path.basename(argv[0]).lower() != os.path.basename(exp_argv[0]).lower():
                    sys.exit("ABORT: annotations line {}: command_argv tool={!r} != {!r} for the "
                             "config_id={} plan of {}. [audit v20.10 P0]".format(
                                 i, (argv[0] if argv else ""), exp_argv[0], exp_cfg, lab))
                if len(argv) != len(exp_argv):
                    sys.exit("ABORT: annotations line {}: command_argv has {} tokens but the "
                             "config_id={} plan of {} has {} — extra/missing tokens are rejected. "
                             "[audit v20.10 P0]".format(i, len(argv), exp_cfg, lab, len(exp_argv)))
                # Wildcard positions are the BruteForce -L/-P wordlist PATHS: require a REAL path —
                # non-empty and NOT flag-like, so `-L -P` (the next option becoming the "path") is
                # rejected [audit v20.12 §9]. Their bytes/existence stay a run_attacks guarantee.
                for j in wild:
                    if not argv[j] or argv[j].startswith("-"):
                        sys.exit("ABORT: annotations line {}: command_argv wordlist path {!r} is empty "
                                 "or looks like a flag — not a valid path. [audit v20.12 §9]".format(
                                     i, argv[j]))
                # The human `command` must be EXACTLY shlex.join(command_argv) — a contradictory pair
                # (e.g. command='echo not-hydra' beside a hydra argv) is not a coherent official
                # artifact [audit v20.13 §9]. `command` is a DERIVED presentation of the argv.
                cmd_txt = str(r.get("command") or "")
                if cmd_txt and cmd_txt != shlex.join(argv):
                    sys.exit("ABORT: annotations line {}: command != shlex.join(command_argv) — the "
                             "human command contradicts the structured argv. "
                             "[audit v20.13 §9]".format(i))
                # The exact per-position VALUE comparison rejects duplicated/foreign/conflicting
                # tokens (`-c 500 -c 1`, `-u https://evil/`, a wrong `-S` host). It needs the COMPLETE
                # manifest (e.g. the DoS -l value = run_spec.dos_seconds), so it is gated below; when
                # the manifest is incomplete the package is marked DIAGNOSTIC instead [§6].
                if require_complete_manifest:
                    if any(j not in wild and argv[j] != exp_argv[j] for j in range(len(exp_argv))):
                        sys.exit("ABORT: annotations line {}: command_argv {!r} != the exact "
                                 "config_id={} argv {!r} for {} — duplicated/extra/foreign/conflicting "
                                 "tokens are rejected. [audit v20.10 P0]".format(
                                     i, argv, exp_cfg, exp_argv, lab))
            # ---- The FULL `parameters` dict must match the plan (needs the complete manifest) ----
            if require_complete_manifest:
                exp_params = scen.expected_scenario_params(exp_cfg, lab, spec)
                if exp_params is not None:
                    try:
                        got_params = _parse_kv(r.get("parameters"))   # STRICT: no dup/empty keys
                    except ValueError as e:
                        sys.exit("ABORT: annotations line {}: malformed parameters ({}). "
                                 "[audit v20.9 P0-8]".format(i, e))
                    if got_params != exp_params:
                        sys.exit("ABORT: annotations line {}: parameters {} != the config_id={} plan "
                                 "{} for {} — the executed intensity/settings do not match the "
                                 "scenario. [audit v20.8 P0-8/P0-9]".format(
                                     i, got_params, exp_cfg, exp_params, r.get("label")))


def port_span(spec):
    """Width of a port spec: 1 for a single port, (b-a+1) for a range."""
    if "-" in spec:
        try:
            a, b = spec.split("-", 1)
            return int(b) - int(a) + 1
        except ValueError:
            return 10 ** 9
    return 1


def port_matches(resp_p, spec):
    if resp_p is None or not spec:
        return False
    try:
        p = int(resp_p)
        if "-" in spec:
            a, b = spec.split("-", 1)
            return int(a) <= p <= int(b)
        return p == int(spec)
    except ValueError:
        return False


def _flow_duration(conn):
    """Flow duration in seconds, or None if absent/invalid (Zeek writes '-' for some flows)."""
    try:
        d = float(conn.get("duration"))
        return d if d >= 0 else None
    except (TypeError, ValueError):
        return None


def _flow_in_window(conn, w, min_overlap):
    """Whether a flow falls inside attack window `w` by TIME [audit v20.19 §18.4].

    Legacy rule (min_overlap is None): the flow's START timestamp is in [start, end] — this misses a
    flow that began just BEFORE the window but was active THROUGH it (false benign), and admits a
    flow that began in the last millisecond but is otherwise OUTSIDE (false attack). Overlap rule
    (min_overlap given): the fraction of the flow interval [start, start+duration] that lies inside
    the window must be >= min_overlap (and strictly positive). A flow with unknown/zero duration
    falls back to the point (start-in-window) rule, so incomplete Zeek durations never crash it."""
    t = float(conn.get("ts"))
    ws, we = w["start"], w["end"]
    if min_overlap is None:
        return ws <= t <= we
    dur = _flow_duration(conn)
    if dur is None or dur <= 0:                        # point flow -> legacy start-in-window
        return ws <= t <= we
    ov = min(t + dur, we) - max(t, ws)                 # overlap of [t,t+dur] with [ws,we]
    return ov > 0 and (ov / dur) >= min_overlap


def classify(conn, windows, min_overlap=None):
    """Return (label, matched_event_id, ambiguous, reason).

    Considers ALL candidate windows (time + endpoints). Among those whose
    protocol+port match, the MOST SPECIFIC one wins (narrowest port range, so a
    single-port BruteForce beats a wide PortScan range that also covers it).
    Only if no candidate matches proto/port is the flow marked ambiguous. `min_overlap` selects the
    time rule (None = legacy start-in-window; a fraction = window-overlap rule) [audit v20.19 §18.4].
    """
    ts = conn.get("ts")
    if ts is None:
        return "BENIGN", "", 0, ""
    t = float(ts)
    orig, resp = conn.get("id.orig_h"), conn.get("id.resp_h")
    proto = (conn.get("proto") or "").lower()
    rport = conn.get("id.resp_p")

    candidates = [w for w in windows
                  if _flow_in_window(conn, w, min_overlap)
                  and orig == w["attacker_ip"] and resp == w["target_ip"]]
    if not candidates:
        return "BENIGN", "", 0, ""
    matches = [w for w in candidates
               if proto == w["protocol"] and port_matches(rport, w["port_spec"])]
    if matches:
        min_span = min(port_span(w["port_spec"]) for w in matches)
        best = [w for w in matches if port_span(w["port_spec"]) == min_span]
        w = best[0]
        if len({b["label"] for b in best}) > 1:            # genuine tie [audit 8.1]
            return (w["label"], w["event_id"], 1,
                    "ambiguous_same_tuple: {} at same proto/port".format(
                        sorted({b["label"] for b in best})))
        return w["label"], w["event_id"], 0, ""
    w = candidates[0]
    # [audit fix] BENIGN must NOT carry a matched_event_id (finalize §7 inverse):
    # this flow fell inside an attack window but is benign (proto/port mismatch).
    # Keep ambiguous=1 (so it is dropped from split-ready) and keep the event id
    # in the REASON text for forensics, but leave matched_event_id empty.
    return ("BENIGN", "", 1,
            "attacker->victim in window {} but proto/port mismatch ({} :{})"
            .format(w["event_id"], proto, rport))


def matching_windows(conn, windows, min_overlap=None):
    """Windows this flow genuinely BELONGS to: time + endpoints AND proto/port all
    match. Returns the list of matching window dicts (possibly several on a tie),
    or [] when nothing matches. Used to count, per attack event, how many flows
    corresponded to it — so a 'success' event that captured ZERO flows (clock/IP/
    port/timing/capture-window bug) can be detected instead of vanishing [audit 2].
    `min_overlap` selects the time rule (must match classify) [audit v20.19 §18.4].
    """
    ts = conn.get("ts")
    try:
        float(ts)
    except (TypeError, ValueError):
        return []
    orig, resp = conn.get("id.orig_h"), conn.get("id.resp_h")
    proto = (conn.get("proto") or "").lower()
    rport = conn.get("id.resp_p")
    return [w for w in windows
            if _flow_in_window(conn, w, min_overlap)
            and orig == w["attacker_ip"] and resp == w["target_ip"]
            and proto == w["protocol"] and port_matches(rport, w["port_spec"])]


def _port_range(spec):
    """(lo, hi) for a port spec ('443' -> (443,443); '1-1024' -> (1,1024))."""
    if "-" in spec:
        a, b = spec.split("-", 1)
        return int(a), int(b)
    p = int(spec)
    return p, p


def overlapping_window_pairs(windows):
    """Pairs of same-run attack windows that intersect in time AND attacker AND
    victim AND protocol AND port range. run_attacks fires attacks SEQUENTIALLY,
    so such an overlap is almost always an annotation/execution error and makes a
    flow ambiguous between two events; refuse it by default [audit 3].
    """
    bad = []
    for i in range(len(windows)):
        for j in range(i + 1, len(windows)):
            a, b = windows[i], windows[j]
            if a["attacker_ip"] != b["attacker_ip"] or a["target_ip"] != b["target_ip"]:
                continue
            if a["protocol"] != b["protocol"]:
                continue
            if not (a["start"] <= b["end"] and b["start"] <= a["end"]):   # time disjoint
                continue
            (alo, ahi), (blo, bhi) = _port_range(a["port_spec"]), _port_range(b["port_spec"])
            if alo <= bhi and blo <= ahi:                                 # ports intersect
                bad.append((a["event_id"], b["event_id"]))
    return bad


CONN_FIELDS = ["ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
               "proto", "service", "duration", "orig_bytes", "resp_bytes",
               "orig_ip_bytes", "resp_ip_bytes",
               "orig_pkts", "resp_pkts", "conn_state"]
SSL_FIELDS = ["version", "cipher", "server_name", "next_protocol", "ja3", "ja3s"]
QUIC_MAP = {"version": "quic_version", "server_name": "quic_sni",
            "client_protocol": "quic_alpn", "history": "quic_history"}
AUDIT_EXTRA = ["dst_port_class", "label", "matched_event_id",
               "ambiguous", "ambiguity_reason"]


def _sha256(path):
    """Return a file's SHA-256, or None if it is absent/unreadable [audit 5].

    Hashes go into the run-status file so a later reader can prove exactly which
    input bytes an attempt consumed (provenance / reproducibility).
    """
    if not path:
        return None
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def write_status(status_out, state, *, attempt_id, start_utc, conn, annotations,
                 input_hashes, ssl=None, quic=None, best_effort=False, **extra):
    """Atomically (over)write the single run-status JSON [audit 5].

    Written with a temp file + os.replace so the status file is never seen
    half-written. Called three ways: 'running' at the very start of an attempt,
    'failed' from main()'s except handler on ANY error (including pre-validation
    aborts), and 'success' only after every output file has been published. The
    caller supplies state-specific fields (outputs_replaced / error / counts) via
    **extra.
    """
    payload = {"attempt_id": attempt_id, "code_version": CODE_VERSION,
               "status_schema_version": STATUS_SCHEMA_VERSION,   # reject old statuses [audit v19 P0-2]
               "status": state, "start_utc": start_utc,
               "inputs": {"conn": conn, "ssl": ssl, "quic": quic,   # all logs, not just conn [audit 6]
                          "annotations": annotations},
               "input_hashes": input_hashes}
    payload.update(extra)
    tmp = status_out + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, allow_nan=False)
        os.replace(tmp, status_out)                  # atomic publish
    except OSError as exc:
        try:
            os.remove(tmp)
        except OSError:
            pass
        # Provenance is not optional for an official run: a status write that fails
        # (e.g. the path is a directory, or the disk is full) must ABORT so outputs
        # are never published without a status [audit 12]. best_effort=True only for
        # the 'failed' write, which is already handling another error.
        if not best_effort:
            raise SystemExit("ABORT: could not write run status to {}: {} [audit 12]".format(
                status_out, exc))


def main():
    ap = argparse.ArgumentParser(description="Label Zeek flows (leak-free ML + audit).")
    ap.add_argument("--conn", required=True)
    ap.add_argument("--ssl")
    ap.add_argument("--quic")
    ap.add_argument("--flowmeter", help="flowmeter.log from zeek-flowmeter (per-flow "
                                        "packet/IAT statistics, joined by uid)")
    ap.add_argument("--require-flowmeter-log", action="store_true",
                    help="abort if flowmeter.log is missing/empty — the enriched feature "
                         "set is not optional in an official run")
    ap.add_argument("--min-flowmeter-join-rate", type=_fraction, default=0.0,
                    help="with --require-flowmeter-log, minimum fraction of flowmeter "
                         "records that join conn.log (expected 1.0: the flowmeter emits "
                         "one row per conn.log flow)")
    ap.add_argument("--annotations", required=True)
    ap.add_argument("--out", default="labeled.csv", help="ML output (clean)")
    ap.add_argument("--audit-out", default=None,
                    help="audit output (default: <out>_audit.csv)")
    ap.add_argument("--use-failed", action="store_true")
    ap.add_argument("--allow-empty", action="store_true",
                    help="proceed even with zero attack windows (label all BENIGN)")
    ap.add_argument("--ambiguous-policy", choices=["drop", "keep"], default="drop",
                    help="ambiguous flows: 'drop' from the ML file (default, avoids "
                         "known label noise) or 'keep' them with their label")
    ap.add_argument("--run-id", type=int, default=None,
                    help="run id for the split-ready file (default: derived from the "
                         "annotations' run_id; must match it if given) [audit 2/3]")
    ap.add_argument("--split-ready-out", default=None,
                    help="split-ready output (default: <out>_split_ready.csv)")
    ap.add_argument("--overwrite", action="store_true",
                    help="replace existing outputs (default: abort if they exist)")
    ap.add_argument("--require-ip-bytes", action="store_true",
                    help="abort if any flow lacks orig/resp_ip_bytes (no byte fallback)")
    ap.add_argument("--require-ssl-log", action="store_true",
                    help="abort if ssl.log is missing/empty — an encrypted-traffic "
                         "collection with no TLS metadata is a silent JA3/plugin "
                         "failure, not a valid campaign [audit 19]")
    ap.add_argument("--require-quic-log", action="store_true",
                    help="abort if quic.log is missing/empty (HTTP/3 metadata) [audit 19]")
    ap.add_argument("--min-ssl-join-rate", type=_fraction, default=0.0,
                    help="with --require-ssl-log, also abort if fewer than this fraction of "
                         "ssl.log records JOIN a conn.log uid (0 => require >=1 join). An "
                         "ssl.log of ANOTHER run has orphan uids and must not satisfy the "
                         "flag [audit 6]")
    ap.add_argument("--min-quic-join-rate", type=_fraction, default=0.0,
                    help="with --require-quic-log, same join-rate gate for quic.log [audit 6]")
    ap.add_argument("--attempt-id", default="",
                    help="use THIS attempt_id in the run status instead of minting a fresh one, so the "
                         "orchestrator can share ONE id across benign/attacks/capture/labeler and the seal "
                         "can bind the benign session log to this attempt [audit v20.43 §6]. Empty = mint "
                         "a uuid (standalone use).")
    ap.add_argument("--campaign", default=None,
                    help="validate every annotation row against a campaign manifest: "
                         "its config_id/split must match the manifest for that run_id, "
                         "and campaign_id/campaign_sha256 must match the manifest [audit 5]")
    ap.add_argument("--ignore-annotation-campaign", action="store_true",
                    help="DIAGNOSTIC: allow campaign-aware annotations to be labeled "
                         "WITHOUT --campaign. By default, if the annotations carry a "
                         "campaign_id/sha/config_id/split, --campaign is REQUIRED so the "
                         "strong check cannot be bypassed by omitting a flag [audit 5]")
    ap.add_argument("--require-reproducible-campaign", action="store_true",
                    help="(now the DEFAULT with --campaign) require a reproducible manifest "
                         "[audit 11]")
    ap.add_argument("--allow-incomplete-campaign", action="store_true",
                    help="opt OUT of the reproducible-manifest requirement that --campaign now "
                         "enforces by default — for dev only; the official merge/validate/"
                         "evaluate load reproducible and will REJECT the run [audit v20.6 §9]")
    ap.add_argument("--min-matches-per-event", type=int, default=1,
                    help="abort if any success attack event has FEWER than N USABLE "
                         "(unambiguous, uniquely-labeled) flows (default 1). Counts "
                         "only flows that actually enter the ML file as this event's "
                         "label — a flow that is dropped as ambiguous does NOT count "
                         "[audit 2/3]. Pass 0 to disable.")
    ap.add_argument("--min-port-coverage", type=_fraction, default=0.0,
                    help="for a PortScan RANGE event, abort if the fraction of the "
                         "planned port range actually probed is below this (0 disables). "
                         "A scan that hit 1 of 4096 ports is not the planned scan [audit 10]")
    ap.add_argument("--window-padding-ms", type=int, default=0,
                    help="widen every attack window by N ms on each side before "
                         "matching, to absorb residual NB3/NB4 clock skew. Base it on "
                         "the largest measured NTP offset, not a guess. [audit 12]")
    ap.add_argument("--min-window-overlap", type=_fraction, default=None,
                    help="use WINDOW-OVERLAP matching instead of the start-in-window rule: a flow "
                         "belongs to an attack window only if the fraction of its [start,start+"
                         "duration] interval inside the window is >= this (0<=f<=1; 0 = ANY strictly "
                         "positive overlap). Fixes long flows that begin just before/after the "
                         "window. A flow with unknown/zero Zeek duration falls back to the "
                         "start-in-window point rule (counted in the status). Default: unset = legacy "
                         "start-in-window. ONE global threshold applies to ALL attacks — the right "
                         "value is attack-specific, so document it [audit v20.19 §18.4 / v20.20 §8]")
    ap.add_argument("--max-duration-fallback-rate", type=_fraction, default=None,
                    help="with --min-window-overlap, the MAX fraction of matched flows that may fall "
                         "back to the start-in-window POINT rule (missing/zero Zeek duration) before "
                         "the run is marked DIAGNOSTIC — an overlap policy that never actually applied "
                         "must not masquerade as official. Default: unset = a DEGENERATE 100%% "
                         "fallback (overlap requested, zero flows used it) is diagnostic [audit v20.21 §11]")
    ap.add_argument("--allow-overlapping-windows", action="store_true",
                    help="do NOT abort when two same-run attack windows intersect in "
                         "time+endpoints+proto+ports (attacks run sequentially, so an "
                         "overlap is normally an annotation error) [audit 3]")
    args = ap.parse_args()
    if args.min_matches_per_event < 0:
        sys.exit("ABORT: --min-matches-per-event must be >= 0.")
    if args.window_padding_ms < 0:
        sys.exit("ABORT: --window-padding-ms must be >= 0.")
    audit_out = args.audit_out or args.out.replace(".csv", "") + "_audit.csv"
    split_ready_out = args.split_ready_out or args.out.replace(".csv", "") + "_split_ready.csv"
    status_out = args.out.replace(".csv", "") + "_run_status.json"

    # Campaign-aware annotations MUST be validated: if the ground truth carries a
    # campaign identity, refuse to label it without a manifest (the strong check
    # can no longer be skipped by omitting --campaign) [audit 5].
    if (not args.campaign and not args.ignore_annotation_campaign
            and annotations_are_campaign_aware(args.annotations)):
        sys.exit("ABORT: the annotations carry campaign identity "
                 "(campaign_id/campaign_sha256/config_id/split) but --campaign was not "
                 "given. Pass --campaign <manifest> so the identity is verified, or "
                 "--ignore-annotation-campaign to label WITHOUT verification (diagnostic "
                 "only). [audit 5]")

    # If the campaign PINS a required labeling policy, the labeler's OWN gates must
    # MEET it BEFORE any work — otherwise it would read/process every log, publish a
    # non-diagnostic SUCCESS, and only the merge would later reject it, wasting the
    # whole run. Fail closed here, at parse time, on any weaker gate [audit v20.4 P0-5].
    if args.campaign:
        _manifest = camp.load(args.campaign)
        _required = _manifest.get("required_labeling_policy")
        if _required:
            _violations = prov.policy_violations(build_labeling_policy(args), _required)
            if _violations:
                _pretty = "; ".join("{}={!r} (campaign requires {!r})".format(f, o, r)
                                    for f, o, r in _violations)
                sys.exit("ABORT: this run's labeling gates do NOT meet the campaign's "
                         "required_labeling_policy: {}. Set the matching flags (e.g. "
                         "--require-ssl-log --min-ssl-join-rate 0.8 --min-quic-join-rate "
                         "0.8) BEFORE labeling so the published status can pass the merge "
                         "[audit v20.4 P0-5].".format(_pretty))
        # §9 [audit v20.21]: if the campaign PINS the temporal window-matching rule, the CLI must MATCH
        # it EXACTLY (pre-registration) — the threshold cannot be tuned after seeing the results.
        if "required_min_window_overlap" in _manifest:
            _pin = _manifest["required_min_window_overlap"]
            if args.min_window_overlap != _pin:
                sys.exit("ABORT: campaign PINS required_min_window_overlap={!r} but this run passed "
                         "--min-window-overlap {!r}. Match the manifest (pre-registered temporal "
                         "policy — no post-hoc tuning). [audit v20.21 §9]".format(
                             _pin, args.min_window_overlap))
        # §11: a pinned fallback ceiling is adopted when the CLI omits it, and the CLI may only TIGHTEN
        # it — a more permissive CLI value is refused, mirroring the duplicate-ceiling rule.
        _pin_fb = _manifest.get("max_duration_fallback_rate")
        if _pin_fb is not None:
            if args.max_duration_fallback_rate is None:
                args.max_duration_fallback_rate = _pin_fb
            elif args.max_duration_fallback_rate > _pin_fb:
                sys.exit("ABORT: --max-duration-fallback-rate {} is MORE PERMISSIVE than the campaign's "
                         "pinned {}. Match or lower it. [audit v20.21 §11]".format(
                             args.max_duration_fallback_rate, _pin_fb))

    # Refuse to run into existing outputs FIRST, before writing any status, so a
    # refusal to start never clobbers a previous run's status file [audit 5/11].
    finals = [args.out, split_ready_out, audit_out]
    existing = [f for f in finals if os.path.exists(f)]
    if existing and not args.overwrite:
        sys.exit("ABORT: output(s) already exist: {}. Pass --overwrite to replace. "
                 "[audit 11]".format(existing))

    # Record the attempt BEFORE any validation, so an abort part-way through is
    # never left looking like the previous clean success [audit 5]. A unique
    # attempt_id plus input hashes make each attempt auditable. The orchestrator
    # SHARES one id across all producers via --attempt-id so the finalizer can
    # bind the benign session log to this attempt [audit v20.43 §6]; standalone
    # use still mints a fresh uuid.
    attempt_id = args.attempt_id or uuid.uuid4().hex
    start_utc = datetime.now(timezone.utc).isoformat()
    input_hashes = {"conn": _sha256(args.conn), "ssl": _sha256(args.ssl),
                    "quic": _sha256(args.quic), "annotations": _sha256(args.annotations)}

    def _status(state, _to_path=None, **extra):
        """Atomically (re)write the run-status JSON with state-correct flags [audit 5].

        outputs_replaced tells the truth: on 'success' it is True only if outputs
        actually existed and were replaced; on 'failed' it is always False and the
        old files are flagged preserved (the atomic write never clobbers them).
        `_to_path` redirects the write to a temp file so the SUCCESS status can be
        published in the SAME atomic set as the CSVs [audit 9].
        """
        base = {"overwriting_existing": bool(existing)}      # the attempt's INTENT
        if state == "success":
            base["outputs_replaced"] = bool(existing)
        elif state == "failed":
            base["outputs_replaced"] = False
            base["previous_outputs_preserved"] = True
        base.update(extra)
        write_status(_to_path or status_out, state, attempt_id=attempt_id,
                     start_utc=start_utc, conn=args.conn, annotations=args.annotations,
                     ssl=args.ssl, quic=args.quic,                     # log paths [audit 6]
                     input_hashes=input_hashes, best_effort=(state == "failed"), **base)

    _status("running")                                # mark the attempt immediately
    try:
        run_labeling(args, audit_out, split_ready_out, _status)
    except BaseException as exc:                       # SystemExit aborts included
        _status("failed", end_utc=datetime.now(timezone.utc).isoformat(),
                error=(str(exc) or repr(exc)))
        raise


def run_labeling(args, audit_out, split_ready_out, status_cb):
    """Join Zeek logs, label them, and publish the three outputs atomically.

    Any exception raised here propagates to main(), which records the attempt as
    'failed'; reaching the end records 'success' via status_cb [audit 5].
    """
    if args.campaign:                                 # every row must match the manifest [audit 5]
        # --allow-incomplete-campaign only relaxes MANIFEST STRUCTURAL completeness (missing
        # target/timeout/…). The command_argv/semantics EVIDENCE is validated either way; and the
        # relaxation is recorded as a diagnostic reason below, so the package can never be official
        # while pretending to be [audit v20.6 §9 / v20.13 §6].
        require_complete_manifest = not args.allow_incomplete_campaign
        validate_annotations_campaign(args.annotations, args.campaign,
                                      require_complete_manifest=require_complete_manifest)
    windows, ann_run_id = load_annotations(args.annotations, args.use_failed)
    ann_scenario_version, ann_orchestrator_version = read_annotation_versions(
        args.annotations, require_per_line=bool(args.campaign))
    # An official (campaign) run must carry KNOWN producer versions, so the status can pin
    # exactly which scenario/orchestrator made the ground truth [audit v20.4 §12].
    if args.campaign and (ann_scenario_version is None or ann_orchestrator_version is None):
        sys.exit("ABORT: campaign-mode annotations must carry scenario_version and "
                 "orchestrator_version (got {!r}/{!r}). [audit v20.4 §12]".format(
                     ann_scenario_version, ann_orchestrator_version))
    ssl_rows = read_zeek_log(args.ssl)                # keep the RAW rows for the join count
    fm_rows = read_zeek_log(args.flowmeter)          # read_zeek_log(None) -> [], so optional
    fm_by_uid = {r.get("uid"): r for r in fm_rows}
    quic_rows = read_zeek_log(args.quic)             # [audit v20.4 §11]
    ssl_by_uid = {r.get("uid"): r for r in ssl_rows} # the lookup can still dedup by uid
    quic_by_uid = {r.get("uid"): r for r in quic_rows}
    conn_rows = read_zeek_log(args.conn)

    # Fail-closed on invalid inputs so a broken capture never looks processed.
    if not conn_rows:
        sys.exit("ABORT: conn.log missing or empty: {} [audit 4.4]".format(args.conn))
    bad_ts = [i for i, c in enumerate(conn_rows, start=2) if not _finite_ts(c.get("ts"))]
    if bad_ts:
        sys.exit("ABORT: {} conn.log row(s) have a missing/invalid ts (first near "
                 "line {}); refusing to write partial output. [audit 5]".format(
                     len(bad_ts), bad_ts[0]))
    missing_conn = [f for f in REQUIRED_CONN if f not in conn_rows[0]]
    if missing_conn:
        sys.exit("ABORT: conn.log is missing required field(s): {} [audit 10]".format(missing_conn))
    validate_raw_conn(conn_rows)                      # reject corrupt raw values [audit 11]
    validate_conn_essentials(conn_rows)               # reject rows missing uid/5-tuple [audit v20.5 §14]
    # A flow falls back to payload bytes if EITHER ip-bytes field is missing OR
    # present-but-invalid ('BAD', NaN, inf). Truthiness alone would miss 'BAD'
    # and let --require-ip-bytes pass while the ML file silently used orig_bytes
    # [audit 4].
    n_ip_fallback = sum(1 for c in conn_rows
                        if not _valid_num(c.get("orig_ip_bytes"))
                        or not _valid_num(c.get("resp_ip_bytes")))
    if n_ip_fallback and args.require_ip_bytes:
        sys.exit("ABORT: {} flow(s) lack valid finite orig/resp_ip_bytes and "
                 "--require-ip-bytes is set. [audit 4/12]".format(n_ip_fallback))
    if not windows and not args.allow_empty:
        sys.exit("ABORT: zero valid attack windows (status=success). Use "
                 "--allow-empty to label everything BENIGN. [audit 4.4]")

    # A require flag must mean the encrypted-metadata log actually BELONGS to this capture,
    # not merely that some file has rows. Compute how many ssl/quic uids JOIN a conn uid;
    # an orphan-only log (another run's ssl.log) has zero joins and must NOT satisfy the
    # flag [audit 6]. These numbers also go into the status for provenance.
    conn_uids = {c.get("uid") for c in conn_rows if c.get("uid")}

    def _join_stats(rows):
        """Count by RAW RECORD (every log line), not by unique uid, so the join_rate is
        literally the fraction of records that join conn.log — matching the CLI/docs — and a
        duplicate-uid log can never inflate the rate by collapsing rows. Every record is
        exactly one of matching / orphan / missing_uid, so the three ALWAYS sum to records
        [audit v20.4 §11]."""
        records = len(rows)
        matching = missing = 0
        for r in rows:
            u = r.get("uid")
            if not u:
                missing += 1                          # a record with no uid can never join
            elif u in conn_uids:
                matching += 1
        orphan = records - matching - missing         # uid present but not in conn.log
        rate = (matching / records) if records else 0.0
        # status join keys: counted per RECORD (line), not unique uid, so the names say so [§15].
        return {"records": records, "records_matching_conn": matching,
                "orphan_records": orphan, "missing_uid_records": missing,
                "join_rate": round(rate, 4)}

    ssl_stats, quic_stats = _join_stats(ssl_rows), _join_stats(quic_rows)
    fm_stats = _join_stats(fm_rows)

    def _require_log(kind, present, stats, want, min_rate):
        if not present or stats["records"] == 0:
            if want:
                sys.exit("ABORT: --require-{0}-log set but {0}.log is missing/empty. A "
                         "modern-encrypted capture with no {1} metadata means the Zeek "
                         "plugin failed. [audit 19]".format(kind, kind.upper()))
            print("WARNING: no {}.log -> that metadata will be empty.".format(kind))
            return
        if want:
            if stats["records_matching_conn"] < 1:
                sys.exit("ABORT: --require-{0}-log set but ZERO {0}.log records join conn.log "
                         "({1} orphan record(s)) — the log belongs to a DIFFERENT capture. "
                         "[audit 6]".format(kind, stats["orphan_records"]))
            if stats["join_rate"] < min_rate:
                sys.exit("ABORT: {0}.log join rate {1:.2f} < --min-{0}-join-rate {2:.2f} "
                         "({3}/{4} records join conn.log). [audit 6]".format(
                             kind, stats["join_rate"], min_rate,
                             stats["records_matching_conn"], stats["records"]))

    _require_log("ssl", bool(args.ssl), ssl_stats, args.require_ssl_log, args.min_ssl_join_rate)
    _require_log("quic", bool(args.quic), quic_stats, args.require_quic_log, args.min_quic_join_rate)
    _require_log("flowmeter", bool(args.flowmeter), fm_stats,
                 args.require_flowmeter_log, args.min_flowmeter_join_rate)

    # Derive run_id from the annotations; the CLI value must MATCH it (never
    # silently override the ground-truth run_id) [audit 2/3].
    if ann_run_id is not None:
        if args.run_id is not None and args.run_id != ann_run_id:
            sys.exit("ABORT: --run-id={} does not match annotations run_id={}. "
                     "[audit 2]".format(args.run_id, ann_run_id))
        effective_run_id = ann_run_id
    else:
        if args.run_id is None:
            sys.exit("ABORT: empty annotations; pass --run-id explicitly. [audit 2]")
        effective_run_id = args.run_id
    if effective_run_id < 0:
        sys.exit("ABORT: run_id must be a non-negative integer. [audit 3]")

    # If the campaign PLANS attacks for this run, the SUCCESS annotations must cover EXACTLY
    # that plan BEFORE we process/publish anything — otherwise the labeler would emit a
    # non-diagnostic 'success' whose events silently miss a planned attack, and only the merge
    # would catch it afterwards (wasting the whole run) [audit v20.4 §8].
    if args.campaign:
        _spec = (camp.load(args.campaign).get("runs") or {}).get(str(effective_run_id)) or {}
        _planned = {str(a) for a in (_spec.get("attacks") or [])}
        if _planned:
            _observed = {str(w["label"]) for w in windows}   # windows are the usable (success) events
            _missing = sorted(_planned - _observed)
            if _missing:
                sys.exit("ABORT: run {} plans attack(s) {} but the annotations cover only {} — a "
                         "planned attack is absent (or exists solely as status=failed). Fix the "
                         "ground truth before labeling. [audit v20.4 §8]".format(
                             effective_run_id, _missing, sorted(_observed)))
            _unplanned = sorted(_observed - _planned)
            if _unplanned:
                sys.exit("ABORT: run {} annotations carry UNPLANNED attack(s) {} not in the "
                         "campaign plan {}. [audit v20.4 §8]".format(
                             effective_run_id, _unplanned, sorted(_planned)))

    # Absorb residual NB3/NB4 clock skew by widening each window symmetrically
    # BEFORE matching / overlap checks [audit 12].
    pad = args.window_padding_ms / 1000.0
    if pad:
        for w in windows:
            w["start"] -= pad
            w["end"] += pad
    # Sequential attacks should never share time+endpoints+proto+ports; an overlap
    # makes flows ambiguous between events -> refuse by default [audit 3].
    if not args.allow_overlapping_windows:
        clashes = overlapping_window_pairs(windows)
        if clashes:
            sys.exit("ABORT: overlapping same-run attack windows {} (time+attacker+"
                     "victim+proto+ports intersect). Attacks run sequentially, so this "
                     "is almost always an annotation error; fix it or pass "
                     "--allow-overlapping-windows. [audit 3]".format(clashes))

    ml_header = fs.EXTENDED + [fs.LABEL]
    sr_header = ["run_id", "timestamp"] + fs.EXTENDED + [fs.LABEL]
    audit_header = ["uid"] + CONN_FIELDS + SSL_FIELDS + list(QUIC_MAP.values()) + AUDIT_EXTRA

    # Build the three outputs as .tmp files first. Per-event match counters are
    # filled during the row loop so a 'success' event that captured zero flows
    # can be caught BEFORE anything is published [audit 2].
    tmp_ml, tmp_sr, tmp_aud = args.out + ".tmp", split_ready_out + ".tmp", audit_out + ".tmp"
    n_attack = n_ambig = n_ml = n_dropped = 0
    # Per-class row counts of the split-ready CSV. Published in the status so a downstream
    # consumer can re-count the CSV and prove status.events actually reflect THIS run's rows
    # (not just the aggregate split) [audit v20.4 §9].
    sr_class_counts = {}
    # event_id -> per-event ground-truth evidence (only for the success windows).
    #   matched_flows : flows whose window+endpoints+proto+port match (may be shared
    #                   with another event on an overlap, and may be ambiguous)
    #   usable_flows  : flows classify() assigns UNAMBIGUOUSLY to THIS event and that
    #                   therefore enter the ML file as this event's label [audit 3]
    #   ambiguous_flows / unique_dst_ports : diagnostics (intensity hint) [audit 11]
    event_stats = {w["event_id"]: {"label": w["label"], "port_spec": w["port_spec"],
                                   "matched_flows": 0, "usable_flows": 0,
                                   "ambiguous_flows": 0, "unique_dst_ports": set(),
                                   # the (padded) attack window, so the status records the time
                                   # bounds and the consumer can check first/last_match ⊂ window
                                   # [audit v20.7]:
                                   "window_start": w["start"], "window_end": w["end"],
                                   "first_match": None, "last_match": None}
                   for w in windows}
    # Overlap-mode accounting [audit v20.20 §8]: how many MATCHED flows had no usable duration and so
    # silently fell back to the start-in-window POINT rule — for those flows the overlap guarantee did
    # NOT actually apply, so the status records the count and a consumer can judge how much of the
    # dataset the overlap policy really governed. Zero in legacy mode (min_window_overlap is None).
    overlap_accounting = {"matched_flows": 0, "duration_fallback_flows": 0}

    def _credit(conn_row, ev, ambiguous):
        """Update per-event counters. `ev`/`ambiguous` come from classify() so the
        UsABLE count reflects exactly what lands in the ML file [audit 3]."""
        mids = matching_windows(conn_row, windows, args.min_window_overlap)
        if not mids:
            return
        t = float(conn_row.get("ts"))
        dur = _flow_duration(conn_row)
        rport = conn_row.get("id.resp_p")
        # In overlap mode, note whether this matched flow actually used the overlap rule or fell back
        # to the point rule because its Zeek duration was missing/zero [audit v20.20 §8].
        ambiguous_here = len({w["label"] for w in mids}) > 1
        if args.min_window_overlap is not None:
            overlap_accounting["matched_flows"] += 1
            # A zero/'unknown'-duration flow uses the point rule. That is only a genuine
            # OVERLAP fallback when the flow is AMBIGUOUS between events (a point can't be
            # apportioned by overlap). A point flow matching a SINGLE window is fully
            # identified by attacker+victim+proto+port+time — a COMPLETE match, not a
            # fallback. SYN scans legitimately emit many zero-duration half-open flows;
            # counting those as fallback misread the scan's natural signature [audit v20.48].
            # A matched flow with zero/missing duration was labeled by the start-in-window
            # POINT rule, not the overlap rule, so the overlap guarantee did NOT govern it and it
            # counts as a duration fallback -- whether or not it is unambiguous. "Unambiguous"
            # concerns label CORRECTNESS; this counter measures overlap-rule COVERAGE, which the
            # provenance gate enforces as a lower bound (>= zero-duration attack rows, audit v20.23
            # §6) and a subset invariant (<= matched_flows, §7). The earlier "and ambiguous_here"
            # understated the count and produced a status the gate rejects [audit v20.49].
            if not (dur and dur > 0):
                overlap_accounting["duration_fallback_flows"] += 1
        for w in mids:
            st = event_stats[w["event_id"]]
            st["matched_flows"] += 1
            if ambiguous_here:
                st["ambiguous_flows"] += 1
            if rport is not None:
                st["unique_dst_ports"].add(str(rport))
            # Record the match time(s) CLAMPED into the (padded) window, so the status invariant
            # window_start <= first_match <= last_match <= window_end HOLDS even when
            # --min-window-overlap admits a flow whose raw START is BEFORE the window — the case the
            # feature exists for. In overlap mode we store the OVERLAP interval; otherwise the legacy
            # point (which is already in-window) [audit v20.20 §7].
            if args.min_window_overlap is not None and dur and dur > 0:
                fmt, lmt = max(t, w["start"]), min(t + dur, w["end"])
            else:
                fmt = lmt = min(max(t, w["start"]), w["end"])
            st["first_match"] = fmt if st["first_match"] is None else min(st["first_match"], fmt)
            st["last_match"] = lmt if st["last_match"] is None else max(st["last_match"], lmt)
        # A flow is USABLE for exactly the ONE event classify() labeled it as, and
        # only when it is unambiguous (so it is the flow written to the ML file).
        if not ambiguous and ev in event_stats:
            event_stats[ev]["usable_flows"] += 1

    written = False
    try:
        with open(tmp_ml, "w", newline="", encoding="utf-8") as fml, \
                open(tmp_sr, "w", newline="", encoding="utf-8") as fsr, \
                open(tmp_aud, "w", newline="", encoding="utf-8") as faud:
            wml, wsr, waud = csv.writer(fml), csv.writer(fsr), csv.writer(faud)
            wml.writerow(ml_header)
            wsr.writerow(sr_header)
            waud.writerow(audit_header)
            for c in conn_rows:
                uid = c.get("uid")
                s = ssl_by_uid.get(uid, {})
                q = quic_by_uid.get(uid, {})
                f = fm_by_uid.get(uid, {})
                label, ev, ambiguous, reason = classify(c, windows, args.min_window_overlap)
                _credit(c, ev, ambiguous)            # per-event match accounting
                n_attack += label != "BENIGN"
                n_ambig += ambiguous
                common = fs.zeek_row_to_common(c, s, q)
                # transport decides applicability: TCP-only measures become NaN on a UDP
                # flow instead of the flowmeter's literal 0, so "no RST on this TCP flow"
                # stays distinguishable from "RST does not exist on UDP".
                common.update(fms.flowmeter_row_to_features(f, common["transport"]))

                arec = {"uid": uid}
                arec.update({k: c.get(k) for k in CONN_FIELDS})
                arec.update({k: s.get(k) for k in SSL_FIELDS})
                arec.update({out: q.get(src) for src, out in QUIC_MAP.items()})
                arec["dst_port_class"] = common["dst_port_class"]
                arec["label"] = label
                arec["matched_event_id"] = ev
                arec["ambiguous"] = ambiguous
                arec["ambiguity_reason"] = reason
                waud.writerow([arec.get(col) for col in audit_header])

                if ambiguous and args.ambiguous_policy == "drop":
                    n_dropped += 1
                    continue
                ml_row = ["" if isinstance(common[k], float) and math.isnan(common[k])
                          else common[k] for k in fs.EXTENDED]
                wml.writerow(ml_row + [label])
                wsr.writerow([effective_run_id, c.get("ts")] + ml_row + [label])
                sr_class_counts[label] = sr_class_counts.get(label, 0) + 1   # [audit v20.4 §9]
                n_ml += 1
        written = True
    finally:
        if not written:
            for t in (tmp_ml, tmp_sr, tmp_aud):      # loop failed: drop temps
                try:
                    os.remove(t)
                except OSError:
                    pass

    # Ground-truth sanity: a success event with too few USABLE flows is almost
    # always a clock/IP/port/timing/capture bug OR an overlap that leaves the
    # attack only in ambiguous flows (which are dropped from ML). Count USABLE
    # (unambiguous, uniquely-labeled) flows, NOT merely matched ones, so an event
    # "validated" only by ambiguous/shared flows still aborts [audit 3]. Refuse
    # BEFORE publishing (clean up temps first) [audit 2].
    if args.min_matches_per_event > 0:
        unusable = {e: st for e, st in event_stats.items()
                    if st["usable_flows"] < args.min_matches_per_event}
        if unusable:
            for t in (tmp_ml, tmp_sr, tmp_aud):
                try:
                    os.remove(t)
                except OSError:
                    pass
            detail = "; ".join(
                "{} ({}) usable={} (matched={}, ambiguous={})".format(
                    e, st["label"], st["usable_flows"], st["matched_flows"],
                    st["ambiguous_flows"]) for e, st in sorted(unusable.items()))
            sys.exit("ABORT: {} attack event(s) have < {} USABLE flow(s) [{}]. An event "
                     "matched only by ambiguous/shared flows contributes NOTHING to the "
                     "ML file, and zero matches usually means a clock/IP/port/timing or "
                     "capture-window bug; the attack would silently vanish. Fix the "
                     "capture/annotations or pass --min-matches-per-event 0. "
                     "[audit 2/3]".format(len(unusable), args.min_matches_per_event, detail))

    # Intensity gate for scans: a PortScan over a RANGE must actually probe enough
    # of it, not just touch one port [audit 10].
    if args.min_port_coverage > 0:
        weak = []
        for e, st in sorted(event_stats.items()):
            span = port_span(st["port_spec"])
            if span > 1:                              # a range == a scan
                cov = len(st["unique_dst_ports"]) / span
                if cov < args.min_port_coverage:
                    weak.append("{} ({}) coverage={:.3f} of {} ports".format(
                        e, st["label"], cov, span))
        if weak:
            for t in (tmp_ml, tmp_sr, tmp_aud):
                try:
                    os.remove(t)
                except OSError:
                    pass
            sys.exit("ABORT: scan event(s) below --min-port-coverage {}: [{}]. The "
                     "planned range was not actually probed. [audit 10]".format(
                         args.min_port_coverage, "; ".join(weak)))

    # Final self-check BEFORE publishing: the COMMON rows we just built must satisfy
    # the SAME numeric/relational CONTRACT the merge and validator enforce. Without
    # this, the labeler could report success while producing a file the official
    # consumer rejects (e.g. a fractional count that slipped past the raw check via a
    # different path) — the exact contradictory state the audit describes [audit 4].
    try:
        import pandas as _pd
        _cerr, _cwarn = fs.common_contract_violations(_pd.read_csv(tmp_sr))
    except ImportError:
        _cerr, _cwarn = [], ["pandas unavailable: COMMON contract self-check skipped "
                             "(the raw integer/finite validation still ran)"]
    for _w in _cwarn:
        print("WARNING (contract):", _w)
    if _cerr:
        for t in (tmp_ml, tmp_sr, tmp_aud):
            try:
                os.remove(t)
            except OSError:
                pass
        sys.exit("ABORT: the labeled COMMON rows violate the official contract {}; "
                 "refusing to publish a file the merge would reject. [audit 4]".format(_cerr))

    # Campaign identity for the status sidecar so the merge can AUTHENTICATE this
    # split-ready file against the manifest later (not just trust its run_id) [audit 6].
    camp_meta = {}
    if args.campaign:
        _m = camp.load(args.campaign)
        camp_meta = {"campaign_id": str(_m.get("campaign_id") or ""),
                     "campaign_sha256": _sha256(args.campaign),
                     "config_id": camp.config_of_run(_m, effective_run_id),
                     "split": camp.split_of_run(_m, effective_run_id)}

    # Record HOW the file was labeled so a downstream consumer can tell an official run
    # from a diagnostic one instead of trusting a bare "success". `diagnostic` is True if
    # ANY methodology gate was LOOSENED (e.g. --use-failed labels tool-failed events);
    # merge/validate/evaluate reject a diagnostic status under --require-status [audit 5].
    labeling_policy = build_labeling_policy(args)
    # status/v5: NAME every reason the run is diagnostic in `diagnostic_reasons`, and set
    # `diagnostic` = (that list is non-empty). The loosenable policy gates use their gate-key names
    # (so validate_status_v5 can prove no loosened gate is hidden); --allow-incomplete-campaign is a
    # non-policy reason that v3 could not record — which is exactly why an --allow-incomplete run
    # produced a self-contradictory v3 status [audit v20.13 §6 / v20.14 §5].
    diagnostic_reasons = []
    if args.use_failed:                      diagnostic_reasons.append("use_failed")
    if args.allow_empty:                     diagnostic_reasons.append("allow_empty")
    if args.ambiguous_policy != "drop":      diagnostic_reasons.append("ambiguous_policy")
    if args.allow_overlapping_windows:       diagnostic_reasons.append("allow_overlapping_windows")
    if args.ignore_annotation_campaign:      diagnostic_reasons.append("ignore_annotation_campaign")
    if args.min_matches_per_event == 0:      diagnostic_reasons.append("min_matches_per_event")
    if args.campaign and args.allow_incomplete_campaign:
        diagnostic_reasons.append("allow_incomplete_campaign")
    # §11 [audit v20.21]: in overlap mode, a flow with no usable duration falls back to the legacy
    # point rule, so the overlap guarantee did NOT apply to it. If the fallback DOMINATES (100% by
    # default, or above a pinned --max-duration-fallback-rate) the run is DIAGNOSTIC — an overlap
    # policy that never actually applied cannot masquerade as an official overlap-labeled dataset.
    if args.min_window_overlap is not None and overlap_accounting["matched_flows"] > 0:
        _fb = overlap_accounting["duration_fallback_flows"]
        _m = overlap_accounting["matched_flows"]
        _ceil = args.max_duration_fallback_rate
        if (_ceil is None and _fb == _m) or (_ceil is not None and (_fb / _m) > _ceil):
            diagnostic_reasons.append("overlap_duration_fallback")
    diagnostic_reasons = sorted(set(diagnostic_reasons))
    diagnostic = bool(diagnostic_reasons)

    # Build the SUCCESS status into a temp and publish ALL FOUR artifacts (ML,
    # split-ready, audit, status) as ONE atomic set with rollback. Output hashes are
    # computed on the TEMPS (identical bytes to the finals after os.replace), so the
    # status can never end up stale after the CSVs are already published [audit 9].
    status_out = args.out.replace(".csv", "") + "_run_status.json"
    status_tmp = status_out + ".tmp"
    out_hashes = {"ml": _sha256(tmp_ml), "split_ready": _sha256(tmp_sr),
                  "audit": _sha256(tmp_aud)}
    # split_ready_sha256 is the ANCHOR the merge re-computes on its input to prove the
    # CSV it received is exactly the one this labeler published for this run [audit 6].
    status_cb("success", _to_path=status_tmp, run_id=effective_run_id,   # [audit 5/9/11]
              end_utc=datetime.now(timezone.utc).isoformat(),
              split_ready_sha256=out_hashes["split_ready"], **camp_meta,
              labeling_policy=labeling_policy, diagnostic=diagnostic,     # [audit 5]
              diagnostic_reasons=diagnostic_reasons,                      # status/v5 [v20.14 §5]
              min_window_overlap=args.min_window_overlap,                 # None=legacy [v20.19 §18.4]
              overlap_accounting=overlap_accounting,                      # fallback audit [v20.20 §8]
              ssl_join=ssl_stats, quic_join=quic_stats, flowmeter_join=fm_stats,                   # [audit 6]
              flows_written_ml=n_ml, flows_dropped_ambiguous=n_dropped,
              flows_audit=len(conn_rows), ip_bytes_fallback=n_ip_fallback,
              events={e: {"label": st["label"], "usable_flows": st["usable_flows"],
                          "matched_flows": st["matched_flows"],
                          "ambiguous_flows": st["ambiguous_flows"],
                          "unique_dst_ports": len(st["unique_dst_ports"]),
                          # For a scan RANGE, how much of the planned range was actually
                          # probed = intensity evidence, not just "some flow" [audit 15].
                          "port_range_width": port_span(st["port_spec"]),
                          "port_coverage": round(len(st["unique_dst_ports"])
                                                 / max(port_span(st["port_spec"]), 1), 4),
                          "window_start": st["window_start"], "window_end": st["window_end"],
                          "first_match": st["first_match"], "last_match": st["last_match"]}
                      for e, st in event_stats.items()},
              files={"ml": args.out, "split_ready": split_ready_out, "audit": audit_out},
              output_hashes=out_hashes,
              # Per-class row counts of the split-ready CSV, so a consumer can re-count the
              # file and prove the events reflect THIS run's rows [audit v20.4 §9].
              class_counts_split_ready=sr_class_counts,
              # Pin the producer versions so the run is reproducible [audit v20.4 §12].
              annotation_scenario_version=ann_scenario_version,
              annotation_orchestrator_version=ann_orchestrator_version)

    finals_temps = [(args.out, tmp_ml), (split_ready_out, tmp_sr),
                    (audit_out, tmp_aud), (status_out, status_tmp)]
    backups, published, publish_ok = {}, [], False
    try:
        for final, _t in finals_temps:
            if os.path.exists(final):
                bak = final + ".bak"
                os.replace(final, bak)               # move existing aside
                backups[final] = bak
        for final, tmp in finals_temps:
            os.replace(tmp, final)                    # publish the whole set
            published.append(final)
        publish_ok = True
    finally:
        if not publish_ok:                           # roll the whole SET back
            for p in published:
                try:
                    os.remove(p)
                except OSError:
                    pass
            for final, bak in backups.items():
                try:
                    os.replace(bak, final)           # restore the previous file
                except OSError:
                    pass
            for _f, tmp in finals_temps:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
        else:
            for bak in backups.values():             # success: drop the backups
                try:
                    os.remove(bak)
                except OSError:
                    pass

    print("ML file     :", args.out, "(common + label; train the final model)")
    print("Split-ready :", split_ready_out,
          "(run_id+timestamp+common+label; feed THIS to merge_and_split)")
    print("Audit file  :", audit_out, "(everything; inspection only)")
    print("Run status  :", args.out.replace(".csv", "") + "_run_status.json")
    print("IP-bytes fallback used in {}/{} flows ({:.1%}) [audit 12]".format(
        n_ip_fallback, len(conn_rows), n_ip_fallback / max(len(conn_rows), 1)))
    print("flows_written_ml:", n_ml, "| dropped_ambiguous:", n_dropped,
          "| audit:", len(conn_rows))
    print("attack / benign :", n_attack, "/", len(conn_rows) - n_attack,
          "| ambiguous:", n_ambig)
    if event_stats:
        print("Per-event ground-truth sanity (usable = enters ML) [audit 2/3]:")
        for e, st in sorted(event_stats.items()):
            print("  {} {:<10} usable={} matched={} ambiguous={} dst_ports={}".format(
                e, st["label"], st["usable_flows"], st["matched_flows"],
                st["ambiguous_flows"], len(st["unique_dst_ports"])))
    print("Windows used:", len(windows), "(status=success only)")


if __name__ == "__main__":
    main()
