#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
provenance.py — ONE shared campaign-authentication chain for every official
consumer (merge / validate / evaluate) [audit 9].

Before this module the merge could authenticate inputs against a campaign but the
validator and the realism evaluator could not, so a dataset unrelated to a manifest
still passed them. Worse, the merge trusted the status' run_id without checking it
against the run_id actually INSIDE the CSV, so a swapped sidecar (CSV of run 0 with a
status claiming run 1) authenticated cleanly [audit 4]. This module centralizes the
whole chain so all three tools enforce exactly the same thing:

    CSV bytes  --sha256-->  status.split_ready_sha256          (right file)   [audit 6]
    CSV run_id column       == status.run_id AND is a SINGLE run (right run)  [audit 4]
    status.campaign_id/sha/config_id/split == manifest         (right campaign)
    status.diagnostic is False (unless explicitly allowed)     (official run) [audit 5]
    the authenticated runs cover the campaign runs EXACTLY once (complete)    [audit 4]

Every check raises SystemExit with an [audit N] message, so a failure is a hard,
auditable abort — never a silent pass.

TERMINOLOGY [audit v20 §15]: this is INTEGRITY / PROVENANCE VERIFICATION via SHA-256,
NOT cryptographic authentication. It reliably catches a swapped sidecar, a wrong/edited
file, corruption, or an internal inconsistency; it does NOT stop an adversary who can
edit the CSV, the status AND the manifest together and recompute every hash. For a
stronger guarantee, sign the manifest/sidecars and publish the hashes in an immutable,
read-only release (e.g. a signed Git tag).
"""

import hashlib
import json
import math
import os
import sys

import feature_schema as fs                 # ONE label vocabulary across the pipeline [audit 8]
import versions                             # ONE source of truth for producer/schema versions [§11/§15]

# Attack labels a status event may carry (the dataset vocabulary minus BENIGN) [audit v20.4 §10].
_ATTACK_LABELS = frozenset(fs.ALLOWED_LABELS) - {"BENIGN"}

# A run is DIAGNOSTIC if the labeler LOOSENED any methodology gate. The labeler writes
# these into status["labeling_policy"] and a top-level status["diagnostic"] boolean;
# we re-derive here too so an OLD/edited status without the boolean is still judged by
# its policy [audit 5]. (Hardening flags like require_ssl_log are recorded for
# provenance but their ABSENCE is not, by itself, "diagnostic".)
_LOOSENING = {
    "use_failed": (lambda v: v is True),
    "allow_empty": (lambda v: v is True),
    "ambiguous_policy": (lambda v: v not in (None, "drop")),
    "allow_overlapping_windows": (lambda v: v is True),
    "ignore_annotation_campaign": (lambda v: v is True),
    "min_matches_per_event": (lambda v: v == 0),          # gate disabled
}


def sha256(path):
    """SHA-256 of a file, or None if unreadable."""
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


def csv_run_ids(path):
    """Return the sorted set of DISTINCT run_id values in a split-ready CSV [audit 4].

    Reads only the run_id column so it stays cheap. A file with no run_id column, or a
    non-integer/negative run_id, is a hard error — a split-ready file always carries a
    clean run_id.
    """
    import pandas as pd
    try:
        col = pd.read_csv(path, usecols=["run_id"])["run_id"]
    except (ValueError, KeyError):
        sys.exit("ABORT: '{}' has no 'run_id' column; cannot bind it to a run. "
                 "[audit 4]".format(path))
    nums = pd.to_numeric(col, errors="coerce")
    if nums.isna().any() or (nums != nums.round()).any() or (nums < 0).any():
        sys.exit("ABORT: '{}' has a missing/non-integer/negative run_id. [audit 4]".format(path))
    return sorted({int(v) for v in nums.unique()})


def attack_rows_needing_fallback(path):
    """Count ATTACK rows (label != BENIGN) in a split-ready CSV whose flow_duration is missing or <= 0
    [audit v20.23 §6]. In OVERLAP mode such a flow CANNOT be matched by the overlap rule (which needs a
    positive duration) and MUST have used the legacy start-in-window POINT fallback — so it is a lower
    bound the status' duration_fallback_flows must respect. Returns None if the columns are absent."""
    import pandas as pd
    try:
        df = pd.read_csv(path, usecols=["label", "flow_duration"])
    except (ValueError, KeyError):
        return None
    dur = pd.to_numeric(df["flow_duration"], errors="coerce")
    is_attack = df["label"].astype(str) != "BENIGN"
    return int((is_attack & (dur.isna() | (dur <= 0))).sum())


def attack_rows_off_window(path, events, min_window_overlap):
    """Count attack rows that match NO event window OF THEIR OWN CLASS under the SAME rule the labeler
    used [audit v20.25 §5/§6/§7]. Three properties the earlier hull check lacked:
      §5 each window is tested INDIVIDUALLY (not against a single min-start..max-end envelope), so a
         flow that falls in the GAP between two disjoint windows is caught;
      §6 windows are grouped BY LABEL — a DoS flow must fall in a DoS window, not a PortScan one;
      §7 in overlap mode the overlap FRACTION (overlap/flow_duration) must reach min_window_overlap, so
         a flow that merely TOUCHES a window is rejected; a zero/absent-duration flow falls back to the
         start-in-window POINT rule (exactly the labeler's fallback).
    Returns (n_off, n_attack), or (None, None) if the timestamp/duration/label columns or windows are
    absent (can't verify)."""
    import numpy as np
    import pandas as pd
    by_label = {}
    for e in (events or {}).values():
        if isinstance(e, dict) and e.get("window_start") is not None and e.get("window_end") is not None:
            by_label.setdefault(str(e.get("label")), []).append(
                (float(e["window_start"]), float(e["window_end"])))
    if not by_label:
        return None, None
    try:
        df = pd.read_csv(path, usecols=["label", "timestamp", "flow_duration"])
    except (ValueError, KeyError):
        return None, None
    atk = df[df["label"].astype(str) != "BENIGN"]
    if not len(atk):
        return 0, 0
    lab = atk["label"].astype(str).to_numpy()
    ts = pd.to_numeric(atk["timestamp"], errors="coerce").to_numpy(dtype=float)
    dur = pd.to_numeric(atk["flow_duration"], errors="coerce").to_numpy(dtype=float)
    has_dur = np.isfinite(dur) & (dur > 0)
    safe_dur = np.where(has_dur, dur, 1.0)                 # avoid /0; the frac branch is masked to has_dur
    matched = np.zeros(len(atk), dtype=bool)
    for lb, wins in by_label.items():
        sel = (lab == lb) & np.isfinite(ts)               # rows of THIS class with a finite timestamp
        for ws, we in wins:
            point = sel & (ts >= ws) & (ts <= we)         # start-in-window (legacy / fallback)
            if min_window_overlap is None:
                matched |= point
            else:
                ov = np.minimum(ts + safe_dur, we) - np.maximum(ts, ws)
                frac_ok = sel & has_dur & (ov > 0) & ((ov / safe_dur) >= min_window_overlap)
                matched |= frac_ok | (sel & ~has_dur & point)   # dur<=0 -> point fallback
    return int((~matched).sum()), int(len(atk))


# Statuses the tooling understands; a status_schema_version outside this set is rejected
# (old / future / invented), not treated as current [audit v20 P0-11]. Sourced from versions.py
# so the schema id bumps in exactly one place (now status/v5) [audit v20.5 §15].
SUPPORTED_STATUS_SCHEMAS = versions.SUPPORTED_STATUS_SCHEMAS

# The COMPLETE set of gates an OFFICIAL required_labeling_policy must pin. A partial policy
# (e.g. only {"use_failed": false}) leaves the other gates unconstrained and is NOT official
# [audit v20.2 P0-4]. A campaign either lists EXACTLY these fields, or names a versioned
# profile below that expands to them.
OFFICIAL_POLICY_FIELDS = frozenset({
    "use_failed", "allow_empty", "ambiguous_policy", "allow_overlapping_windows",
    "ignore_annotation_campaign", "min_matches_per_event", "min_port_coverage",
    "require_ip_bytes", "require_ssl_log", "require_quic_log", "min_ssl_join_rate",
    "min_quic_join_rate", "window_padding_ms",
})

# Versioned strict profiles: required_policy_profile: "official/v1" expands to this exact
# policy, so a manifest need not spell out all 13 fields to be official [audit v20.2 P0-4].
OFFICIAL_POLICY_PROFILES = {
    "official/v1": {
        "use_failed": False, "allow_empty": False, "ambiguous_policy": "drop",
        "allow_overlapping_windows": False, "ignore_annotation_campaign": False,
        "min_matches_per_event": 1, "min_port_coverage": 0.8, "require_ip_bytes": True,
        "require_ssl_log": True, "require_quic_log": True, "min_ssl_join_rate": 0.8,
        "min_quic_join_rate": 0.8, "window_padding_ms": 0,
    },
}

# Policy fields where a HIGHER value is STRICTER, so the observed run must be >= the
# campaign's requirement [audit v19 P0-2]. window_padding_ms is NOT here: a WIDER window
# is not "stricter" — it can pull in benign traffic before/after the attack and raise
# label noise, so it is a CEILING (observed <= required), not a floor [audit v20 P0-10].
_POLICY_GE = {"min_port_coverage", "min_ssl_join_rate", "min_quic_join_rate",
              "min_matches_per_event"}
_POLICY_LE = {"window_padding_ms"}


_POLICY_BOOL = {"use_failed", "allow_empty", "allow_overlapping_windows",
                "ignore_annotation_campaign", "require_ip_bytes", "require_ssl_log",
                "require_quic_log"}
_POLICY_FRAC = {"min_port_coverage", "min_ssl_join_rate", "min_quic_join_rate"}
_POLICY_INT = {"min_matches_per_event", "window_padding_ms"}


def validate_observed_labeling_policy(label, policy):
    """Abort unless `policy` is a WELL-FORMED complete labeling policy [audit v20.3 P0-3].

    This is what stops NaN/Infinity and Python's 1==True / 0==False type-punning from
    satisfying a gate: booleans must be real bools (not 1/0), fractions must be FINITE in
    [0,1], the two counters must be real ints (not bools), ambiguous_policy in {drop,keep},
    and the field set must be EXACTLY the 13 official gates — no missing, no extra.
    """
    if not isinstance(policy, dict):
        sys.exit("ABORT: '{}' labeling_policy is not an object. [audit v20.3 P0-3]".format(label))
    keys = set(policy)
    if keys != set(OFFICIAL_POLICY_FIELDS):
        sys.exit("ABORT: '{}' labeling_policy fields {} != the 13 official gates {}. "
                 "[audit v20.3 P0-3]".format(label, sorted(keys), sorted(OFFICIAL_POLICY_FIELDS)))
    for k, v in policy.items():
        if k == "ambiguous_policy":
            if v not in ("drop", "keep"):
                sys.exit("ABORT: '{}' labeling_policy.ambiguous_policy={!r} not in "
                         "{{drop,keep}}. [audit v20.3 P0-3]".format(label, v))
        elif k in _POLICY_BOOL:
            if type(v) is not bool:                       # reject 1/0 masquerading as bool
                sys.exit("ABORT: '{}' labeling_policy.{} must be a real boolean, got {!r}. "
                         "[audit v20.3 P0-3]".format(label, k, v))
        elif k in _POLICY_FRAC:
            if (type(v) is bool or not isinstance(v, (int, float))
                    or not math.isfinite(v) or not (0.0 <= v <= 1.0)):
                sys.exit("ABORT: '{}' labeling_policy.{}={!r} must be a FINITE number in "
                         "[0,1]. [audit v20.3 P0-3]".format(label, k, v))
        elif k in _POLICY_INT:
            if type(v) is not int or v < 0:               # bool is not int here
                sys.exit("ABORT: '{}' labeling_policy.{}={!r} must be a non-negative "
                         "integer. [audit v20.3 P0-3]".format(label, k, v))


def policy_violations(observed, required):
    """Return [(field, observed, requirement)] where the observed labeling policy does NOT
    MEET the campaign's required policy [audit v19 P0-2]. Numeric gates use >= for floors and
    <= for the window-padding ceiling [audit v20 P0-10]; the rest must match EXACTLY. A
    NON-FINITE or non-numeric observed value is always a violation [audit v20.3 P0-3].
    """
    observed = observed or {}

    def _num(x):
        try:
            f = float(x)
            return f if math.isfinite(f) else None
        except (TypeError, ValueError):
            return None

    viol = []
    for k, req in (required or {}).items():
        obs = observed.get(k)
        if k in _POLICY_GE:
            fo = _num(obs)
            if fo is None or fo < float(req):
                viol.append((k, obs, ">= {}".format(req)))
        elif k in _POLICY_LE:
            fo = _num(obs)
            if fo is None or fo > float(req):
                viol.append((k, obs, "<= {}".format(req)))
        elif obs != req or type(obs) is not type(req):    # exact value AND type (no 1==True)
            viol.append((k, obs, req))
    return viol


def require_official_policy(manifest, allow_missing=False):
    """OFFICIAL mode (a --require-status run) must go against a manifest that DECLARES its
    required_labeling_policy — otherwise a run made with weak gates is accepted just because
    the manifest forgot to demand strong ones [audit v20 P0-9]. Opt out with allow_missing."""
    if not (manifest or {}).get("required_labeling_policy") and not allow_missing:
        sys.exit("ABORT: official mode (--require-status) needs the campaign to declare a "
                 "required_labeling_policy; without it a weak-policy run passes silently. "
                 "Add the policy, or pass --allow-missing-required-policy (diagnostic). "
                 "[audit v20 P0-9]")


def enforce_status_schema(label, status_json):
    """Validate a sidecar's status_schema_version WHENEVER the sidecar is used — before
    identity, hashes or policy, and REGARDLESS of whether the campaign declares a policy
    [audit v20.2 P0-10]. An absent/old/future/invented version is a hard abort."""
    sv = str(status_json.get("status_schema_version") or "").strip()
    if not sv:
        sys.exit("ABORT: status for '{}' has no status_schema_version; refusing an old/"
                 "incomplete status. [audit v20.2 P0-10]".format(label))
    if sv not in SUPPORTED_STATUS_SCHEMAS:
        sys.exit("ABORT: status for '{}' has status_schema_version={!r}, not one of {} — "
                 "refusing an unknown/old/future schema. [audit v20 P0-11]".format(
                     label, sv, sorted(SUPPORTED_STATUS_SCHEMAS)))


def _finite_num(x):
    try:
        f = float(x)
        return f if math.isfinite(f) else None
    except (TypeError, ValueError):
        return None


def validate_status_v5(label, js, require_campaign_fields=True):
    """Full structural + INVARIANT check that a status/v5 sidecar actually FOLLOWS the v4
    schema and its OWN evidence confirms the gates its policy claims [audit v20.3 P0-4].

    A label can no longer claim require_ssl_log=true while ssl_join shows zero joined
    uids, or claim a min_port_coverage while a scan event covered 1%. The status is
    internally CONSISTENT, or it aborts. v4 adds `diagnostic_reasons`: `diagnostic` must equal
    (that list is non-empty), and every LOOSENED policy gate must appear in it — but the list may
    ALSO carry a recognised non-policy reason such as `allow_incomplete_campaign`, which v3 could
    not express, so an --allow-incomplete-campaign status is now VALID (and merely diagnostic)
    instead of self-contradictory [audit v20.14 §5].
    """
    # A SUCCESS status/v5 must carry the full set the labeler always produces — an official
    # run cannot omit its hashes/counts/files [audit v20.4 P0-9].
    need = ["attempt_id", "code_version", "status", "run_id", "split_ready_sha256",
            "labeling_policy", "events", "ssl_join", "quic_join", "ip_bytes_fallback",
            "diagnostic", "diagnostic_reasons", "input_hashes", "output_hashes", "files",
            "flows_written_ml", "flows_audit", "flows_dropped_ambiguous", "class_counts_split_ready",
            "annotation_scenario_version", "annotation_orchestrator_version",
            # v27 window-matching fields — REQUIRED so a status can't omit them and sail through as
            # official (cross-run equality alone can't catch two runs sharing the same bogus/absent
            # field) [audit v20.21 §7]:
            "min_window_overlap", "overlap_accounting"]
    if require_campaign_fields:
        need += ["campaign_id", "campaign_sha256", "config_id", "split"]
    missing = [k for k in need if k not in js]
    if missing:
        sys.exit("ABORT: '{}' status/v5 is missing field(s) {}. [audit v20.4 P0-9]".format(
            label, missing))
    if js.get("status") != "success":
        sys.exit("ABORT: '{}' status must be 'success'. [audit v20.4 P0-9]".format(label))

    def _req_str(k, hexlen=None):
        v = js.get(k)
        if not isinstance(v, str) or not v:
            sys.exit("ABORT: '{}' status.{} must be a non-empty string. [audit v20.4 P0-9]".format(label, k))
        if hexlen is not None and (len(v) != hexlen or any(c not in "0123456789abcdef" for c in v.lower())):
            sys.exit("ABORT: '{}' status.{}={!r} is not {}-hex. [audit v20.4 P0-9]".format(label, k, v, hexlen))

    def _req_int(k):                                       # a real int, never a bool
        v = js.get(k)
        if type(v) is not int or v < 0:
            sys.exit("ABORT: '{}' status.{}={!r} must be a non-negative integer. "
                     "[audit v20.4 P0-9]".format(label, k, v))

    _req_str("attempt_id")
    _req_str("code_version")
    _req_str("split_ready_sha256", 64)
    _req_int("run_id")
    _req_int("flows_written_ml")
    _req_int("flows_audit")
    if require_campaign_fields:
        _req_str("campaign_id")            # a TEXTUAL id, never a bare number [audit v20.8 P1-11]
        _req_str("campaign_sha256", 64)
        _req_int("config_id")
        if js.get("split") not in ("train", "validation", "test"):
            sys.exit("ABORT: '{}' status.split={!r} invalid. [audit v20.4 P0-9]".format(label, js.get("split")))
    # Hash / file objects must have EXACT keys with well-typed values — NOT merely be
    # non-empty — so a status can't carry {"garbage": 123} or a hash that contradicts its own
    # anchor [audit v20.4 §10.2/§10.4].
    def _hexval(d, k, optional=False):
        v = d.get(k)
        if optional and v is None:
            return
        if (not isinstance(v, str) or len(v) != 64
                or any(c not in "0123456789abcdef" for c in v.lower())):
            sys.exit("ABORT: '{}' status hash {}={!r} must be 64-hex{}. [audit v20.4 §10]".format(
                label, k, v, " or null" if optional else ""))
    ih = js.get("input_hashes")
    if not isinstance(ih, dict) or set(ih) != {"conn", "ssl", "quic", "annotations"}:
        sys.exit("ABORT: '{}' status.input_hashes must have EXACTLY conn/ssl/quic/annotations. "
                 "[audit v20.4 §10]".format(label))
    _hexval(ih, "conn"); _hexval(ih, "annotations")       # conn+annotations are never optional
    _hexval(ih, "ssl", optional=True); _hexval(ih, "quic", optional=True)
    oh = js.get("output_hashes")
    if not isinstance(oh, dict) or set(oh) != {"ml", "split_ready", "audit"}:
        sys.exit("ABORT: '{}' status.output_hashes must have EXACTLY ml/split_ready/audit. "
                 "[audit v20.4 §10]".format(label))
    for k in ("ml", "split_ready", "audit"):
        _hexval(oh, k)
    if oh["split_ready"] != js.get("split_ready_sha256"):
        sys.exit("ABORT: '{}' output_hashes.split_ready != split_ready_sha256 — the status "
                 "contradicts its own anchor. [audit v20.4 §10.4]".format(label))
    fl = js.get("files")
    if not isinstance(fl, dict) or set(fl) != {"ml", "split_ready", "audit"}:
        sys.exit("ABORT: '{}' status.files must have EXACTLY ml/split_ready/audit. "
                 "[audit v20.4 §10]".format(label))
    for k in ("ml", "split_ready", "audit"):
        if not isinstance(fl.get(k), str) or not fl[k]:
            sys.exit("ABORT: '{}' status.files.{} must be a non-empty string. "
                     "[audit v20.4 §10]".format(label, k))
    # class_counts_split_ready is a plain {label: non-negative int} map (the CSV comparison is
    # done by enforce_class_counts, which has the file) [audit v20.4 §9].
    ccsr = js.get("class_counts_split_ready")
    if not isinstance(ccsr, dict) or not ccsr:
        sys.exit("ABORT: '{}' status.class_counts_split_ready must be a non-empty object. "
                 "[audit v20.4 §9]".format(label))
    for k, v in ccsr.items():
        if type(v) is not int or v < 0:
            sys.exit("ABORT: '{}' class_counts_split_ready[{!r}]={!r} must be a non-negative int. "
                     "[audit v20.4 §9]".format(label, k, v))
    if type(js.get("diagnostic")) is not bool:
        sys.exit("ABORT: '{}' status.diagnostic must be boolean. [audit v20.3 P0-4]".format(label))
    pol = js.get("labeling_policy")
    validate_observed_labeling_policy(label, pol)
    # v4: `diagnostic` must AGREE with `diagnostic_reasons` [audit v20.14 §5]. The reasons must all be
    # RECOGNISED (the loosenable policy gates, plus the non-policy `allow_incomplete_campaign`), every
    # LOOSENED gate must be RECORDED (so a weak gate can't hide behind diagnostic=false), and the
    # `diagnostic` boolean must equal "the list is non-empty". A non-policy reason like
    # allow_incomplete_campaign is now expressible, so that status is VALID (merely diagnostic).
    reasons = js.get("diagnostic_reasons")
    if not (isinstance(reasons, list) and all(isinstance(x, str) for x in reasons)):
        sys.exit("ABORT: '{}' status.diagnostic_reasons must be a list of strings. "
                 "[audit v20.14 §5]".format(label))
    known = set(_LOOSENING) | {"allow_incomplete_campaign", "overlap_duration_fallback"}
    unknown = sorted(set(reasons) - known)
    if unknown:
        sys.exit("ABORT: '{}' status.diagnostic_reasons has unrecognised reason(s) {} (known: {}). "
                 "[audit v20.14 §5]".format(label, unknown, sorted(known)))
    loosened = {k for k in _LOOSENING if k in (pol or {}) and _LOOSENING[k](pol.get(k))}
    hidden = sorted(loosened - set(reasons))
    if hidden:
        sys.exit("ABORT: '{}' loosened policy gate(s) {} are not recorded in diagnostic_reasons {}. "
                 "[audit v20.14 §5]".format(label, hidden, sorted(set(reasons))))
    if bool(js.get("diagnostic")) != (len(reasons) > 0):
        sys.exit("ABORT: '{}' status.diagnostic={} contradicts diagnostic_reasons={} (diagnostic "
                 "must be TRUE iff there is at least one reason). [audit v20.14 §5]".format(
                     label, js.get("diagnostic"), sorted(set(reasons))))
    # Join blocks (status/v5 keys, counted per RECORD not unique uid) [audit v20.5 §15]: integer
    # counts that CLOSE, and a join_rate that actually EQUALS matching/records [audit v20.4 P0-7].
    for blk in ("ssl_join", "quic_join"):
        b = js.get(blk)
        if not isinstance(b, dict) or not all(k in b for k in
                                              ("records", "records_matching_conn", "join_rate")):
            sys.exit("ABORT: '{}' status.{} malformed (needs records/records_matching_conn/"
                     "join_rate). [audit v20.5 §15]".format(label, blk))
        rec, mat = b.get("records"), b.get("records_matching_conn")
        orph = b.get("orphan_records", 0)
        miss = b.get("missing_uid_records", 0)             # records with no uid (never join)
        for nm, v in (("records", rec), ("records_matching_conn", mat),
                      ("orphan_records", orph), ("missing_uid_records", miss)):
            if type(v) is not int or v < 0:
                sys.exit("ABORT: '{}' {}.{}={!r} must be a non-negative integer. "
                         "[audit v20.4 P0-7]".format(label, blk, nm, v))
        # Every record is EXACTLY one of matching / orphan / missing, so the three must sum to
        # records — a status that counts 8+0 out of 10 no longer passes [audit v20.4 §10.1].
        if mat + orph + miss != rec:
            sys.exit("ABORT: '{}' {} counts do not close: matching+orphan+missing ({}+{}+{}) != "
                     "records ({}). [audit v20.4 §10.1]".format(label, blk, mat, orph, miss, rec))
        jr = _finite_num(b.get("join_rate"))
        expected = (mat / rec) if rec else 0.0
        if jr is None or not (0.0 <= jr <= 1.0) or abs(jr - round(expected, 4)) > 1e-4:
            sys.exit("ABORT: '{}' {}.join_rate={!r} != matching/records={:.4f}. "
                     "[audit v20.4 P0-7]".format(label, blk, b.get("join_rate"), expected))
    if type(js.get("ip_bytes_fallback")) is not int or js["ip_bytes_fallback"] < 0:
        sys.exit("ABORT: '{}' status.ip_bytes_fallback must be a non-negative int. "
                 "[audit v20.3 P0-4]".format(label))
    if not isinstance(js.get("events"), dict):
        sys.exit("ABORT: '{}' status.events must be an object. [audit v20.3 P0-4]".format(label))
    # Each event's counters must be well-typed NON-NEGATIVE INTEGERS that respect the obvious
    # relationships, carry a real attack label, and a coverage in [0,1] — a fractional
    # usable_flows or a "BAD" matched_flows no longer passes [audit v20.4 §10.3].
    for ev, st in (js["events"] or {}).items():
        if not isinstance(st, dict):
            sys.exit("ABORT: '{}' event {} is not an object. [audit v20.4 §10.3]".format(label, ev))
        for k in ("usable_flows", "matched_flows", "ambiguous_flows",
                  "unique_dst_ports", "port_range_width"):
            v = st.get(k)
            if type(v) is not int or v < 0:
                sys.exit("ABORT: '{}' event {}.{}={!r} must be a non-negative integer. "
                         "[audit v20.4 §10.3]".format(label, ev, k, v))
        # Every valid attack window targets a port or range in 1..65535, so the width is >=1;
        # and a matched flow must have reached at least one port [audit v20.8 P1-11].
        if st["port_range_width"] < 1:
            sys.exit("ABORT: '{}' event {} port_range_width must be >= 1. [audit v20.8 P1-11]"
                     .format(label, ev))
        if st["matched_flows"] > 0 and st["unique_dst_ports"] < 1:
            sys.exit("ABORT: '{}' event {} has matched flows but unique_dst_ports=0. "
                     "[audit v20.8 P1-11]".format(label, ev))
        if st["usable_flows"] > st["matched_flows"]:
            sys.exit("ABORT: '{}' event {} usable_flows {} > matched_flows {}. [audit v20.4 §10.3]"
                     .format(label, ev, st["usable_flows"], st["matched_flows"]))
        if st["ambiguous_flows"] > st["matched_flows"]:
            sys.exit("ABORT: '{}' event {} ambiguous_flows {} > matched_flows {}. [audit v20.4 §10.3]"
                     .format(label, ev, st["ambiguous_flows"], st["matched_flows"]))
        if st["unique_dst_ports"] > st["port_range_width"]:
            sys.exit("ABORT: '{}' event {} unique_dst_ports {} > port_range_width {}. "
                     "[audit v20.4 §10.3]".format(label, ev, st["unique_dst_ports"], st["port_range_width"]))
        # A matched flow is either usable or ambiguous, and a distinct port needs a matched
        # flow to have reached it — so neither total may exceed matched_flows [audit v20.5 §8].
        if st["usable_flows"] + st["ambiguous_flows"] > st["matched_flows"]:
            sys.exit("ABORT: '{}' event {} usable+ambiguous ({}+{}) > matched_flows {}. "
                     "[audit v20.5 §8]".format(label, ev, st["usable_flows"],
                                               st["ambiguous_flows"], st["matched_flows"]))
        # §7 [audit v20.24]: under the OFFICIAL policy (allow_overlapping_windows=false) a flow matches
        # AT MOST one window, so every matched flow is EITHER usable OR ambiguous — matched must EQUAL
        # usable+ambiguous, not merely be >= it. This rejects a status that inflates matched_flows with
        # phantom matches that correspond to no published (usable) or dropped (ambiguous) flow.
        if not pol.get("allow_overlapping_windows") \
                and st["usable_flows"] + st["ambiguous_flows"] != st["matched_flows"]:
            sys.exit("ABORT: '{}' event {} matched_flows {} != usable+ambiguous ({}+{}) under "
                     "allow_overlapping_windows=false — phantom matches with no usable/dropped flow. "
                     "[audit v20.24 §7]".format(label, ev, st["matched_flows"],
                                                st["usable_flows"], st["ambiguous_flows"]))
        if st["unique_dst_ports"] > st["matched_flows"]:
            sys.exit("ABORT: '{}' event {} unique_dst_ports {} > matched_flows {}. "
                     "[audit v20.5 §8]".format(label, ev, st["unique_dst_ports"], st["matched_flows"]))
        if str(st.get("label")) not in _ATTACK_LABELS:
            sys.exit("ABORT: '{}' event {} label {!r} is not an attack label {}. "
                     "[audit v20.4 §10.3]".format(label, ev, st.get("label"), sorted(_ATTACK_LABELS)))
        pc = _finite_num(st.get("port_coverage"))
        if pc is None or not (0.0 <= pc <= 1.0):
            sys.exit("ABORT: '{}' event {} port_coverage {!r} not in [0,1]. [audit v20.4 §10.3]"
                     .format(label, ev, st.get("port_coverage")))
        # port_coverage must actually EQUAL unique_dst_ports / port_range_width — a status can
        # no longer claim 0.8 while probing 1 of 100 ports [audit v20.5 §8].
        exp_pc = st["unique_dst_ports"] / max(st["port_range_width"], 1)
        if abs(pc - round(exp_pc, 4)) > 1e-4:
            sys.exit("ABORT: '{}' event {} port_coverage {} != unique_dst_ports/port_range_width "
                     "{:.4f}. [audit v20.5 §8]".format(label, ev, pc, exp_pc))
        # Temporal evidence must be REAL: finite match times AND a finite attack window that
        # CONTAINS them (window_start <= first_match <= last_match <= window_end) — a "BAD" time,
        # reversed order, or a match outside its own window is rejected [audit v20.6 §11 / v20.7].
        fm, lm = _finite_num(st.get("first_match")), _finite_num(st.get("last_match"))
        ws, we = _finite_num(st.get("window_start")), _finite_num(st.get("window_end"))
        if fm is None or lm is None or ws is None or we is None:
            sys.exit("ABORT: '{}' event {} first_match/last_match/window_start/window_end must be "
                     "finite numbers. [audit v20.7]".format(label, ev))
        if not (ws <= fm <= lm <= we):
            sys.exit("ABORT: '{}' event {} times must satisfy window_start<=first_match<="
                     "last_match<=window_end (got {}<= {} <= {} <= {}). [audit v20.7]"
                     .format(label, ev, ws, fm, lm, we))
    # --- INVARIANTS: the recorded evidence must CONFIRM the claimed gates ---
    if pol["require_ip_bytes"] and js["ip_bytes_fallback"] != 0:
        sys.exit("ABORT: '{}' claims require_ip_bytes but ip_bytes_fallback={}. "
                 "[audit v20.3 P0-4]".format(label, js["ip_bytes_fallback"]))
    for kind, blk, rk in (("ssl", "ssl_join", "min_ssl_join_rate"),
                          ("quic", "quic_join", "min_quic_join_rate")):
        if pol["require_{}_log".format(kind)]:
            b = js[blk]
            if (_finite_num(b.get("records")) or 0) <= 0 or (_finite_num(b.get("records_matching_conn")) or 0) <= 0:
                sys.exit("ABORT: '{}' claims require_{}_log but {} has no joined records. "
                         "[audit v20.3 P0-4]".format(label, kind, blk))
            jr = _finite_num(b.get("join_rate"))
            if jr is None or jr < pol[rk]:
                sys.exit("ABORT: '{}' {} join_rate {} < policy {} {}. [audit v20.3 P0-4]".format(
                    label, blk, b.get("join_rate"), rk, pol[rk]))
            # A policy that REQUIRES the log must also carry its input hash — a null ssl/quic
            # hash under require_*_log is an incomplete, unverifiable provenance [audit v20.5 §10].
            if ih.get(kind) is None:
                sys.exit("ABORT: '{}' claims require_{}_log but input_hashes.{} is null — the "
                         "required log is not hashed. [audit v20.5 §10]".format(label, kind, kind))
    for ev, st in (js["events"] or {}).items():
        if not isinstance(st, dict):
            continue
        uf = _finite_num(st.get("usable_flows"))
        if uf is None or uf < pol["min_matches_per_event"]:
            sys.exit("ABORT: '{}' event {} usable_flows {} < min_matches_per_event {}. "
                     "[audit v20.3 P0-4]".format(label, ev, st.get("usable_flows"),
                                                 pol["min_matches_per_event"]))
        if (_finite_num(st.get("port_range_width")) or 1) > 1:   # a scan over a RANGE
            pc = _finite_num(st.get("port_coverage"))
            if pc is None or pc < pol["min_port_coverage"]:
                sys.exit("ABORT: '{}' scan event {} port_coverage {} < min_port_coverage {}. "
                         "[audit v20.3 P0-4]".format(label, ev, st.get("port_coverage"),
                                                     pol["min_port_coverage"]))
    # --- FLOW accounting: the counts must be internally consistent, so a status cannot
    # under-report its events (claim usable_flows=1 over a CSV with thousands) [audit v20.5 §9] ---
    fwr, fau, fdrop = js["flows_written_ml"], js["flows_audit"], js.get("flows_dropped_ambiguous")
    if type(fdrop) is not int or fdrop < 0:
        sys.exit("ABORT: '{}' flows_dropped_ambiguous must be a non-negative int. "
                 "[audit v20.5 §9]".format(label))
    if fwr > fau:
        sys.exit("ABORT: '{}' flows_written_ml {} > flows_audit {}. [audit v20.5 §9]".format(
            label, fwr, fau))
    if fau != fwr + fdrop:
        sys.exit("ABORT: '{}' flows_audit {} != flows_written_ml {} + flows_dropped_ambiguous {}. "
                 "[audit v20.5 §9]".format(label, fau, fwr, fdrop))
    if sum(ccsr.values()) != fwr:
        sys.exit("ABORT: '{}' sum(class_counts_split_ready) {} != flows_written_ml {}. "
                 "[audit v20.5 §9]".format(label, sum(ccsr.values()), fwr))
    # Under the OFFICIAL policy (drop ambiguous, no overlapping windows) the attack rows in the
    # split-ready CSV come ONLY from usable event flows, so the attack CLASSES the status counts
    # must EXACTLY match the events' labels, and each class' count must equal the sum of its
    # events' usable_flows — an events={} over a DoS-containing file is rejected [audit v20.5 §9].
    if pol.get("ambiguous_policy") == "drop" and not pol.get("allow_overlapping_windows"):
        attack_counts = {k: v for k, v in ccsr.items() if str(k) in _ATTACK_LABELS}
        usable_by_label = {}
        for st in (js["events"] or {}).values():
            if isinstance(st, dict):
                usable_by_label[str(st["label"])] = (usable_by_label.get(str(st["label"]), 0)
                                                     + int(st["usable_flows"]))
        if set(attack_counts) != set(usable_by_label):
            sys.exit("ABORT: '{}' attack classes in the CSV {} != attack classes in status.events "
                     "{} — events do not describe the file's attack rows [audit v20.5 §9].".format(
                         label, sorted(attack_counts), sorted(usable_by_label)))
        for lab, cnt in attack_counts.items():
            if usable_by_label.get(str(lab), 0) != cnt:
                sys.exit("ABORT: '{}' class {} has {} rows but its events sum {} usable flows — "
                         "under-reported evidence [audit v20.5 §9].".format(
                             label, lab, cnt, usable_by_label.get(str(lab), 0)))
    # --- PRODUCER/SCHEMA versions must be KNOWN (a forged/old sidecar with invented versions is
    # not official) [audit v20.5 §11] ---
    if js.get("code_version") not in versions.SUPPORTED_LABELER_VERSIONS:
        sys.exit("ABORT: '{}' code_version {!r} not in supported {}. [audit v20.5 §11]".format(
            label, js.get("code_version"), sorted(versions.SUPPORTED_LABELER_VERSIONS)))
    if js.get("annotation_scenario_version") not in versions.SUPPORTED_SCENARIO_VERSIONS:
        sys.exit("ABORT: '{}' annotation_scenario_version {!r} not in supported {}. "
                 "[audit v20.5 §11]".format(label, js.get("annotation_scenario_version"),
                                            sorted(versions.SUPPORTED_SCENARIO_VERSIONS)))
    if js.get("annotation_orchestrator_version") not in versions.SUPPORTED_ORCHESTRATOR_VERSIONS:
        sys.exit("ABORT: '{}' annotation_orchestrator_version {!r} not in supported {}. "
                 "[audit v20.5 §11]".format(label, js.get("annotation_orchestrator_version"),
                                            sorted(versions.SUPPORTED_ORCHESTRATOR_VERSIONS)))
    # --- v27 WINDOW-MATCHING fields [audit v20.21 §7]: present (checked above) AND well-formed, so a
    # status with an INVALID temporal policy (min_window_overlap=2.0/"banana") or IMPOSSIBLE counters
    # (fallback>matched, fallback with zero matched, matched>flows_audit) can no longer be authenticated
    # as official. The code_version was just proven to be a supported labeler, so these apply. ---
    mwo = js.get("min_window_overlap")
    if mwo is not None:
        # §12 [audit v20.23]: STRICT typing — a real int/float in [0,1], never a bool (true==1.0) or a
        # numeric STRING ("0.5"). float(value) coercion previously let both through.
        if type(mwo) not in (int, float) or isinstance(mwo, bool) or not math.isfinite(mwo) \
                or not (0.0 <= mwo <= 1.0):
            sys.exit("ABORT: '{}' status.min_window_overlap={!r} must be null or a real number "
                     "(int/float, not bool/string) in [0,1]. [audit v20.23 §12]".format(label, mwo))
    oa = js.get("overlap_accounting")
    if not isinstance(oa, dict) or set(oa) != {"matched_flows", "duration_fallback_flows"}:
        sys.exit("ABORT: '{}' status.overlap_accounting must be an object with EXACTLY "
                 "matched_flows/duration_fallback_flows. [audit v20.21 §7]".format(label))
    mf, ff = oa.get("matched_flows"), oa.get("duration_fallback_flows")
    for nm, v in (("matched_flows", mf), ("duration_fallback_flows", ff)):
        if type(v) is not int or v < 0:
            sys.exit("ABORT: '{}' overlap_accounting.{}={!r} must be a non-negative integer. "
                     "[audit v20.21 §7]".format(label, nm, v))
    if ff > mf:                                            # fallback flows ARE a subset of matched flows
        sys.exit("ABORT: '{}' overlap_accounting.duration_fallback_flows {} > matched_flows {} — "
                 "impossible. [audit v20.21 §7]".format(label, ff, mf))
    if mf > js["flows_audit"]:
        sys.exit("ABORT: '{}' overlap_accounting.matched_flows {} > flows_audit {}. "
                 "[audit v20.21 §7]".format(label, mf, js["flows_audit"]))
    if mwo is None and mf != 0:                            # legacy mode records NO overlap-mode matches
        sys.exit("ABORT: '{}' min_window_overlap is null (legacy) but overlap_accounting.matched_flows"
                 "={} (must be 0 in legacy mode). [audit v20.21 §7]".format(label, mf))
    if mwo is not None:
        # §6 [audit v20.22]: TIE overlap_accounting.matched_flows to the events. It counts DISTINCT
        # flows matching >=1 window; each event's matched_flows is a subset, so it must sit between the
        # LARGEST single event and the SUM of events. A status that claims 0 overlap matches while its
        # events matched thousands (the auditor's forgery) — or vice-versa — is incoherent and rejected.
        ev_matched = [int(st.get("matched_flows", 0)) for st in (js.get("events") or {}).values()
                      if isinstance(st, dict)]
        ev_sum, ev_max = sum(ev_matched), (max(ev_matched) if ev_matched else 0)
        # §7 [audit v20.23]: under the OFFICIAL policy the windows do NOT overlap
        # (allow_overlapping_windows=false), so a flow matches AT MOST one window — distinct matched
        # flows must then EQUAL the sum of per-event matches, not merely sit under it. Only when
        # overlapping windows are explicitly allowed (diagnostic) does a flow count for several events,
        # loosening the tie to max_event <= matched <= sum_events [audit v20.22 §6].
        if not pol.get("allow_overlapping_windows"):
            if mf != ev_sum:
                sys.exit("ABORT: '{}' overlap_accounting.matched_flows {} != sum of event matches {} "
                         "under allow_overlapping_windows=false (a flow matches one window) — the "
                         "accounting does not describe the events. [audit v20.23 §7]".format(
                             label, mf, ev_sum))
        elif not (ev_max <= mf <= ev_sum):
            sys.exit("ABORT: '{}' overlap_accounting.matched_flows {} is inconsistent with the events "
                     "(need max_event {} <= matched <= sum_events {}) — the overlap accounting does not "
                     "describe the matched flows. [audit v20.22 §6]".format(label, mf, ev_max, ev_sum))
        # §5 [audit v20.22]: a DEGENERATE 100% fallback (overlap requested but EVERY matched flow used
        # the legacy point rule) means the overlap policy NEVER applied — it MUST be recorded as
        # diagnostic with 'overlap_duration_fallback', so a forged status can't claim it as official.
        if mf > 0 and ff == mf and not (
                js.get("diagnostic") and "overlap_duration_fallback" in (js.get("diagnostic_reasons") or [])):
            sys.exit("ABORT: '{}' overlap_accounting shows 100% duration fallback ({}/{}) but the status "
                     "is not diagnostic with 'overlap_duration_fallback' — the overlap policy never "
                     "applied. [audit v20.22 §5]".format(label, ff, mf))


def enforce_planned_events(label, js, manifest, run_id):
    """If the campaign PLANS attacks for this run, the status' events must cover them — an
    empty events dict (which makes min_matches_per_event vacuously true) no longer passes,
    and an UNPLANNED attack event is rejected [audit v20.4 P0-8]."""
    spec = (manifest.get("runs") or {}).get(str(run_id)) or {}
    planned = spec.get("attacks")
    if not planned:
        return
    planned_set = {str(a) for a in planned}
    observed = {str((ev or {}).get("label")) for ev in (js.get("events") or {}).values()
                if isinstance(ev, dict)}
    missing = sorted(planned_set - observed)
    if missing:
        sys.exit("ABORT: '{}' run {} plans attack(s) {} but status.events shows none of them "
                 "(observed {}). [audit v20.4 P0-8]".format(label, run_id, missing, sorted(observed)))
    unplanned = sorted(observed - planned_set - {"None"})
    if unplanned:
        sys.exit("ABORT: '{}' run {} status.events has UNPLANNED attack(s) {} (planned {}). "
                 "[audit v20.4 P0-8]".format(label, run_id, unplanned, sorted(planned_set)))


def csv_class_counts(path):
    """Per-class row counts of a split-ready CSV's label column [audit v20.4 §9]."""
    import pandas as pd
    try:
        col = pd.read_csv(path, usecols=["label"])["label"]
    except (ValueError, KeyError):
        sys.exit("ABORT: '{}' has no 'label' column; cannot verify class counts. "
                 "[audit v20.4 §9]".format(path))
    counts = {}
    for v in col:
        counts[str(v)] = counts.get(str(v), 0) + 1
    return counts


def enforce_class_counts(label, js, manifest, run_id):
    """Bind the status.events claims to the CSV's ACTUAL rows [audit v20.4 §9]:
      * status.class_counts_split_ready must EQUAL the per-class counts recomputed from the CSV
        (so the status can't describe a different file);
      * every attack the campaign PLANS for this run must have >0 rows of that class in THIS
        CSV (aggregate-split coverage is not enough — the run's own file must carry it);
      * no event may claim more usable_flows of a class than the CSV holds of it.
    `label` is the CSV path (used both to read and to report)."""
    claimed = js.get("class_counts_split_ready")            # already type-checked by validate_status_v3
    norm = {str(k): int(v) for k, v in (claimed or {}).items()}
    actual = csv_class_counts(label)
    if norm != actual:
        sys.exit("ABORT: '{}' status class_counts_split_ready {} != actual CSV counts {} — the "
                 "status does not describe this file's rows. [audit v20.4 §9]".format(
                     label, norm, actual))
    spec = (manifest.get("runs") or {}).get(str(run_id)) or {}
    for atk in (spec.get("attacks") or []):
        if actual.get(str(atk), 0) <= 0:
            sys.exit("ABORT: '{}' run {} plans attack {} but its split-ready CSV has ZERO {} "
                     "rows — status events are not backed by this file. [audit v20.4 §9]".format(
                         label, run_id, atk, atk))
    used = {}
    for ev in (js.get("events") or {}).values():
        if isinstance(ev, dict):
            lab = str(ev.get("label"))
            used[lab] = used.get(lab, 0) + int(ev.get("usable_flows") or 0)
    for lab, uf in used.items():
        if uf > actual.get(lab, 0):
            sys.exit("ABORT: '{}' events claim {} usable {} flow(s) but the CSV has only {} — "
                     "events exceed the file. [audit v20.4 §9]".format(
                         label, uf, lab, actual.get(lab, 0)))


def _enforce_required_policy(label, status_json, manifest):
    """If the campaign declares required_labeling_policy, the status must MEET every required
    gate [audit v19 P0-2]. (The schema version is checked separately, always.) No-op when the
    campaign declares no policy."""
    req = (manifest or {}).get("required_labeling_policy")
    if not req:
        return
    viol = policy_violations(status_json.get("labeling_policy"), req)
    if viol:
        pretty = "; ".join("{}={!r} (need {})".format(f, o, r) for f, o, r in viol)
        sys.exit("ABORT: '{}' labeling policy does NOT meet the campaign's required policy: "
                 "{}. A weak-policy run is not official. [audit v19 P0-2]".format(label, pretty))


def status_diagnostic_reasons(status_json):
    """Return the list of reasons a status is DIAGNOSTIC (empty == official) [audit 5]. Prefers the
    status's explicit `diagnostic_reasons` (status/v5), which NAMES the reason — e.g.
    `allow_incomplete_campaign` — instead of the opaque `status.diagnostic=true`; falls back to
    re-deriving from the policy for an old/edited status that lacks the list [audit v20.14 §5]."""
    explicit = status_json.get("diagnostic_reasons")
    if isinstance(explicit, list) and all(isinstance(x, str) for x in explicit):
        reasons = list(explicit)
    else:
        reasons = ["status.diagnostic=true"] if status_json.get("diagnostic") is True else []
    pol = status_json.get("labeling_policy") or {}
    for key, is_loose in _LOOSENING.items():                # union with policy-derived, for safety
        if key in pol and is_loose(pol.get(key)):
            reasons.append(key)
    return sorted(set(reasons))


def _load_status(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        sys.exit("ABORT: cannot read status '{}': {} [audit 6]".format(path, exc))


def _discover_status(csv_path):
    """Map an input split-ready CSV to its labeler status sidecar by convention."""
    if csv_path.endswith("_split_ready.csv"):
        return csv_path[:-len("_split_ready.csv")] + "_run_status.json"
    return csv_path.rsplit(".csv", 1)[0] + "_run_status.json"


def authenticate_against_campaign(csvs, status_paths, manifest, campaign_path,
                                  require_status, allow_diagnostic=False,
                                  require_full_coverage=True):
    """Authenticate every input CSV against the campaign; return per-input records.

    Aborts on ANY mismatch. Aborts on a MISSING sidecar only when require_status is set.
    When require_full_coverage, the authenticated runs must equal the campaign runs, each
    present exactly once (no missing, extra, or duplicated run) [audit 4].
    """
    m_id = str(manifest.get("campaign_id") or "")
    m_sha = sha256(campaign_path)
    csv_sha = {p: sha256(p) for p in csvs}

    # Resolve which status belongs to which CSV. If --status is given EXPLICITLY, use ONLY
    # those files and require an EXACT bijection (one per CSV, matched by split_ready_sha256,
    # no extra file, no repeated hash) — no silent auto-discovery fallback [audit v20.3 P1-8].
    chosen = {}
    if status_paths is not None:
        by_hash = {}
        for sp in status_paths:
            js = _load_status(sp)
            key = js.get("split_ready_sha256")
            if key in by_hash:
                sys.exit("ABORT: two --status files share split_ready_sha256 {}... "
                         "[audit v20.3 P1-8]".format(str(key)[:12]))
            by_hash[key] = (sp, js)
        used = set()
        for p in csvs:
            hit = by_hash.get(csv_sha[p])
            if hit is None:
                if require_status:
                    sys.exit("ABORT: no --status sidecar matches '{}' by split_ready_sha256; "
                             "pass exactly one status per CSV. [audit v20.3 P1-8]".format(p))
                continue
            chosen[p] = hit
            used.add(csv_sha[p])
        extra = [sp for k, (sp, _js) in by_hash.items() if k not in used]
        if extra:
            sys.exit("ABORT: --status file(s) {} match no input CSV; pass exactly one status "
                     "per CSV (no extras). [audit v20.3 P1-8]".format(extra))
    else:
        for p in csvs:                                    # auto-discover ONLY when --status omitted
            cand = _discover_status(p)
            if os.path.exists(cand):
                chosen[p] = (cand, _load_status(cand))

    records, authed_runs = [], []
    for p in csvs:
        csha = csv_sha[p]
        sp, js = chosen.get(p, (None, None))
        if js is None:
            if require_status:
                sys.exit("ABORT: no status sidecar for '{}' and status is required; cannot "
                         "authenticate it against the campaign. [audit 6]".format(p))
            records.append({"input": p, "sha256": csha, "status_authenticated": False,
                            "reason": "no status sidecar found"})
            continue
        if js.get("status") != "success":
            sys.exit("ABORT: status for '{}' is '{}', not 'success'. [audit 6]".format(
                p, js.get("status")))
        enforce_status_schema(p, js)                       # ALWAYS, before anything else [P0-10]
        validate_status_v5(p, js)                          # full v4 structure + invariants [P0-4]
        if js.get("split_ready_sha256") != csha:
            sys.exit("ABORT: '{}' SHA-256 {}... != status split_ready_sha256 {}... — the CSV "
                     "is NOT the file the labeler published. [audit 6]".format(
                         p, (csha or "")[:12], str(js.get("split_ready_sha256"))[:12]))
        # §6 [audit v20.23]: the overlap accounting must DESCRIBE the authenticated CSV, not just be
        # internally tidy. In overlap mode, every attack row with missing/zero flow_duration provably
        # used the point fallback, so duration_fallback_flows can't be LESS than their count — this
        # catches a status that declares 0 fallback over a CSV whose attack flows all have duration 0.
        if js.get("min_window_overlap") is not None:
            oa = js.get("overlap_accounting") or {}
            need_fb = attack_rows_needing_fallback(p)
            if need_fb is not None and oa.get("duration_fallback_flows", 0) < need_fb:
                sys.exit("ABORT: '{}' declares duration_fallback_flows={} but the CSV has {} attack "
                         "row(s) with missing/zero flow_duration that MUST have used the point-rule "
                         "fallback in overlap mode — the accounting does not describe the data. "
                         "[audit v20.23 §6]".format(p, oa.get("duration_fallback_flows", 0), need_fb))
        # BIND the file's content to the run: the run_id INSIDE the CSV must be a single
        # value equal to the status' run_id, so a swapped sidecar or a multi-run file is
        # rejected [audit 4].
        try:
            st_rid = int(js.get("run_id"))
        except (TypeError, ValueError):
            sys.exit("ABORT: status for '{}' has no valid run_id. [audit 4]".format(p))
        file_rids = csv_run_ids(p)
        if len(file_rids) != 1:
            sys.exit("ABORT: '{}' contains {} run_id(s) {}; an authenticated split-ready file "
                     "must hold exactly ONE run. [audit 4]".format(p, len(file_rids), file_rids))
        if file_rids[0] != st_rid:
            sys.exit("ABORT: '{}' contains run_id {} but its status declares run_id {} — the "
                     "sidecar does not belong to this file. [audit 4]".format(
                         p, file_rids[0], st_rid))
        # §5/§6/§7 [audit v20.25]: TIE the event windows to the CSV's TIMESTAMPS, per-window, per-CLASS,
        # and at the pinned overlap FRACTION. Every attack flow was matched to an event of its own class
        # whose window contains it (legacy) or overlaps it by >= min_window_overlap (overlap mode); a
        # status whose windows don't actually cover the file's attack flows under that rule — a shifted
        # window, a class swap, a sub-threshold graze, a sidecar from another run — no longer
        # authenticates. The temporal evidence must DESCRIBE the file, not merely be internally ordered.
        n_out, n_atk = attack_rows_off_window(p, js.get("events"), js.get("min_window_overlap"))
        if n_out:
            sys.exit("ABORT: '{}' has {}/{} attack row(s) that match NO same-class event window under "
                     "the declared rule (min_window_overlap={}) — the status does not temporally "
                     "describe the CSV. [audit v20.25 §5/§6/§7]".format(
                         p, n_out, n_atk, js.get("min_window_overlap")))
        # Diagnostic labeling must not enter an official package unless explicitly allowed.
        diag = status_diagnostic_reasons(js)
        if diag and not allow_diagnostic:
            sys.exit("ABORT: '{}' was labeled with a DIAGNOSTIC policy {} — it is not an "
                     "official run. Pass --allow-diagnostic-status to include it on "
                     "purpose. [audit 5]".format(p, diag))
        exp_cfg = camp_config_of_run(manifest, st_rid)
        exp_split = camp_split_of_run(manifest, st_rid)
        if exp_cfg is None:
            sys.exit("ABORT: status run_id {} for '{}' is not in the campaign. "
                     "[audit 6]".format(st_rid, p))
        for fld, got, exp in (("campaign_id", str(js.get("campaign_id") or ""), m_id),
                              ("campaign_sha256", str(js.get("campaign_sha256") or ""), m_sha),
                              ("config_id", js.get("config_id"), exp_cfg),
                              ("split", str(js.get("split") or ""), str(exp_split))):
            if str(got) != str(exp):
                sys.exit("ABORT: '{}' status {}={!r} != campaign {!r}. This CSV did not come "
                         "from the declared campaign. [audit 6]".format(p, fld, got, exp))
        _enforce_required_policy(p, js, manifest)         # official gates ON? [audit v19 P0-2]
        enforce_planned_events(p, js, manifest, st_rid)   # planned attacks present? [audit v20.4 P0-8]
        enforce_class_counts(p, js, manifest, st_rid)     # events match THIS CSV's rows [audit v20.4 §9]
        authed_runs.append(st_rid)
        # PIN the sidecar itself so the split can be re-verified later [audit v20.3 P1-9].
        records.append({"input": p, "sha256": csha, "status_path": sp,
                        "status_sha256": sha256(sp), "attempt_id": js.get("attempt_id"),
                        "code_version": js.get("code_version"),
                        "status_schema_version": js.get("status_schema_version"),
                        "run_id": st_rid, "config_id": exp_cfg, "split": str(exp_split),
                        "labeling_policy": js.get("labeling_policy"),
                        # The window-matching policy is a labeling-time choice too: the merge checks it
                        # is IDENTICAL across all authenticated runs so a split can't mix legacy and
                        # overlap labeling [audit v20.20 §8], and re-validates the fallback RATE against
                        # the campaign's pinned ceiling [audit v20.22 §5].
                        "min_window_overlap": js.get("min_window_overlap"),
                        "overlap_accounting": js.get("overlap_accounting"),
                        # Producer versions, so the split provenance records exactly which
                        # scenario/orchestrator made each run's ground truth [audit v20.4 §12].
                        "annotation_scenario_version": js.get("annotation_scenario_version"),
                        "annotation_orchestrator_version": js.get("annotation_orchestrator_version"),
                        "class_counts_split_ready": js.get("class_counts_split_ready"),
                        "diagnostic": bool(diag), "diagnostic_reasons": diag,
                        "status_authenticated": True})

    if require_full_coverage and (status_paths is not None or require_status
                                  or any(r["status_authenticated"] for r in records)):
        declared = sorted(all_campaign_runs(manifest))
        got = sorted(authed_runs)
        if len(got) != len(set(got)):
            sys.exit("ABORT: a run is authenticated more than once ({}). [audit 4]".format(got))
        if got != declared:
            sys.exit("ABORT: authenticated runs {} != campaign runs {} (each run must be "
                     "present exactly once). [audit 4]".format(got, declared))
    return records


# NOTE: the old identity-only `authenticate_status_set()` (no per-file byte binding) was
# REMOVED in v20 — the validator now byte-binds each per-run CSV via
# authenticate_against_campaign(), so keeping the weak helper around only risked an
# accidental regression to the forgeable model [audit v20 P1-13].


# --- tiny manifest helpers (kept local so validate/evaluate need not import campaign
# just for these three lookups; campaign.py remains the loader/validator). ------------
def camp_config_of_run(manifest, run_id):
    spec = (manifest.get("runs") or {}).get(str(run_id))
    return spec.get("config_id") if spec else None


def camp_split_of_run(manifest, run_id):
    spec = (manifest.get("runs") or {}).get(str(run_id))
    return spec.get("split") if spec else None


def all_campaign_runs(manifest):
    return [int(r) for r in (manifest.get("runs") or {})]
