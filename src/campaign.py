#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
campaign.py — the ONE source of truth for a capture campaign [audit 11/12].

`ALLOWED_LABELS` (feature_schema) is the whole vocabulary the tooling understands.
A CAMPAIGN is what THIS experiment actually intends to collect: which classes are
EXPECTED, which run_ids exist, which attack config each run used, and which split
(train / validation / test) each run belongs to. Without a single manifest,
different scripts silently assume different things — merge accepts a partial
campaign, the validator calls the file valid, and realism calls the coverage
"complete". A campaign a partial dataset must be DECLARED, not inferred.

MANIFEST (JSON)
---------------
{
  "campaign_id": "lab-2026-07",
  "expected_labels": ["BENIGN", "PortScan", "BruteForce", "DoS"],
  "reserved_test_configs": [6, 7],
  "runs": {
    "0": {"config_id": 0, "split": "train",      "seed": 0, "day": "2026-07-01"},
    "1": {"config_id": 1, "split": "train",      "seed": 1, "day": "2026-07-02"},
    "2": {"config_id": 2, "split": "train",      "seed": 2, "day": "2026-07-03"},
    "3": {"config_id": 3, "split": "train",      "seed": 3, "day": "2026-07-04"},
    "4": {"config_id": 4, "split": "validation", "seed": 4, "day": "2026-07-05"},
    "5": {"config_id": 6, "split": "test",       "seed": 5, "day": "2026-07-06"},
    "6": {"config_id": 7, "split": "test",       "seed": 6, "day": "2026-07-07"}
  }
}

A reserved-test config MUST NOT appear in a train/validation run (that would leak
an "unseen" attack setting into training) [audit 12].
"""

import datetime
import ipaddress
import json
import math
import re

import attack_scenarios as scen
import feature_schema as fs
import provenance as prov               # OFFICIAL_POLICY_FIELDS / profiles [audit v20.2 P0-4]

SPLITS = {"train", "validation", "test"}
# A run's `attacks` plan may only list ACTUAL attacks — never BENIGN — so the official loader
# accepts exactly what the official orchestrator can execute [audit v20.6 §5].
ATTACK_LABELS = {str(a) for a in fs.ALLOWED_LABELS} - {"BENIGN"}

_HOSTNAME_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
_CAMPAIGN_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")   # safe for file names / logs / URLs [P1-15]


def _is_hostname(h):
    """A conventional DNS hostname: 1+ dot-separated labels, each 1-63 chars of [A-Za-z0-9-] not
    starting/ending with '-', no empty labels [audit v20.8 P1-10]. Rejects '-bad.lab', 'foo..lab',
    '.', '_srv.lab'; accepts 'blog.lab', 'h'."""
    h = h.rstrip(".")                                          # tolerate a single trailing FQDN dot
    if not h or len(h) > 253:
        return False
    return all(_HOSTNAME_LABEL.match(lbl) for lbl in h.split("."))


def _die(msg):
    raise SystemExit("ABORT campaign: " + msg + " [audit 5]")


def _canonical_int(key):
    """Return int(key) only if `key` is its own canonical form ('1', not '01')."""
    try:
        n = int(key)
    except (TypeError, ValueError):
        return None
    return n if str(n) == str(key) else None


def load(path, require_reproducible=False):
    """Load + STRICTLY validate a campaign manifest; SystemExit on any problem [audit 5].

    Rejects: empty campaign_id; duplicate/unknown expected_labels; empty runs;
    non-canonical/negative run_id; duplicate run ids; config_id outside the shared
    CONFIG_MATRIX; negative seed; non-ISO day; missing train or test; a config used in
    BOTH test and (train|validation); and a manifest whose declared DAYS contradict the
    split order (train after test) [audit 9]. With require_reproducible=True, every run
    must additionally carry a seed AND a day, so the manifest is a faithful record of
    the campaign (the official mode) [audit 9].
    """
    with open(path, encoding="utf-8") as fh:
        m = json.load(fh)

    if not isinstance(m, dict):                        # controlled abort, not traceback [audit 8]
        _die("top-level JSON must be an object")

    if not isinstance(m.get("campaign_id"), str) or not _CAMPAIGN_ID_RE.match(m["campaign_id"]):
        _die("'campaign_id' must be a non-empty string matching [A-Za-z0-9._-]+ (safe for file "
             "names/logs/URLs) [audit v20.7 / v20.8 P1-15]")

    exp = m.get("expected_labels")
    if not exp or not isinstance(exp, list):
        _die("'expected_labels' must be a non-empty list")
    if len(exp) != len(set(map(str, exp))):
        _die("'expected_labels' has duplicates: {}".format(exp))
    unknown = sorted(set(map(str, exp)) - {str(a) for a in fs.ALLOWED_LABELS})
    if unknown:
        _die("expected_labels {} not in ALLOWED_LABELS {}".format(unknown, sorted(fs.ALLOWED_LABELS)))

    runs = m.get("runs")
    if not isinstance(runs, dict) or not runs:
        _die("'runs' must be a non-empty object")
    # The reserved-test set is CODE (attack_scenarios), not a manifest-editable field
    # [audit 7]. If the manifest lists it, it must MATCH the code exactly.
    reserved = set(scen.TEST_RESERVED_CONFIGS)
    if "reserved_test_configs" in m:
        declared_res = m["reserved_test_configs"]
        if (not isinstance(declared_res, list)
                or any(not isinstance(x, int) or isinstance(x, bool) for x in declared_res)
                or set(declared_res) != reserved):
            _die("reserved_test_configs must equal the code's {} (it is not manifest-"
                 "editable)".format(sorted(reserved)))
    seen_ids, cfg_by_split = set(), {"train": set(), "validation": set(), "test": set()}
    for rid, spec in runs.items():
        if not isinstance(spec, dict):                 # controlled abort [audit 8]
            _die("run {} specification must be an object".format(rid))
        n = _canonical_int(rid)
        if n is None or n < 0:
            _die("run id '{}' must be a canonical non-negative integer".format(rid))
        if n in seen_ids:
            _die("duplicate run id {} (after int conversion)".format(n))
        seen_ids.add(n)
        split = spec.get("split")
        if split not in SPLITS:
            _die("run {} split must be one of {}".format(rid, sorted(SPLITS)))
        cfg = spec.get("config_id")
        if not isinstance(cfg, int) or isinstance(cfg, bool):
            _die("run {} config_id must be an integer".format(rid))
        if not (0 <= cfg < len(scen.CONFIG_MATRIX)):
            _die("run {} config_id={} outside CONFIG_MATRIX (0..{})".format(
                rid, cfg, len(scen.CONFIG_MATRIX) - 1))
        cfg_by_split[split].add(cfg)
        if cfg in reserved and split != "test":
            _die("run {} uses reserved-test config_id={} in split '{}' (TEST-only)".format(
                rid, cfg, split))
        sd = spec.get("seed")
        if sd is not None and (not isinstance(sd, int) or isinstance(sd, bool) or sd < 0):
            _die("run {} seed must be a non-negative integer".format(rid))
        day = spec.get("day")
        if day is not None:
            try:
                datetime.date.fromisoformat(str(day))
            except ValueError:
                _die("run {} day '{}' is not ISO YYYY-MM-DD".format(rid, day))

    if not runs_in_split(m, "train"):
        _die("at least one 'train' run is required")
    if not runs_in_split(m, "test"):
        _die("at least one 'test' run is required")
    leaked = cfg_by_split["test"] & (cfg_by_split["train"] | cfg_by_split["validation"])
    if leaked:
        _die("config(s) {} appear in BOTH test and train/validation — test configs "
             "must be unseen".format(sorted(leaked)))

    # The manifest must not CONTRADICT the split order: a train day after a test day is
    # incoherent even though the real leak check runs on flow timestamps later. ISO days
    # sort lexicographically == chronologically. Only enforced where days exist [audit 9].
    def _days(split):
        return [str((runs.get(str(r)) or {}).get("day"))
                for r in runs_in_split(m, split)
                if (runs.get(str(r)) or {}).get("day") is not None]
    tr_d, va_d, te_d = _days("train"), _days("validation"), _days("test")
    if tr_d and te_d and max(tr_d) > min(te_d):
        _die("manifest day-order: latest train day {} is after earliest test day {}".format(
            max(tr_d), min(te_d)))
    if tr_d and va_d and max(tr_d) > min(va_d):
        _die("manifest day-order: latest train day {} is after earliest validation day "
             "{}".format(max(tr_d), min(va_d)))
    if va_d and te_d and max(va_d) > min(te_d):
        _die("manifest day-order: latest validation day {} is after earliest test day "
             "{}".format(max(va_d), min(te_d)))

    # Optional OFFICIAL labeling policy the campaign REQUIRES of every run's status
    # [audit v19 P0-2]. A versioned profile expands to the full policy [audit v20.2 P0-4].
    prof = m.get("required_policy_profile")
    if prof is not None:
        if prof not in prov.OFFICIAL_POLICY_PROFILES:
            _die("required_policy_profile '{}' is unknown (known: {})".format(
                prof, sorted(prov.OFFICIAL_POLICY_PROFILES)))
        if "required_labeling_policy" in m:
            _die("declare required_policy_profile OR required_labeling_policy, not both")
        m["required_labeling_policy"] = dict(prov.OFFICIAL_POLICY_PROFILES[prof])

    # An EXPLICIT required_labeling_policy must be COMPLETE — it has to pin EVERY official
    # gate, so a partial policy (e.g. only use_failed) can never count as official
    # [audit v20.2 P0-4]. Shape is validated here; provenance enforces it against each status.
    rlp = m.get("required_labeling_policy")
    if rlp is not None:
        if not isinstance(rlp, dict) or not rlp:
            _die("required_labeling_policy must be a non-empty object")
        keys = set(rlp)
        if keys != set(prov.OFFICIAL_POLICY_FIELDS):
            missing = sorted(set(prov.OFFICIAL_POLICY_FIELDS) - keys)
            extra = sorted(keys - set(prov.OFFICIAL_POLICY_FIELDS))
            _die("required_labeling_policy must pin EXACTLY the official gates; "
                 "missing={} extra={} (or use required_policy_profile)".format(missing, extra))
        _bool_keys = {"use_failed", "allow_empty", "allow_overlapping_windows",
                      "ignore_annotation_campaign", "require_ip_bytes", "require_ssl_log",
                      "require_quic_log"}
        # RATE/coverage fields are proportions in [0,1]; the other two are non-negative
        # INTEGERS. NaN/Infinity (which json.load accepts non-standardly) are rejected
        # everywhere [audit v20 P1-12].
        _frac_keys = {"min_port_coverage", "min_ssl_join_rate", "min_quic_join_rate"}
        _int_keys = {"min_matches_per_event", "window_padding_ms"}
        for k, v in rlp.items():
            if k == "ambiguous_policy":
                if v not in ("drop", "keep"):
                    _die("required_labeling_policy.ambiguous_policy must be 'drop' or 'keep'")
            elif k in _bool_keys:
                if not isinstance(v, bool):
                    _die("required_labeling_policy.{} must be a boolean".format(k))
            elif k in _frac_keys:
                if (isinstance(v, bool) or not isinstance(v, (int, float))
                        or not math.isfinite(v) or not (0.0 <= v <= 1.0)):
                    _die("required_labeling_policy.{} must be a number in [0,1]".format(k))
            elif k in _int_keys:
                if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                    _die("required_labeling_policy.{} must be a non-negative integer".format(k))
            else:
                _die("required_labeling_policy has unknown field '{}'".format(k))

    # Optional benign_quality_policy [audit v20.41 §8]: PIN the benign-traffic floor + evidence gates in the
    # manifest and validate them HERE, in the central parser, so the WHOLE chain (labeler / orchestrator /
    # merge / finalizer) sees the SAME closed schema and a bad policy fails EARLY — not only at seal time.
    # min_benign_flows is a positive int; the session/evidence gates are optional but strictly typed; unknown
    # keys abort so a typo (e.g. "min_benign_flow") cannot silently disable a gate.
    if "benign_quality_policy" in m:
        bqp = m["benign_quality_policy"]
        if not isinstance(bqp, dict):
            _die("benign_quality_policy must be an object")
        mbf = bqp.get("min_benign_flows")
        if isinstance(mbf, bool) or not isinstance(mbf, int) or mbf < 1:
            _die("benign_quality_policy.min_benign_flows must be a positive int")
        mss = bqp.get("min_successful_sessions")
        if mss is not None and (isinstance(mss, bool) or not isinstance(mss, int) or mss < 1):
            _die("benign_quality_policy.min_successful_sessions must be a positive int")
        msr = bqp.get("min_success_rate")
        if msr is not None and (isinstance(msr, bool) or not isinstance(msr, (int, float))
                                or not math.isfinite(msr) or not (0.0 <= msr <= 1.0)):
            _die("benign_quality_policy.min_success_rate must be a finite number in [0,1]")
        for _bk in ("require_benign_jsonl", "require_browser_evidence"):
            if bqp.get(_bk) is not None and not isinstance(bqp.get(_bk), bool):
                _die("benign_quality_policy.{} must be a boolean".format(_bk))
        _extra = sorted(set(bqp) - {"min_benign_flows", "min_successful_sessions", "min_success_rate",
                                    "require_benign_jsonl", "require_browser_evidence"})
        if _extra:
            _die("benign_quality_policy has unknown key(s): {}".format(_extra))

    # Optional release policy: the campaign may PIN the cross-split duplicate ceiling merge enforces
    # (a float in [0,1]; 0 = no cross-split leakage allowed) [audit v20.17 §11.1].
    if "max_cross_split_duplicate_rate" in m:
        xr = m["max_cross_split_duplicate_rate"]
        if isinstance(xr, bool) or not isinstance(xr, (int, float)) or not (0.0 <= xr <= 1.0):
            _die("max_cross_split_duplicate_rate must be a number in [0,1]")
    # Optional TEMPORAL labeling policy [audit v20.21 §9]: PIN the window-matching rule so the
    # threshold is chosen BEFORE the results are seen (no post-hoc tuning). The KEY's presence is the
    # pin; its value is null (legacy start-in-window) or a finite fraction in [0,1] (overlap). A
    # companion ceiling caps how many flows may fall back to the point rule.
    if "required_min_window_overlap" in m:
        mv = m["required_min_window_overlap"]
        if mv is not None and (isinstance(mv, bool) or not isinstance(mv, (int, float))
                               or not (0.0 <= mv <= 1.0)):
            _die("required_min_window_overlap must be null (legacy) or a number in [0,1]")
    if "max_duration_fallback_rate" in m:
        fr = m["max_duration_fallback_rate"]
        if isinstance(fr, bool) or not isinstance(fr, (int, float)) or not (0.0 <= fr <= 1.0):
            _die("max_duration_fallback_rate must be a number in [0,1]")
        # A fallback ceiling only has meaning in OVERLAP mode (duration fallback exists only there), so
        # it must be paired with an ACTIVE overlap pin — otherwise the manifest appears to govern a
        # policy that is not in force [audit v20.22 §7].
        if m.get("required_min_window_overlap") is None:
            _die("max_duration_fallback_rate requires required_min_window_overlap to be pinned to a "
                 "non-null overlap fraction (fallback only exists in overlap mode)")
    # Optional DOMAIN-realism gate ceiling [audit v20.21 §14]: PIN the max real-vs-synth AUC in the
    # manifest so release-eligibility is judged against a PRE-registered bar, not one the operator
    # picks after seeing the AUC. evaluate lets the CLI only CONFIRM or TIGHTEN it.
    if "max_domain_auc" in m:
        da = m["max_domain_auc"]
        if isinstance(da, bool) or not isinstance(da, (int, float)) or not (0.0 <= da <= 1.0):
            _die("max_domain_auc must be a number in [0,1]")
    # §9 [audit v20.24]: `min_overall_realism_quality` is DEPRECATED at the top level. Its verdict
    # depends on the AXIS thresholds (max_mean_js, ...) that define "strong"; if those aren't pinned too,
    # "strong" is redefinable on the CLI. So the quality bar may ONLY be pinned inside a COMPLETE
    # release_quality_policy block (below) — never loose at the top level.
    if "min_overall_realism_quality" in m:
        _die("min_overall_realism_quality is deprecated at the top level — pin it inside a complete "
             "release_quality_policy (so the axis thresholds that define 'strong' are pinned too) "
             "[audit v20.24 §9]")
    if "min_domain_test_samples_per_class" in m:
        n = m["min_domain_test_samples_per_class"]
        if isinstance(n, bool) or not isinstance(n, int) or n < 1:
            _die("min_domain_test_samples_per_class must be an integer >= 1")
    # §8/§10 [audit v20.24]: a release_quality_policy block, if present, must be COMPLETE — pinning only
    # some fields leaves the rest free on the CLI, which is exactly how "strong" was redefinable. It is
    # also the SINGLE source of the release thresholds it carries: the legacy top-level max_domain_auc /
    # min_domain_test_samples_per_class must NOT also be present (no contradictory dual source). Every
    # field is a FINITE number in a sane range (no inf).
    if "release_quality_policy" in m:
        rqp = m["release_quality_policy"]
        if not isinstance(rqp, dict) or not rqp:
            _die("release_quality_policy must be a non-empty object")
        _num = {"max_domain_auc": (0.0, 1.0), "max_mean_js": (0.0, 1.0), "max_cat_js": (0.0, 1.0),
                "max_cond_js": (0.0, 1.0), "max_missing_rate_difference": (0.0, 1.0),
                "min_tstr_reference_ratio": (0.0, 1.0e6), "min_reference_f1": (0.0, 1.0)}
        required = set(_num) | {"min_overall_realism_quality", "min_domain_test_samples_per_class"}
        unknown = set(rqp) - required
        if unknown:
            _die("release_quality_policy has unknown field(s) {}".format(sorted(unknown)))
        missing = required - set(rqp)
        if missing:                                        # §8: a partial policy is rejected
            _die("release_quality_policy is INCOMPLETE — missing {}. Pin EVERY release threshold so the "
                 "definition of 'strong' can't be relaxed on the CLI [audit v20.24 §8]".format(
                     sorted(missing)))
        for dup in ("max_domain_auc", "min_domain_test_samples_per_class"):
            if dup in m:                                   # §10: single source, no contradiction
                _die("{} is set BOTH at the top level and in release_quality_policy — declare it in ONE "
                     "place [audit v20.24 §10]".format(dup))
        for k, (lo, hi) in _num.items():
            v = rqp[k]
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not (lo <= v <= hi) \
                    or v != v or v in (float("inf"), float("-inf")):
                _die("release_quality_policy.{} must be a finite number in [{},{}]".format(k, lo, hi))
        if rqp["min_overall_realism_quality"] not in ("moderate", "strong"):
            _die("release_quality_policy.min_overall_realism_quality must be 'moderate' or 'strong'")
        n = rqp["min_domain_test_samples_per_class"]
        if isinstance(n, bool) or not isinstance(n, int) or n < 1:
            _die("release_quality_policy.min_domain_test_samples_per_class must be an integer >= 1")

    # Coherence between expected_labels and the per-run attack PLAN [audit 7]: an attack
    # a run declares but the campaign does not expect (or vice-versa) is a contradiction.
    declared_attacks, runs_with_attacks = set(), 0
    for rid, spec in runs.items():
        atk = spec.get("attacks")
        if atk is None:
            continue
        runs_with_attacks += 1
        if not isinstance(atk, list) or not atk:
            _die("run {} 'attacks' must be a non-empty list".format(rid))
        if len(atk) != len(set(map(str, atk))):                # §6: a repeated attack is ambiguous
            _die("run {} 'attacks' has duplicate(s) {} — model repeated runs as distinct events, "
                 "not repeated labels [audit v20.6 §6]".format(rid, atk))
        for a in atk:
            if str(a) not in ATTACK_LABELS:                    # §5: an attack label, never BENIGN
                _die("run {} plans '{}' which is not an ATTACK label {} (BENIGN is not an attack; "
                     "the orchestrator cannot execute it) [audit v20.6 §5]".format(
                         rid, a, sorted(ATTACK_LABELS)))
            if str(a) not in {str(x) for x in exp}:
                _die("run {} plans attack '{}' not in expected_labels {}".format(rid, a, exp))
            declared_attacks.add(str(a))
    if runs_with_attacks == len(runs) and runs_with_attacks:      # every run declares its plan
        want_attacks = {str(x) for x in exp} - {"BENIGN"}
        missing = sorted(want_attacks - declared_attacks)
        if missing:
            _die("expected_labels list attack(s) {} that NO run plans; the manifest is "
                 "incoherent".format(missing))

    # Official/reproducible mode: a manifest that omits seed or day is not a faithful
    # record of the campaign; require both on EVERY run [audit 9]. It must ALSO pin each run's
    # attack PLAN + target + timeout, so a run can never be published official while its status
    # carries events={} — the manifest itself documents what should have happened [audit v20.5 §7].
    if require_reproducible:
        incomplete = sorted(int(rid) for rid, spec in runs.items()
                            if spec.get("seed") is None or spec.get("day") is None)
        if incomplete:
            _die("reproducible mode: run(s) {} are missing 'seed' and/or 'day'".format(
                incomplete))
        for rid, spec in runs.items():
            atk = spec.get("attacks")
            if not isinstance(atk, list) or not atk:
                _die("reproducible mode: run {} must declare a non-empty 'attacks' plan "
                     "(so an events={{}} run can never be official) [audit v20.5 §7]".format(rid))
            # attacker_ip is REQUIRED in official mode: it selects which flows get an attack label,
            # so a wrong/absent one can mislabel another host's traffic [audit v20.8 P0-9].
            for fld in ("target_host", "target_ip", "attacker_ip"):
                if not str(spec.get(fld) or "").strip():
                    _die("reproducible mode: run {} must declare '{}' [audit v20.5 §7 / v20.8 P0-9]"
                         .format(rid, fld))
            # target_ip AND attacker_ip must be real IPs, and target_host a valid DNS hostname, so
            # a malformed manifest can't be declared valid and only blow up at attack time [§7/P0-9].
            # Parse to ipaddress OBJECTS (not strings) and require IPv4: the orchestrator binds an
            # IPv4 socket to discover the local source, so an IPv6 target could never be reached, and
            # object comparison makes attacker!=target robust to equivalent textual forms — e.g.
            # 2001:db8::1 vs 2001:0db8:0:0:0:0:0:1, or 10.0.0.1 written differently [audit v20.9 P1-11].
            ipobj = {}
            for ipf in ("target_ip", "attacker_ip"):
                try:
                    obj = ipaddress.ip_address(str(spec[ipf]).strip())
                except ValueError:
                    _die("reproducible mode: run {} {} '{}' is not a valid IP address "
                         "[audit v20.6 §7 / v20.8 P0-9]".format(rid, ipf, spec.get(ipf)))
                if not isinstance(obj, ipaddress.IPv4Address):
                    _die("reproducible mode: run {} {} '{}' is not IPv4 — this testbed's orchestrator "
                         "uses IPv4 only [audit v20.9 P1-11]".format(rid, ipf, spec.get(ipf)))
                ipobj[ipf] = obj
            if ipobj["attacker_ip"] == ipobj["target_ip"]:     # normalized-object compare, not text
                _die("reproducible mode: run {} attacker_ip == target_ip — the attacker cannot be "
                     "the victim [audit v20.8 P1-12 / v20.9 P1-11]".format(rid))
            if not _is_hostname(str(spec["target_host"]).strip()):
                _die("reproducible mode: run {} target_host '{}' is not a valid DNS hostname "
                     "[audit v20.6 §7 / v20.8 P1-10]".format(rid, spec.get("target_host")))
            to = spec.get("timeout")
            if isinstance(to, bool) or not isinstance(to, int) or to <= 0:
                _die("reproducible mode: run {} 'timeout' must be a positive integer "
                     "[audit v20.5 §7]".format(rid))
            atk_set = {str(a) for a in atk}
            if "DoS" in atk_set:
                ds = spec.get("dos_seconds")
                if isinstance(ds, bool) or not isinstance(ds, int) or ds <= 0:
                    _die("reproducible mode: run {} plans DoS but 'dos_seconds' is not a "
                         "positive integer [audit v20.5 §7]".format(rid))
            # A reproducible BruteForce run must PIN its wordlists (so the try-space is fixed),
            # unless the manifest explicitly opts out with wordlists_pinned:false [audit v20.6 §8].
            if "BruteForce" in atk_set and spec.get("wordlists_pinned") is not False:
                for hk in ("userlist_sha256", "passlist_sha256"):
                    v = spec.get(hk)
                    if not (isinstance(v, str) and len(v) == 64
                            and all(c in "0123456789abcdef" for c in str(v).lower())):
                        _die("reproducible mode: run {} plans BruteForce but '{}' is not a 64-hex "
                             "SHA-256; pin the wordlists or set wordlists_pinned:false to opt out "
                             "(then the run is NOT a full BruteForce reproduction) [audit v20.6 §8]"
                             .format(rid, hk))
    return m


def chronology_ok(train_ts, test_ts, val_ts=None):
    """True iff max(train) < min(val) < max(val) < min(test), strictly, ignoring NaN
    [audit 4]. Returns None if train or test has no finite timestamp (unverifiable).
    Shared by merge/validate/evaluate so the validation run is NEVER ignored.
    """
    import numpy as np

    def _mn(a):
        a = np.asarray(list(a), dtype=float)
        a = a[np.isfinite(a)]
        return a.min() if a.size else None

    def _mx(a):
        a = np.asarray(list(a), dtype=float)
        a = a[np.isfinite(a)]
        return a.max() if a.size else None

    tr_max, te_min = _mx(train_ts), _mn(test_ts)
    if tr_max is None or te_min is None:
        return None
    if val_ts is not None and len(list(val_ts)):
        v_min, v_max = _mn(val_ts), _mx(val_ts)
        if v_min is None or v_max is None:
            return None
        return bool(tr_max < v_min and v_max < te_min)
    return bool(tr_max < te_min)


def bruteforce_unpinned(manifest):
    """True if ANY run plans BruteForce without pinned wordlist hashes (wordlists_pinned:false,
    or a missing/short userlist/passlist sha). Such a campaign does NOT fully reproduce the
    BruteForce password space, so the consumers mark the package DIAGNOSTIC (official=false) —
    it may still LOAD (for pilots), it just cannot claim official [audit v20.7 P0-1]."""
    for spec in (manifest.get("runs") or {}).values():
        if "BruteForce" not in {str(a) for a in (spec.get("attacks") or [])}:
            continue
        if spec.get("wordlists_pinned") is False:
            return True
        for hk in ("userlist_sha256", "passlist_sha256"):
            v = spec.get(hk)
            if not (isinstance(v, str) and len(v) == 64
                    and all(c in "0123456789abcdef" for c in v.lower())):
                return True
    return False


def runs_in_split(manifest, split):
    """Sorted run_ids assigned to a split ('train'/'validation'/'test')."""
    return sorted(int(r) for r, s in (manifest.get("runs") or {}).items()
                  if s.get("split") == split)


def config_of_run(manifest, run_id):
    """The config_id a manifest assigns to run_id (or None)."""
    spec = (manifest.get("runs") or {}).get(str(run_id))
    return spec.get("config_id") if spec else None


def split_of_run(manifest, run_id):
    """The split a manifest assigns to run_id (or None)."""
    spec = (manifest.get("runs") or {}).get(str(run_id))
    return spec.get("split") if spec else None
