#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
merge_and_split.py  (version: see CODE_VERSION below — aborts on temporal leakage)
=================================================================================

Merge several labeled capture runs and produce a TEMPORAL train/test split.
Training timestamps must STRICTLY precede test timestamps, otherwise the model
"sees the future" [Arp et al. 2022, P3; Survey §6.3; Ring et al. 2019].

WHAT CHANGED vs v1 (addresses the audit)
----------------------------------------
  * Fail-closed: if the chosen split leaks time (max(train) >= min(test)), the
    program ABORTS and writes nothing, unless --allow-leak is given.
  * Strict inequality (< , not <=) to match "strictly precedes".
  * --drop-ids now also removes dst_port (a known shortcut).
  * Reports exact-duplicate feature rows that span more than one run
    (near-duplicate leakage across runs).

USAGE
-----
  python3 merge_and_split.py labeled_run0.csv labeled_run1.csv labeled_run2.csv
  python3 merge_and_split.py synthetic_nids_dataset.csv --test-run 2 --drop-ids
"""

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys

import numpy as np
import pandas as pd

import campaign as camp
import provenance as prov               # shared campaign-authentication chain [audit 9]
import feature_schema as fs

# SINGLE source of truth for THIS tool's version — written into the package provenance (was a "v7"
# code_version beside a stale "v2" header) [audit v20.15 doc/impl consistency].
CODE_VERSION = "merge_and_split/v15"   # v15: temporal tie is per-window, per-CLASS, at the overlap FRACTION [§5/§6/§7]; v14: window/timestamp tie


def _finite_rate(value):
    """argparse type: a FINITE number in [0,1]. Rejects nan/inf/out-of-range, so a bogus ceiling
    like `--max-cross-split-duplicate-rate nan` can never slip the gate (every NaN comparison is
    False) or poison the provenance JSON [audit v20.20 §5]."""
    try:
        x = float(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("expected a number, got {!r}".format(value))
    if not math.isfinite(x) or not (0.0 <= x <= 1.0):
        raise argparse.ArgumentTypeError("expected a finite value in [0,1], got {!r}".format(value))
    return x


def _sha256(path):
    """SHA-256 of a file, or None if unreadable (provenance) [audit 21]."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _git_commit():
    """Best-effort current git commit (None if not a repo / git absent) [audit 21]."""
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True,
                             text=True, timeout=5)
        return out.stdout.strip() or None if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None

# Identifier / metadata columns that must never be learned as features.
ID_COLS = ["uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
           "src_ip", "ttl", "flow_id", "dst_port", "matched_event_id",
           "ambiguity_reason"]
TIME_CANDIDATES = ["timestamp", "ts"]
NON_FEATURE = set(ID_COLS) | {"label", "run_id", "timestamp", "ts",
                              "ambiguous", "ambiguity_reason"}
# Split metadata: used internally to build the split, ALWAYS stripped from the
# written train/test files so it never becomes a feature [audit 3].
SPLIT_METADATA = ["run_id", "timestamp", "ts"]


def write_manifest(df, split_indices, time_col, path):
    """Write an auditable split manifest (split, run_id, row count, ts range).

    `split_indices` maps a split name ('train'/'val'/'test') to the row index it
    covers in `df` (which still has run_id/timestamp) [audit 19].
    """
    rows = []
    for split_name, idx in split_indices.items():
        for rid, g in df.loc[idx].groupby("run_id"):
            tmin = tmax = ""
            if time_col:
                t = pd.to_numeric(g[time_col], errors="coerce")
                tmin, tmax = int(t.min()), int(t.max())
            rows.append({"split": split_name, "run_id": int(rid),
                         "n_rows": len(g), "ts_min": tmin, "ts_max": tmax})
    pd.DataFrame(rows).to_csv(path, index=False)


def infer_run_id(path, order):
    m = re.search(r"run[_-]?(\d+)", path, flags=re.IGNORECASE)
    return int(m.group(1)) if m else order


def load_runs(paths):
    # SCHEMA-AWARE read so categorical values (tls_version='1.3', alpn, ja3…) are strings in EVERY
    # file — otherwise pandas infers a float in one and object in another and the merge rejects a
    # valid run on a spurious dtype mismatch [audit v20.7 P0-2].
    if len(paths) == 1:
        df = fs.read_common_csv(paths[0])
        if "run_id" not in df.columns:
            df["run_id"] = infer_run_id(paths[0], 0)
        return df
    loaded = []
    for i, p in enumerate(paths):
        df = fs.read_common_csv(p)
        if "run_id" not in df.columns:
            df["run_id"] = infer_run_id(p, i)
        loaded.append((p, df))
    # Refuse to silently merge incompatible schemas [audit 15]: identical columns.
    ref = set(loaded[0][1].columns)
    for p, df in loaded[1:]:
        cols = set(df.columns)
        if cols != ref:
            sys.exit("ABORT: schema mismatch in {} (missing={}, extra={}). All "
                     "runs must share the same columns.".format(
                         p, sorted(ref - cols), sorted(cols - ref)))
    # Also refuse incompatible dtypes for shared columns [audit 8.2].
    for col in loaded[0][1].columns:
        numeric = [pd.api.types.is_numeric_dtype(df[col]) for _, df in loaded]
        if len(set(numeric)) > 1:
            bad = [p for p, df in loaded
                   if not pd.api.types.is_numeric_dtype(df[col])
                   and pd.to_numeric(df[col], errors="coerce").isna().sum() > df[col].isna().sum()]
            if bad:
                sys.exit("ABORT: column '{}' has incompatible dtypes across runs "
                         "(non-numeric in {}). [audit 8.2]".format(col, bad))
    return pd.concat([df for _, df in loaded], ignore_index=True)


def pick_time_col(df):
    for c in TIME_CANDIDATES:
        if c in df.columns and pd.to_numeric(df[c], errors="coerce").notna().any():
            return c
    return None


def check_temporal(train, test, time_col):
    """Return (ok, tr_max, te_min); ok requires STRICT max(train) < min(test)."""
    if not time_col:
        return None, None, None
    tr_max = pd.to_numeric(train[time_col], errors="coerce").max()
    te_min = pd.to_numeric(test[time_col], errors="coerce").min()
    return (tr_max < te_min), tr_max, te_min


def duplicate_stats(df, split_of_index=None):
    """Quantify identical-feature collisions for the provenance, BEFORE publication [audit 12].

    Uses the 15 COMMON features (never run_id/timestamp/label). Returns counts plus the
    feature-groups whose rows carry MORE THAN ONE label — identical features with
    different labels is unresolvable noise and must abort. cross_split counts groups whose
    rows fall in >1 split (train/val/test), the leakage that actually matters.
    """
    feat = [c for c in fs.EXTENDED if c in df.columns]
    out = {"exact_duplicate_groups": 0, "cross_run_duplicate_groups": 0,
           "cross_split_duplicate_groups": 0, "cross_split_duplicate_rows": 0,
           # rate_raw is UNROUNDED — the gate decides on it so 2 rows in millions can't round to 0.0
           # and slip a 0 ceiling; rate is rounded for display only [audit v20.18 §7].
           "cross_split_duplicate_rate": 0.0, "cross_split_duplicate_rate_raw": 0.0,
           "conflicting_label_groups": 0, "conflicting_examples": []}
    if not feat:
        return out
    dup = df[df.duplicated(subset=feat, keep=False)]
    if dup.empty:
        return out
    grp = dup.groupby(feat, dropna=False)
    out["exact_duplicate_groups"] = int(grp.ngroups)
    if "run_id" in df.columns:
        out["cross_run_duplicate_groups"] = int((grp["run_id"].nunique() > 1).sum())
    if "label" in df.columns:
        out["conflicting_label_groups"] = int((grp["label"].nunique() > 1).sum())
        for _keys, sub in grp:
            if sub["label"].nunique() > 1:
                out["conflicting_examples"].append(sorted(set(map(str, sub["label"]))))
                if len(out["conflicting_examples"]) >= 5:
                    break
    if split_of_index is not None:
        tmp = dup.assign(_split=[split_of_index.get(i) for i in dup.index])
        g2 = tmp.groupby(feat, dropna=False)["_split"].nunique()
        out["cross_split_duplicate_groups"] = int((g2 > 1).sum())
        # ROWS that live in a cross-split group, and their share of the WHOLE dataset — the actual
        # leakage RATE a release can gate on [audit v20.16 §9.5].
        cross_mask = tmp.groupby(feat, dropna=False)["_split"].transform("nunique") > 1
        out["cross_split_duplicate_rows"] = int(cross_mask.sum())
        raw = (int(cross_mask.sum()) / len(df)) if len(df) else 0.0
        out["cross_split_duplicate_rate_raw"] = raw            # UNROUNDED — for the decision
        out["cross_split_duplicate_rate"] = round(raw, 6)      # rounded — for display
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Merge runs + temporal split (fail-closed) ({}).".format(CODE_VERSION))
    ap.add_argument("csvs", nargs="+")
    ap.add_argument("--test-run", type=int, default=None)
    ap.add_argument("--val-run", type=int, default=None,
                    help="hold out a THIRD run for validation, producing train/val/"
                         "test so tuning never touches the test set (run-based split "
                         "only; requires train < val < test chronologically) [audit 19]")
    ap.add_argument("--expected-labels", nargs="+", default=None,
                    help="classes the campaign expects in EVERY split; abort if any "
                         "split lacks one (unless --allow-missing-expected-labels) [audit 5]")
    ap.add_argument("--allow-missing-expected-labels", action="store_true",
                    help="downgrade a missing expected class to a warning (diagnostic)")
    ap.add_argument("--campaign", default=None,
                    help="campaign manifest (campaign.py): sets expected_labels and, if "
                         "--test-run/--val-run are omitted, derives them from the run->"
                         "split assignment (reserved-test configs enforced) [audit 11/12]")
    ap.add_argument("--status", nargs="+", default=None,
                    help="labeler *_run_status.json sidecars to AUTHENTICATE the inputs "
                         "against --campaign: each input's SHA-256 must equal the status' "
                         "split_ready_sha256, and the status' campaign_id/campaign_sha256/"
                         "config_id/split must match the manifest. Omit to auto-discover "
                         "'<input>'.replace('_split_ready.csv','_run_status.json') [audit 6]")
    ap.add_argument("--require-status", action="store_true",
                    help="with --campaign, ABORT if any input lacks an authenticated "
                         "status sidecar — the merge then PROVES every CSV came from the "
                         "declared campaign, not just that run_ids/classes line up [audit 6]")
    ap.add_argument("--allow-diagnostic-status", action="store_true",
                    help="include inputs whose status is DIAGNOSTIC (labeled with a "
                         "loosened gate: --use-failed/--allow-empty/keep/etc). By default "
                         "a diagnostic run is refused in an official package [audit 5]")
    ap.add_argument("--allow-missing-required-policy", action="store_true",
                    help="with --require-status, allow a campaign that does NOT declare a "
                         "required_labeling_policy (default: official mode demands one, so a "
                         "weak-policy run cannot slip through) [audit v20 P0-9]")
    ap.add_argument("--allow-unauthenticated-inputs", action="store_true",
                    help="with --campaign, run WITHOUT byte-authentication of the inputs "
                         "(default: --require-status is demanded). Marks the package "
                         "DIAGNOSTIC (official=false in the provenance) [audit v20.2 P0-6]")
    ap.add_argument("--allow-extra-campaign-labels", action="store_true",
                    help="permit classes NOT declared in the campaign's expected_labels "
                         "(default: with --campaign the observed classes must EQUAL "
                         "expected_labels, not merely include them) [audit 7]")
    ap.add_argument("--dup-label-conflicts-ok", action="store_true",
                    help="downgrade identical-feature rows with DIFFERENT labels from an "
                         "abort to a warning (default: abort — it is unresolvable label "
                         "noise) [audit 12]")
    ap.add_argument("--max-cross-split-duplicate-rate", type=_finite_rate, default=None,
                    help="FAIL-CLOSED ceiling on the share of rows that are identical-feature "
                         "duplicates spanning >1 split (0 = none allowed). Above it, ABORT unless "
                         "--allow-cross-split-duplicates. The rate is ALWAYS recorded in the "
                         "provenance regardless of this flag [audit v20.16 §9.5]")
    ap.add_argument("--allow-cross-split-duplicates", action="store_true",
                    help="downgrade exceeding --max-cross-split-duplicate-rate from an abort to a "
                         "DIAGNOSTIC package (records 'cross_split_duplicates') [audit v20.16 §9.5]")
    ap.add_argument("--allow-incomplete-campaign", action="store_true",
                    help="with --campaign, do NOT require seed+day on every run (default: "
                         "official mode requires a reproducible manifest) [audit 11]")
    ap.add_argument("--time-frac", type=float, default=None,
                    help="hold out the latest fraction OF ROWS by time")
    ap.add_argument("--prefix", default="dataset")
    ap.add_argument("--drop-ids", action="store_true",
                    help="drop identifier columns (IPs/ports/uid/dst_port)")
    ap.add_argument("--allow-leak", action="store_true",
                    help="write outputs even if the split leaks time (NOT advised)")
    ap.add_argument("--i-trust-run-order", action="store_true",
                    help="accept a run-based split WITHOUT timestamps (trust the "
                         "filename order); otherwise abort when chronology is unverifiable")
    ap.add_argument("--overwrite", action="store_true",
                    help="replace existing output files (default: abort if they exist) [audit 6]")
    ap.add_argument("--allow-extra-labels", action="store_true",
                    help="permit labels outside feature_schema.ALLOWED_LABELS "
                         "(default: abort on any unknown class) [audit 8]")
    ap.add_argument("--allow-within-run-split", action="store_true",
                    help="DIAGNOSTIC: allow a --time-frac cut that falls inside a run "
                         "(train/test share a session/tool); official splits fall on "
                         "run boundaries [audit 10]")
    ap.add_argument("--allow-partial-schema", action="store_true",
                    help="skip the strict official-schema check (run_id + timestamp + "
                         "the 15 COMMON features + label, all numeric columns clean); "
                         "use only for ad-hoc inputs, never an official split [audit 13]")
    args = ap.parse_args()

    # A campaign manifest is the single source of truth [audit 11/12]: it supplies
    # expected_labels and the run->split assignment. We keep the FULL run SETS (not a
    # single test/val run) so EVERY test run is held out and none leaks into train
    # [audit 4].
    campaign_sets = None
    if args.campaign:
        # Official mode: the manifest must be reproducible (seed+day on every run) unless
        # explicitly relaxed [audit 11].
        manifest = camp.load(args.campaign,
                             require_reproducible=not args.allow_incomplete_campaign)
        m_labels = sorted(manifest["expected_labels"])
        if args.expected_labels is not None and sorted(args.expected_labels) != m_labels:
            sys.exit("ABORT: --expected-labels {} contradicts the campaign manifest {}; "
                     "the manifest is the source of truth. [audit 6]".format(
                         sorted(args.expected_labels), m_labels))
        args.expected_labels = m_labels                   # manifest wins [audit 6]
        campaign_sets = {
            "train": set(camp.runs_in_split(manifest, "train")),
            "validation": set(camp.runs_in_split(manifest, "validation")),
            "test": set(camp.runs_in_split(manifest, "test")),
        }
        if not campaign_sets["train"] or not campaign_sets["test"]:
            sys.exit("ABORT: campaign must declare train AND test runs. [audit 4]")
        # Authenticate every input CSV against the campaign via the labeler status
        # sidecars (shared chain in provenance.py): prove each file came from THIS
        # campaign, bind the CSV's run_id to the status, reject diagnostic runs, and
        # require the runs to cover the campaign exactly once [audit 4/5/6/9].
        # With a campaign, byte-authentication is the DEFAULT; opting out is explicit and
        # makes the package DIAGNOSTIC, not official [audit v20.2 P0-6].
        if not args.require_status and not args.allow_unauthenticated_inputs:
            sys.exit("ABORT: an official merge with --campaign needs --require-status (one "
                     "*_run_status.json* per input). Pass --require-status, or "
                     "--allow-unauthenticated-inputs to build a DIAGNOSTIC package. "
                     "[audit v20.2 P0-6]")
        if args.require_status:                           # official mode needs a policy [audit v20 P0-9]
            prov.require_official_policy(manifest, args.allow_missing_required_policy)
        auth_records = prov.authenticate_against_campaign(
            args.csvs, args.status, manifest, args.campaign, args.require_status,
            allow_diagnostic=args.allow_diagnostic_status)
        # §8 [audit v20.20]: the window-matching policy (`min_window_overlap`, None=legacy) must be
        # IDENTICAL across every authenticated run — otherwise the split silently mixes legacy
        # start-in-window labeling with overlap labeling, and the ground truth is not comparable
        # run-to-run. (Authenticated runs only; unauthenticated/diagnostic packages skip this.)
        if auth_records:
            overlaps = {(r.get("run_id")): r.get("min_window_overlap")
                        for r in auth_records if r.get("status_authenticated")}
            distinct = set(overlaps.values())
            if len(distinct) > 1:
                sys.exit("ABORT: runs were labeled with DIFFERENT --min-window-overlap policies "
                         "{} — a split must use ONE window-matching rule for all runs. Re-label the "
                         "outliers to match. [audit v20.20 §8]".format(
                             {str(k): v for k, v in sorted(overlaps.items(), key=lambda t: str(t[0]))}))
            # §9 [audit v20.21]: if the campaign PINS the temporal policy, the runs must actually match
            # the pinned value — not merely agree with each other on some other value.
            if "required_min_window_overlap" in manifest and distinct:
                pin = manifest["required_min_window_overlap"]
                if distinct != {pin}:
                    sys.exit("ABORT: campaign PINS required_min_window_overlap={!r} but the "
                             "authenticated runs used {} — the labeling does not match the "
                             "pre-registered temporal policy. [audit v20.21 §9]".format(
                                 pin, sorted(distinct, key=str)))
            # §5 [audit v20.22]: RE-VALIDATE the duration-fallback RATE against the campaign's pinned
            # ceiling here (the labeler enforced it too, but the consumer must not trust that). A forged
            # status that quietly exceeds the pinned ceiling — even claiming non-diagnostic — is caught.
            fb_ceiling = manifest.get("max_duration_fallback_rate")
            if fb_ceiling is not None:
                for r in auth_records:
                    if not r.get("status_authenticated"):
                        continue
                    oa = r.get("overlap_accounting") or {}
                    m, fb = oa.get("matched_flows", 0), oa.get("duration_fallback_flows", 0)
                    if m > 0 and (fb / m) > fb_ceiling:
                        sys.exit("ABORT: run {} has duration-fallback rate {:.4f} ({}/{}) above the "
                                 "campaign's pinned max_duration_fallback_rate {} — the overlap policy "
                                 "did not apply to enough flows. [audit v20.22 §5]".format(
                                     r.get("run_id"), fb / m, fb, m, fb_ceiling))
        all_runs = (camp.runs_in_split(manifest, "train")
                    + camp.runs_in_split(manifest, "validation")
                    + camp.runs_in_split(manifest, "test"))
        campaign_prov = {
            "path": args.campaign, "sha256": _sha256(args.campaign),
            "campaign_id": str(manifest.get("campaign_id") or ""),
            "runs": {str(r): {"config_id": camp.config_of_run(manifest, r),
                              "split": camp.split_of_run(manifest, r)}
                     for r in all_runs},
        }
    else:
        if args.status or args.require_status:
            sys.exit("ABORT: --status/--require-status require --campaign (the manifest is "
                     "the reference to authenticate against). [audit 6]")
        auth_records, campaign_prov = None, None

    # Refuse the SAME input given twice — it would double a run and inflate the
    # split while report_duplicates stays 0 (same run_id) [audit 13].
    seen_hash = {}
    for p in args.csvs:
        h = _sha256(p)
        if h is not None and h in seen_hash:
            sys.exit("ABORT: duplicate input '{}' has identical content to '{}'. "
                     "[audit 13]".format(p, seen_hash[h]))
        seen_hash[h] = p

    df = load_runs(args.csvs)
    if "label" not in df.columns:
        sys.exit("No 'label' column found.")
    # No missing/empty labels and (unless overridden) no stray classes [audit 4/8].
    fs.require_valid_labels(df["label"], "merge input", allow_extra=args.allow_extra_labels)
    # A campaign declares its EXACT class set: an UNPLANNED class (e.g. PortScan traffic
    # in a BENIGN/DoS-only campaign) must abort, not be silently kept [audit 7].
    if campaign_sets is not None and not args.allow_extra_campaign_labels:
        observed = set(str(x) for x in pd.Series(df["label"]).dropna().unique())
        expected = set(str(x) for x in manifest["expected_labels"])
        extra = sorted(observed - expected)
        if extra:
            sys.exit("ABORT: class(es) {} are NOT in the campaign expected_labels {} — a "
                     "campaign declares its EXACT set, not a minimum. Pass "
                     "--allow-extra-campaign-labels to keep them. [audit 7]".format(
                         extra, sorted(expected)))
    # Official split-ready contract: EXACTLY run_id + timestamp + the 15 COMMON +
    # label — no missing AND no EXTRA columns (an extra like matched_event_id would
    # leak the ground truth), clean numerics, and canonical order [audit 3/13].
    # EXTENDED, not COMMON: the split-ready now carries the flowmeter features too, and
    # this contract is EXACT — leaving it at COMMON makes merge abort on every v2 run.
    required = ["run_id", "timestamp"] + fs.EXTENDED + ["label"]
    if not args.allow_partial_schema:
        actual = set(df.columns)
        missing = sorted(set(required) - actual)
        extra = sorted(actual - set(required))
        if missing or extra:
            sys.exit("ABORT: official schema mismatch — missing={} extra={}. Expected "
                     "EXACTLY run_id + timestamp + the 15 COMMON features + label (the "
                     "labeler's *_split_ready.csv*). An extra column (e.g. "
                     "matched_event_id) leaks the ground truth. Pass "
                     "--allow-partial-schema for ad-hoc inputs. [audit 3/13]".format(
                         missing, extra))
        corrupt = []
        for col in fs.COMMON_NUMERIC:
            coerced = pd.to_numeric(df[col], errors="coerce")
            n_bad = int((df[col].notna() & coerced.isna()).sum())   # junk, not blank
            if n_bad:
                corrupt.append("{}={}".format(col, n_bad))
        if corrupt:
            sys.exit("ABORT: non-numeric junk in COMMON numeric column(s) [{}] (e.g. "
                     "'BAD'). [audit 13]".format(", ".join(corrupt)))
        errs, warns = fs.common_contract_violations(df)             # value + relational [audit 4/6]
        for w in warns:
            print("WARNING (value domain): {}".format(w))
        if errs:
            sys.exit("ABORT: COMMON contract violated: {}. inf/negatives/fractional "
                     "counts, out-of-domain categoricals, and derived features that do "
                     "not match their inputs are not allowed in an official split. "
                     "[audit 4/6]".format("; ".join(errs)))
        df = df[required].copy()                                     # canonical order [audit 3]
    if "run_id" in df.columns:                        # complete/integer/non-negative [audit 3]
        rv = pd.to_numeric(df["run_id"], errors="coerce").to_numpy(dtype=float)
        if not np.isfinite(rv).all() or not np.all(rv == np.floor(rv)) or (rv < 0).any():
            sys.exit("ABORT: run_id must be present, integer and non-negative. [audit 3]")
    time_col = pick_time_col(df)
    if args.time_frac is not None and not (0 < args.time_frac < 1):
        sys.exit("--time-frac must be in (0, 1).")
    if time_col is not None:
        t = pd.to_numeric(df[time_col], errors="coerce").to_numpy(dtype=float)
        if not bool(np.isfinite(t).all()):        # NaN or inf anywhere -> abort
            sys.exit("ABORT: '{}' has {} missing/non-finite value(s); the official "
                     "split needs a valid timestamp for EVERY flow. [audit 3]".format(
                         time_col, int((~np.isfinite(t)).sum())))
        df = df.sort_values(time_col, kind="mergesort").reset_index(drop=True)

    val = None                                        # optional 3-way split [audit 19]
    within_run_split = False
    if campaign_sets is not None:
        # The manifest DICTATES the split: use the FULL run sets so EVERY declared
        # test run is held out and none leaks into train; require the CSV runs to
        # match the manifest exactly (no extra/missing run) [audit 4].
        if args.time_frac is not None:
            sys.exit("--time-frac cannot be combined with --campaign. [audit 4]")
        present = set(int(r) for r in
                      pd.to_numeric(df["run_id"], errors="coerce").dropna().unique())
        declared = (campaign_sets["train"] | campaign_sets["validation"]
                    | campaign_sets["test"])
        if present != declared:
            sys.exit("ABORT: CSV runs {} != campaign runs {} (no extra/missing run "
                     "allowed). [audit 4]".format(sorted(present), sorted(declared)))
        train = df[df["run_id"].isin(campaign_sets["train"])].copy()
        test = df[df["run_id"].isin(campaign_sets["test"])].copy()
        if campaign_sets["validation"]:
            val = df[df["run_id"].isin(campaign_sets["validation"])].copy()
        how = "campaign: train {} | val {} | test {}".format(
            sorted(campaign_sets["train"]), sorted(campaign_sets["validation"]),
            sorted(campaign_sets["test"]))
    elif args.time_frac is not None:
        if args.val_run is not None:
            sys.exit("--val-run is run-based; do not combine it with --time-frac. [audit 19]")
        if not time_col:
            sys.exit("--time-frac needs a 'timestamp' or 'ts' column.")
        cut = int((1.0 - args.time_frac) * len(df))
        train, test = df.iloc[:cut].copy(), df.iloc[cut:].copy()
        how = "latest {:.0%} of rows by {}".format(args.time_frac, time_col)
        # A row-fraction cut can slice through the MIDDLE of a run, so train and
        # test share a session/tool/config/fingerprint — a dependency even without
        # time inversion. Official splits must fall on run boundaries [audit 10].
        if "run_id" in df.columns:
            shared = (set(pd.to_numeric(train["run_id"], errors="coerce").dropna())
                      & set(pd.to_numeric(test["run_id"], errors="coerce").dropna()))
            within_run_split = bool(shared)
        else:
            within_run_split = True                   # cannot even check -> treat as within-run
        if within_run_split and not args.allow_within_run_split:
            sys.exit("ABORT: --time-frac cut falls INSIDE run(s) {} (train and test "
                     "share them), so train/test share a session/tool/config. Split on "
                     "run boundaries (run-based --test-run) or pass "
                     "--allow-within-run-split (diagnostic). [audit 10]".format(
                         sorted(shared) if "run_id" in df.columns else "unknown"))
    else:
        runs = sorted(int(r) for r in df["run_id"].unique())
        if len(runs) < 2:
            sys.exit("Only one run present. Capture more runs or use --time-frac.")
        test_run = args.test_run if args.test_run is not None else runs[-1]
        if test_run not in runs:
            sys.exit("test-run {} not in runs {}".format(test_run, runs))
        if args.val_run is not None:                  # train / val / test [audit 19]
            if args.val_run not in runs:
                sys.exit("val-run {} not in runs {}".format(args.val_run, runs))
            if args.val_run == test_run:
                sys.exit("--val-run must differ from --test-run. [audit 19]")
            if len(runs) < 3:
                sys.exit("--val-run needs >=3 runs (train must keep >=1). [audit 19]")
            test = df[df["run_id"] == test_run].copy()
            val = df[df["run_id"] == args.val_run].copy()
            train = df[~df["run_id"].isin([args.val_run, test_run])].copy()
            how = "train {} | val run_id=={} | test run_id=={}".format(
                sorted(set(runs) - {args.val_run, test_run}), args.val_run, test_run)
        else:
            test = df[df["run_id"] == test_run].copy()
            train = df[df["run_id"] != test_run].copy()
            how = "hold out run_id == {} (runs: {})".format(test_run, runs)

    if train.empty or test.empty or (val is not None and val.empty):
        sys.exit("ABORT: empty train/val/test split.")
    if test["label"].nunique() < 2:
        print("WARNING: test split has <2 classes ({}) — a multiclass evaluation "
              "on it is not meaningful [audit 3].".format(sorted(test["label"].unique())))
    # Every class the campaign EXPECTS must appear in EACH split [audit 5].
    if args.expected_labels:
        want = set(args.expected_labels)
        checkable = [("train", train), ("test", test)] + (
            [("val", val)] if val is not None else [])
        gaps = {nm: sorted(want - set(d["label"])) for nm, d in checkable
                if want - set(d["label"])}
        if gaps and not args.allow_missing_expected_labels:
            sys.exit("ABORT: expected class(es) missing from split(s) {}. A failed "
                     "attack run may have dropped a class; capture it, or pass "
                     "--allow-missing-expected-labels (diagnostic). [audit 5]".format(gaps))
        if gaps:
            print("WARNING: expected class(es) missing {} (diagnostic split) [audit 5].".format(gaps))

    # --- Fail-closed temporal check BEFORE writing anything ---
    ok, tr_max, te_min = check_temporal(train, test, time_col)
    chronology_check_passed = None                     # None = could not check
    if time_col:
        print("Temporal check: max(train)={} min(test)={} strict<? {}".format(
            tr_max, te_min, ok))
        chronology_check_passed = bool(ok)
        if not ok and not args.allow_leak:
            sys.exit("ABORT: split leaks time (train does not strictly precede "
                     "test). Nothing written. [Arp 2022 P3]")
        if val is not None:                            # need train < val < test [audit 19]
            train_t = pd.to_numeric(train[time_col], errors="coerce")
            val_t = pd.to_numeric(val[time_col], errors="coerce")
            test_t = pd.to_numeric(test[time_col], errors="coerce")
            chron = bool(train_t.max() < val_t.min() and val_t.max() < test_t.min())
            print("Temporal check (3-way): train<val<test strict<? {}".format(chron))
            chronology_check_passed = chronology_check_passed and chron
            if not chron and not args.allow_leak:
                sys.exit("ABORT: 3-way split leaks time (need train < val < test). "
                         "Nothing written. [audit 19]")
    elif args.time_frac is None and not args.i_trust_run_order:
        sys.exit("ABORT: no timestamp to verify chronology and run_id was inferred "
                 "from filenames. Provide files with a 'timestamp'/'ts' column, or "
                 "pass --i-trust-run-order to accept the filename order. [audit 3]")
    # "verified" requires a TIMESTAMP that actually PASSED the check and no leak
    # override — a trusted run-order or an --allow-leak publish is NOT verified,
    # even though the timestamp column exists [audit 9].
    timestamp_available = time_col is not None
    chronology_verified = bool(timestamp_available and chronology_check_passed
                               and not args.allow_leak and not within_run_split)

    # Ordered split set (train, [val], test). Strip split metadata so a naive user
    # cannot train on run_id/timestamp; keep the pre-strip index for the manifest.
    split_frames = [("train", train)] + ([("val", val)] if val is not None else []) + [("test", test)]
    strip = list(SPLIT_METADATA) + ([c for c in ID_COLS] if args.drop_ids else [])
    split_frames = [(nm, d.drop(columns=[c for c in strip if c in d.columns]))
                    for nm, d in split_frames]
    split_indices = {nm: d.index for nm, d in split_frames}

    # Quantify identical-feature collisions BEFORE publishing. A group with identical
    # features but DIFFERENT labels is unresolvable noise -> abort (unless downgraded);
    # cross-run/cross-split counts go into the provenance as leakage evidence [audit 12].
    split_of_index = {}
    for nm, d in [("train", train)] + ([("val", val)] if val is not None else []) + [("test", test)]:
        for i in d.index:
            split_of_index[i] = nm
    dup_stats = duplicate_stats(df, split_of_index)
    if dup_stats["conflicting_label_groups"] and not args.dup_label_conflicts_ok:
        sys.exit("ABORT: {} feature-group(s) have IDENTICAL features but DIFFERENT labels "
                 "(e.g. {}); this is unresolvable label noise. Fix the source or pass "
                 "--dup-label-conflicts-ok. [audit 12]".format(
                     dup_stats["conflicting_label_groups"], dup_stats["conflicting_examples"][:3]))
    if dup_stats["cross_split_duplicate_groups"]:
        print("WARNING: {} duplicate feature-group(s) / {} row(s) (rate {}) span >1 SPLIT "
              "(train/val/test) — possible leakage. [audit 12]".format(
                  dup_stats["cross_split_duplicate_groups"], dup_stats["cross_split_duplicate_rows"],
                  dup_stats["cross_split_duplicate_rate"]))
    # The cross-split duplicate CEILING [audit v20.16 §9.5 / v20.17 §11.1 / v20.18 §6/§7].
    # The campaign manifest is AUTHORITATIVE: the CLI may CONFIRM or TIGHTEN a pinned ceiling but
    # NEVER RELAX it (a looser CLI aborts, unless --allow-cross-split-duplicates makes the package
    # diagnostic). Sources: CLI, manifest (`max_cross_split_duplicate_rate`), or the OFFICIAL default
    # 0.0 (a complete campaign with no ceiling anywhere). The decision uses the UNROUNDED rate, and a
    # 0 ceiling rejects ANY cross-split row, so leakage can't hide behind rounding [§7].
    xrows = dup_stats["cross_split_duplicate_rows"]
    xraw = dup_stats["cross_split_duplicate_rate_raw"]
    cli_ceiling = args.max_cross_split_duplicate_rate      # NaN/inf already rejected by _finite_rate
    manifest_ceiling = None
    if args.campaign is not None and manifest.get("max_cross_split_duplicate_rate") is not None:
        manifest_ceiling = float(manifest["max_cross_split_duplicate_rate"])
    # An OFFICIAL campaign (complete manifest) with NO pinned ceiling is fail-closed at 0.0. This
    # floor exists INDEPENDENTLY of the CLI [audit v20.20 §6], so a permissive --max-... can no longer
    # erase it just because the manifest omitted the field.
    official_default = (0.0 if (args.campaign is not None and not args.allow_incomplete_campaign
                                and manifest_ceiling is None) else None)
    # The AUTHORITATIVE floor the campaign imposes; the CLI may only CONFIRM or TIGHTEN it.
    authoritative = manifest_ceiling if manifest_ceiling is not None else official_default
    auth_source = ("manifest" if manifest_ceiling is not None
                   else ("official_default" if official_default is not None else None))
    ceiling_override_used = False
    if authoritative is not None and cli_ceiling is not None and cli_ceiling > authoritative:
        if not args.allow_cross_split_duplicates:
            sys.exit("ABORT: --max-cross-split-duplicate-rate {} is MORE PERMISSIVE than the "
                     "authoritative ({}) ceiling {} — the campaign is authoritative; the CLI may only "
                     "confirm or tighten it. Match/lower the CLI, or pass "
                     "--allow-cross-split-duplicates (diagnostic). [audit v20.18 §6 / v20.20 §6]".format(
                         cli_ceiling, auth_source, authoritative))
        ceiling_override_used = True
    if ceiling_override_used:
        xdup_ceiling, ceiling_source = cli_ceiling, "cli_override"
    else:
        _bounds = [b for b in (cli_ceiling, authoritative) if b is not None]
        xdup_ceiling = min(_bounds) if _bounds else None   # STRICTEST of the floor and the CLI
        if xdup_ceiling is None:
            ceiling_source = None
        elif authoritative is not None and xdup_ceiling == authoritative:
            ceiling_source = auth_source
        else:
            ceiling_source = "cli"
    if xdup_ceiling is None:
        exceeds = False                                   # no ceiling in force (pilot / no campaign)
    elif xdup_ceiling == 0.0:
        exceeds = xrows > 0                               # 0 ceiling: ANY cross-split row is leakage
    else:
        exceeds = xraw > xdup_ceiling                     # RAW (unrounded) rate [§7]
    xdup_diagnostic = ceiling_override_used or (
        xdup_ceiling is not None and exceeds and args.allow_cross_split_duplicates)
    if xdup_ceiling is not None and exceeds and not args.allow_cross_split_duplicates:
        sys.exit("ABORT: cross-split duplicate leakage — {} row(s) (raw rate {}) exceed the ceiling "
                 "{} (source={}). Regenerate without the leakage, tighten the ceiling, or pass "
                 "--allow-cross-split-duplicates (diagnostic). [audit v20.18 §6/§7]".format(
                     xrows, xraw, xdup_ceiling, ceiling_source))
    dup_stats["cross_split_duplicate_ceiling"] = {         # full audit trail in the provenance [§6]
        "effective": xdup_ceiling, "source": ceiling_source, "manifest": manifest_ceiling,
        "cli": cli_ceiling, "official_default": official_default,
        "override_used": ceiling_override_used, "rate_raw": xraw, "rows": xrows}

    manifest_path = "{}_split_manifest.csv".format(args.prefix)
    prov_path = "{}_split_provenance.json".format(args.prefix)
    split_paths = {nm: "{}_{}.csv".format(args.prefix, nm) for nm, _ in split_frames}
    all_finals = [manifest_path, prov_path] + [split_paths[nm] for nm, _ in split_frames]

    # Refuse to clobber an existing split package unless --overwrite [audit 6].
    existing = [p for p in all_finals if os.path.exists(p)]
    if existing and not args.overwrite:
        sys.exit("ABORT: output(s) already exist: {}. Pass --overwrite to replace. "
                 "[audit 6]".format(existing))

    # Write EVERY temp first (manifest + each split), hash them, write a provenance
    # JSON that records input+output hashes / classes / counts / runs / commit, and
    # ONLY then publish the whole set transactionally (rollback on any failure)
    # [audit 6/21].
    tmp = {p: p + ".tmp" for p in all_finals}
    write_manifest(df, split_indices, time_col, tmp[manifest_path])
    for nm, d in split_frames:
        d.to_csv(tmp[split_paths[nm]], index=False)
    out_hashes = {os.path.basename(split_paths[nm]): _sha256(tmp[split_paths[nm]])
                  for nm, _ in split_frames}
    out_hashes[os.path.basename(manifest_path)] = _sha256(tmp[manifest_path])
    runs_all = (sorted(int(r) for r in pd.to_numeric(df["run_id"], errors="coerce")
                       .dropna().unique()) if "run_id" in df.columns else None)

    # ONE explicit verdict so nobody has to interpret a dozen fields: any relaxation OR an
    # unauthenticated input makes the package DIAGNOSTIC, not official [audit v20.2 P0-9].
    diag_reasons = [f for f in (
        "allow_leak", "allow_partial_schema", "allow_extra_labels",
        "allow_missing_expected_labels", "allow_extra_campaign_labels",
        "allow_diagnostic_status", "allow_incomplete_campaign", "dup_label_conflicts_ok",
        "allow_within_run_split", "allow_missing_required_policy",
        "allow_unauthenticated_inputs") if getattr(args, f, False)]
    if args.i_trust_run_order and not chronology_verified:
        diag_reasons.append("trusted_run_order")
    if within_run_split:
        diag_reasons.append("within_run_split")
    if xdup_diagnostic:                                   # override used or ceiling exceeded w/ allow
        diag_reasons.append("cross_split_duplicates")
    if auth_records is not None and not all(a.get("status_authenticated") for a in auth_records):
        diag_reasons.append("unauthenticated_inputs")
    if args.campaign is None:
        diag_reasons.append("no_campaign")             # a split without a campaign is not official
    elif camp.bruteforce_unpinned(manifest):           # unpinned BruteForce is not a full reproduction
        diag_reasons.append("brute_force_wordlists_unpinned")   # [audit v20.7 P0-1]
    provenance = {
        "code_version": CODE_VERSION, "git_commit": _git_commit(), "how": how,
        # Explicit verdict [audit v20.2 P0-9]:
        "official": len(diag_reasons) == 0, "diagnostic": len(diag_reasons) > 0,
        "diagnostic_reasons": sorted(set(diag_reasons)),
        # LIST of records so two inputs with the same basename never collide [audit 12].
        "inputs": [{"path": p, "sha256": _sha256(p)} for p in args.csvs],
        # The manifest and its SHA-256, plus each run's declared config/split, so the
        # package PROVES which campaign produced it [audit 6].
        "campaign": campaign_prov,
        # Per-input authentication against that campaign via labeler status sidecars.
        "input_authentication": auth_records,
        # Quantified duplicate collisions (label conflicts already aborted above) [audit 12].
        "duplicates": dup_stats,
        "outputs": out_hashes, "runs": runs_all, "n_rows_total": int(len(df)),
        # Provenance must make a diagnostic package obviously non-official [audit 12].
        # Separate provenance states so a reader can tell a VERIFIED chronology from
        # one that was merely available / checked-and-failed / leak-overridden [audit 9].
        "timestamp_available": bool(timestamp_available),
        "chronology_check_passed": (None if chronology_check_passed is None
                                    else bool(chronology_check_passed)),
        "chronology_verified": bool(chronology_verified),
        "leak_override_used": bool(args.allow_leak),
        "within_run_split": bool(within_run_split),   # --time-frac cut inside a run [audit 10]
        "trusted_run_order": bool(args.i_trust_run_order and not chronology_verified),
        "diagnostic_overrides": {
            "allow_leak": bool(args.allow_leak),
            "allow_partial_schema": bool(args.allow_partial_schema),
            "allow_extra_labels": bool(args.allow_extra_labels),
            "allow_missing_expected_labels": bool(args.allow_missing_expected_labels),
            "allow_extra_campaign_labels": bool(args.allow_extra_campaign_labels),
            "allow_diagnostic_status": bool(args.allow_diagnostic_status),
            "allow_incomplete_campaign": bool(args.allow_incomplete_campaign),
            "dup_label_conflicts_ok": bool(args.dup_label_conflicts_ok),
            "allow_within_run_split": bool(args.allow_within_run_split),
            "allow_missing_required_policy": bool(args.allow_missing_required_policy),
            "allow_unauthenticated_inputs": bool(args.allow_unauthenticated_inputs),
            "i_trust_run_order": bool(args.i_trust_run_order),
            "drop_ids": bool(args.drop_ids),
        },
        "expected_labels": sorted(args.expected_labels) if args.expected_labels else None,
        "test_run": args.test_run, "val_run": args.val_run,
        "splits": {nm: {"n_rows": int(len(d)),
                        "class_counts": {str(k): int(v)
                                         for k, v in d["label"].value_counts().items()}}
                   for nm, d in split_frames},
    }
    with open(tmp[prov_path], "w", encoding="utf-8") as fh:
        json.dump(provenance, fh, indent=2, allow_nan=False)   # strict JSON: no NaN/Inf [v20.20 §5]

    backups, published, publish_ok = {}, [], False
    try:
        for final in all_finals:
            if os.path.exists(final):
                bak = final + ".bak"
                os.replace(final, bak)
                backups[final] = bak
        for final in all_finals:
            os.replace(tmp[final], final)
            published.append(final)
        publish_ok = True
    finally:
        if not publish_ok:
            for p in published:
                try:
                    os.remove(p)
                except OSError:
                    pass
            for final, bak in backups.items():
                try:
                    os.replace(bak, final)
                except OSError:
                    pass
            for t in tmp.values():
                try:
                    os.remove(t)
                except OSError:
                    pass
        else:
            for bak in backups.values():
                try:
                    os.remove(bak)
                except OSError:
                    pass

    print("Wrote", manifest_path, "and", prov_path, "(hashes + class counts)")
    print("split:", how)
    for nm, d in split_frames:
        print("Wrote {} ({} rows)".format(split_paths[nm], len(d)))
    print("\nClass distribution:")
    print(pd.DataFrame({nm: d["label"].value_counts()
                        for nm, d in split_frames}).fillna(0).astype(int))
    print("Duplicates (exact/cross-run/cross-split/label-conflict): {}/{}/{}/{}".format(
        dup_stats["exact_duplicate_groups"], dup_stats["cross_run_duplicate_groups"],
        dup_stats["cross_split_duplicate_groups"], dup_stats["conflicting_label_groups"]))


if __name__ == "__main__":
    main()
