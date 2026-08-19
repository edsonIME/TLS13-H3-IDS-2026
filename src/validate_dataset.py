#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
validate_dataset.py  (version: see CODE_VERSION below — common schema, fail-closed
chronology, PR-AUC/MCC)
=============================================================================

Quality/anti-smell validator for a labeled NIDS flow dataset (CSV). Give it a
file that STILL has time: the synthetic dataset, or label_flows'
*_split_ready.csv* (run_id + timestamp + COMMON + label — the intended split
input; the *_audit.csv* also works but carries inspection-only noise).

WHAT CHANGED vs v3 (addresses the audit)
----------------------------------------
  * The baseline ALWAYS uses the COMMON feature schema (feature_schema.to_common)
    so it evaluates the SAME features the real ML file will have — not extra
    synthetic-only columns nor raw-log-only columns [audit 5.1]. Because
    to_common maps a Zeek *_audit.csv* to the common schema, validating the
    audit file now DOES produce a baseline [audit 5.2].
  * Fail-closed chronology: if max(train time) is NOT < min(test time), the
    baseline is SKIPPED (not trained on a time-leaking split) [audit 4.5].
  * Binary PR-AUC and MCC are reported again [audit 5.3].
  * NaN-safe (median imputer + string categoricals + OneHot ignore) [audit 6].

USAGE
-----
  pip install -r requirements.txt
  python3 validate_dataset.py --csv synthetic_nids_dataset.csv
  python3 validate_dataset.py --csv labeled_run0_split_ready.csv
"""

import argparse
import sys

import numpy as np
import pandas as pd

import campaign as camp
import provenance as prov               # shared campaign authentication [audit 9]
import feature_schema as fs

# SINGLE source of truth for THIS tool's version, used by the runtime banner (was a stray "v5"
# banner beside a "v4" header) [audit v20.15 doc/impl consistency].
CODE_VERSION = "validate_dataset/v5"

try:
    from sklearn.compose import ColumnTransformer
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.metrics import (average_precision_score, balanced_accuracy_score,
                                 classification_report, confusion_matrix, f1_score,
                                 matthews_corrcoef, roc_auc_score)
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder
except ImportError:
    sys.exit("scikit-learn is required. Install with: pip install -r requirements.txt")

NUM, CAT, LABEL = fs.COMMON_NUMERIC, fs.COMMON_CATEGORICAL, fs.LABEL


def build_common(df):
    """Map to the common schema and keep hidden _ts/_run_id for the split only."""
    common = fs.to_common(df)
    common["_run_id"] = df["run_id"].values if "run_id" in df.columns else np.nan
    ts = np.nan
    for tc in ("timestamp", "ts"):
        if tc in df.columns:
            ts = pd.to_numeric(df[tc], errors="coerce").values
            break
    common["_ts"] = ts
    return common


def temporal_split(c):
    """(train_idx, test_idx, how, chronology_ok) or (None,...) if impossible."""
    has_run = c["_run_id"].notna().any() and c["_run_id"].nunique() > 1
    has_ts = pd.Series(c["_ts"]).notna().any()
    if has_run:
        last = c["_run_id"].max()
        tr, te = c.index[c["_run_id"] < last], c.index[c["_run_id"] == last]
        ok = None                                    # None = run split, ts NOT verified
        if has_ts:
            ok = bool(pd.to_numeric(c.loc[tr, "_ts"]).max()
                      < pd.to_numeric(c.loc[te, "_ts"]).min())
        return tr, te, "run_id < {} vs == {}".format(last, last), ok
    if has_ts:
        order = pd.to_numeric(c["_ts"]).sort_values().index
        cut = int(0.7 * len(order))
        return order[:cut], order[cut:], "earliest 70% vs latest 30% by ts", True
    return None, None, None, None


def prep(c, idx):
    X = pd.DataFrame(index=idx)
    for col in NUM:
        X[col] = pd.to_numeric(c.loc[idx, col], errors="coerce")
    for col in CAT:
        X[col] = c.loc[idx, col].astype("string").fillna("missing").astype(str)
    return X


def build_pipe():
    return Pipeline([
        ("pre", ColumnTransformer([
            ("num", SimpleImputer(strategy="median"), NUM),
            ("cat", OneHotEncoder(handle_unknown="ignore"), CAT),
        ])),
        ("rf", RandomForestClassifier(n_estimators=120, random_state=0, n_jobs=-1)),
    ])


def check_balance(c):
    print("\n[1] Class balance  [Arp 2022 P7/P8]")
    print(c[LABEL].value_counts().to_string())
    print("  attack share: {:.2f}%".format(100 * (c[LABEL] != "BENIGN").mean()))


def numeric_shortcut(c, y):
    print("\n[2] Numeric single-feature shortcut (ROC-AUC)  [Smells Smell 2]")
    scores = []
    for col in NUM:
        v = pd.to_numeric(c[col], errors="coerce")
        if v.notna().sum() < 5 or v.std() == 0:
            continue
        try:
            auc = roc_auc_score(y, v.fillna(v.median()))
        except ValueError:
            continue
        scores.append((max(auc, 1 - auc), col))
    for sep, col in sorted(scores, reverse=True)[:6]:
        print("    {:<18} {:.3f}{}".format(col, sep, "  <-- SHORTCUT?" if sep >= 0.95 else ""))


def categorical_lift(c, tr, te):
    print("\n[3] Categorical shortcut with LIFT (temporal test)  [audit 9]")
    if tr is None:
        print("  no temporal split; skipping.")
        return
    ytr, yte = c.loc[tr, LABEL].astype(str), c.loc[te, LABEL].astype(str)
    major = ytr.value_counts().idxmax()
    base = (yte == major).mean()
    print("  majority baseline acc={:.3f}".format(base))
    print("  feature          acc    lift   bal-acc")
    for col in CAT:
        m = c.loc[tr].groupby(col)[LABEL].agg(lambda s: s.value_counts().idxmax())
        pred = c.loc[te, col].map(m).fillna(major).astype(str)
        acc = (pred.values == yte.values).mean()
        print("    {:<14} {:.3f}  {:+.3f}  {:.3f}{}".format(
            col, acc, acc - base, balanced_accuracy_score(yte, pred),
            "  <-- near-label" if acc - base > 0.1 else ""))


def baseline(c, tr, te, how, ok, trust):
    """Run the temporal baseline. Returns True only if it actually ran [audit 5]."""
    print("\n[4] Multiclass baseline, TEMPORAL split (common schema)  [Arp P3/P6]")
    if tr is None:
        print("  no run_id/timestamp -> temporal split impossible; skipping [Arp P3].")
        return False
    if ok is False:
        print("  ABORT baseline: chronology invalid (max(train) !< min(test)) [audit 4.5].")
        return False
    if ok is None and not trust:
        print("  ABORT baseline: run_id split has NO timestamp to verify chronology; "
              "pass --trust-run-order (DIAGNOSTIC only) to proceed [audit 5.1].")
        return False
    print("  split:", how)
    tsv = pd.to_numeric(c["_ts"], errors="coerce")
    if tsv.notna().any() and not bool(np.isfinite(tsv.to_numpy(dtype=float)).all()):
        print("  ABORT baseline: timestamp present but incomplete/non-finite ({} bad "
              "rows) [audit 5.2].".format(int((~np.isfinite(tsv.to_numpy(dtype=float))).sum())))
        return False
    ytr, yte = c.loc[tr, LABEL], c.loc[te, LABEL]
    if ytr.nunique() < 2 or yte.nunique() < 2:
        print("  ABORT baseline: train has {} class(es), test has {} class(es) "
              "(missing in test: {}); a multiclass baseline needs >=2 in EACH — "
              "the single-run 70/30 fallback failed here [audit 4].".format(
                  ytr.nunique(), yte.nunique(),
                  sorted(set(ytr.unique()) - set(yte.unique()))))
        return False
    clf = build_pipe()
    clf.fit(prep(c, tr), ytr)
    pred = clf.predict(prep(c, te))
    print("  balanced acc: {:.4f} | macro-F1: {:.4f}".format(
        balanced_accuracy_score(yte, pred), f1_score(yte, pred, average="macro")))
    # Binary attack-vs-benign metrics [audit 5.3].
    classes = list(clf.named_steps["rf"].classes_)
    if "BENIGN" in classes:
        proba = clf.predict_proba(prep(c, te))
        p_attack = 1 - proba[:, classes.index("BENIGN")]
        yb = (yte != "BENIGN").astype(int)
        print("  binary PR-AUC: {:.4f} | MCC: {:.4f}  [Arp P7/P8]".format(
            average_precision_score(yb, p_attack),
            matthews_corrcoef(yb, (pred != "BENIGN").astype(int))))
    print("  per-class report:")
    print("   " + classification_report(yte, pred, zero_division=0).replace("\n", "\n   "))
    labels = sorted(yte.unique())
    print("  confusion {}:".format(labels))
    print("   " + str(confusion_matrix(yte, pred, labels=labels)).replace("\n", "\n   "))
    return True


def main():
    ap = argparse.ArgumentParser(
        description="Validate a NIDS flow dataset ({}).".format(CODE_VERSION))
    ap.add_argument("--csv", required=True, nargs="+",
                    help="one or MORE split-ready CSVs. For byte-authenticated official "
                         "runs, pass the PER-RUN *_split_ready.csv* files (one run each) "
                         "with --status/--require-status; they are concatenated internally "
                         "[audit v19 P0-1]")
    ap.add_argument("--trust-run-order", action="store_true",
                    help="DIAGNOSTIC ONLY: accept a run_id split without timestamps")
    ap.add_argument("--allow-single-run-diagnostic", action="store_true",
                    help="DIAGNOSTIC ONLY: allow the 70/30 baseline inside a SINGLE "
                         "run (train/test may share a session/tool); never an "
                         "official pass. Otherwise abort — the official baseline "
                         "needs >=2 independent runs [audit 9]")
    ap.add_argument("--allow-extra-labels", action="store_true",
                    help="permit labels outside feature_schema.ALLOWED_LABELS "
                         "(default: abort on any unknown class) [audit 8]")
    ap.add_argument("--allow-contract-violations", action="store_true",
                    help="DIAGNOSTIC: proceed even if COMMON values/relations are "
                         "physically impossible (default: abort — a metric must not be "
                         "computed on impossible data) [audit 7]")
    ap.add_argument("--allow-partial-schema", action="store_true",
                    help="DIAGNOSTIC: accept a file that is NOT run_id+timestamp+15 "
                         "COMMON+label (default: abort — otherwise missing features are "
                         "silently imputed and metrics are a lie) [audit 8]")
    ap.add_argument("--campaign", default=None,
                    help="campaign manifest (campaign.py): sets the expected classes "
                         "required in train AND test [audit 7]")
    ap.add_argument("--expected-labels", nargs="+", default=None,
                    help="classes required in train AND test (default: campaign's, or "
                         "none) [audit 7]")
    ap.add_argument("--allow-missing-expected-labels", action="store_true",
                    help="downgrade a missing expected class to a warning (diagnostic)")
    ap.add_argument("--status", nargs="+", default=None,
                    help="labeler *_run_status.json sidecars, one per --csv file, to "
                         "BYTE-authenticate this dataset against --campaign: each per-run "
                         "*_split_ready.csv* must hash to its status' split_ready_sha256 and "
                         "its run_id must match. Pass the PER-RUN files to --csv, NOT one "
                         "concatenated file [audit v19 P0-1]")
    ap.add_argument("--require-status", action="store_true",
                    help="with --campaign, ABORT unless every --csv is byte-authenticated "
                         "by its --status sidecar against the campaign [audit v19 P0-1]")
    ap.add_argument("--allow-diagnostic-status", action="store_true",
                    help="accept DIAGNOSTIC-policy status sidecars (default: reject) [audit 5]")
    ap.add_argument("--allow-missing-required-policy", action="store_true",
                    help="with --require-status, allow a campaign without a "
                         "required_labeling_policy (default: official mode demands one) "
                         "[audit v20 P0-9]")
    ap.add_argument("--allow-unauthenticated-inputs", action="store_true",
                    help="with --campaign, validate WITHOUT byte-authentication of the "
                         "inputs (default: --require-status is demanded). Marks the run "
                         "DIAGNOSTIC [audit v20.2 P0-6]")
    ap.add_argument("--json", default=None,
                    help="write the verdict as JSON {official, diagnostic, "
                         "diagnostic_reasons} (fail-closed) [audit v20.3 P0-6]")
    ap.add_argument("--allow-extra-campaign-labels", action="store_true",
                    help="permit classes not in the campaign expected_labels (default: with "
                         "--campaign the observed classes must EQUAL expected_labels) [audit 7]")
    ap.add_argument("--allow-incomplete-campaign", action="store_true",
                    help="with --campaign, do not require seed+day on every run [audit 11]")
    args = ap.parse_args()

    # Refuse the SAME input twice (would double a run) and concatenate all inputs into one
    # frame for the baseline [audit v19 P0-1].
    if len(set(args.csv)) != len(args.csv):
        sys.exit("ABORT: a --csv file is listed more than once.")
    # SCHEMA-AWARE read: categorical values as strings across files (tls_version='1.3' etc.) [P0-2].
    df = pd.concat([fs.read_common_csv(f) for f in args.csv], ignore_index=True)
    if LABEL not in df.columns:
        sys.exit("No 'label' column found.")
    # If handed an *_audit.csv*, drop the known-ambiguous rows so validation is not
    # contaminated by label noise; *_split_ready.csv* has no such column [audit 14].
    if "ambiguous" in df.columns:
        amb = pd.to_numeric(df["ambiguous"], errors="coerce").fillna(0) != 0
        if amb.any():
            print("NOTE: audit file detected — dropping {} ambiguous row(s) before "
                  "validation (use *_split_ready.csv* to avoid this) [audit 14].".format(
                      int(amb.sum())))
            df = df[~amb].reset_index(drop=True)
    # No missing/empty labels and (unless overridden) no stray classes [audit 4/8].
    fs.require_valid_labels(df[LABEL], "dataset", allow_extra=args.allow_extra_labels)
    # Same STRUCTURAL contract as the official split: the COMMON columns must
    # actually be present (not fabricated by to_common) and free of numeric junk,
    # else the reported "9 numeric + 6 categorical" and its metrics are a lie
    # [audit 8/9].
    if not args.allow_partial_schema:
        col_errs = fs.check_official_columns(df, require_time=True)
        if col_errs:
            sys.exit("ABORT: not an official split-ready file: {}. Feed the labeler's "
                     "*_split_ready.csv*, or pass --allow-partial-schema (diagnostic). "
                     "[audit 8/9]".format("; ".join(col_errs)))
    c = build_common(df)
    # Same physical/relational contract as the official split — a metric must not be
    # computed on impossible data [audit 7].
    _errs, _warns = fs.common_contract_violations(c)
    for _w in _warns:
        print("WARNING (value domain):", _w)
    if _errs and not args.allow_contract_violations:
        sys.exit("ABORT: COMMON contract violated: {}. Pass --allow-contract-violations "
                 "to force (diagnostic). [audit 7]".format("; ".join(_errs)))
    # run_id, if present at all, must be complete/integer/non-negative [audit 5.3].
    if c["_run_id"].notna().any():
        rv = pd.to_numeric(c["_run_id"], errors="coerce").to_numpy(dtype=float)
        if not np.isfinite(rv).all() or not np.all(rv == np.floor(rv)) or (rv < 0).any():
            sys.exit("ABORT: run_id must be present, integer and non-negative for "
                     "EVERY row [audit 5.3].")
    y = (c[LABEL] != "BENIGN").astype(int)
    # With a campaign, the split is DICTATED by the manifest (train/test run SETS) —
    # NOT inferred from max(run_id). A validation run is held OUT of the training
    # used for the baseline (it is for threshold/hyperparameter tuning) [audit 5].
    manifest = (camp.load(args.campaign,
                          require_reproducible=not args.allow_incomplete_campaign)
                if args.campaign else None)
    auth_records = None                                   # per-file byte-auth evidence for --json [P1-10]
    if manifest is not None:
        if not c["_run_id"].notna().any():
            sys.exit("ABORT: --campaign needs a run_id column. [audit 5]")
        rid = pd.to_numeric(c["_run_id"], errors="coerce")
        # The file must contain EXACTLY the manifest's runs (incl. validation), so a
        # missing or extra run cannot pass silently [audit 7].
        present = set(int(x) for x in rid.dropna().unique())
        declared = set(int(r) for r in (manifest.get("runs") or {}))
        if present != declared:
            sys.exit("ABORT: dataset runs {} != campaign runs {} (no extra/missing "
                     "run). [audit 7]".format(sorted(present), sorted(declared)))
        # Authenticate the dataset against the campaign — by BYTES. Each --csv must be a
        # PER-RUN split-ready file whose SHA-256 equals its status' split_ready_sha256 and
        # whose run_id column equals the status' run_id, so a CONCATENATED file with swapped
        # labels/features cannot pass (it holds >1 run and no matching hash) [audit v19 P0-1].
        # With a campaign, byte-authentication is the DEFAULT; opting out is explicit and
        # makes the run DIAGNOSTIC [audit v20.2 P0-6].
        if not (args.status or args.require_status) and not args.allow_unauthenticated_inputs:
            sys.exit("ABORT: an official validation with --campaign needs --require-status "
                     "(one *_run_status.json* per --csv). Pass --require-status, or "
                     "--allow-unauthenticated-inputs to run DIAGNOSTIC. [audit v20.2 P0-6]")
        if args.allow_unauthenticated_inputs and not (args.status or args.require_status):
            print("\n[DIAGNOSTIC] --allow-unauthenticated-inputs: inputs are NOT "
                  "byte-authenticated against the campaign; metrics are indicative, not "
                  "official. [audit v20.2 P0-6]")
        if args.status or args.require_status:
            if not args.status:
                sys.exit("ABORT: --require-status needs --status <sidecars>. [audit 9]")
            if len(args.csv) < 2:
                sys.exit("ABORT: byte authentication needs the PER-RUN split-ready files: "
                         "pass each run's *_split_ready.csv* to --csv (not one concatenated "
                         "file). [audit v19 P0-1]")
            # Giving --status means official authentication, so the campaign must declare a
            # policy AND every input must fully authenticate — not gated on --require-status
            # [audit v20.3 P0-5].
            prov.require_official_policy(manifest, args.allow_missing_required_policy)
            # Keep the per-file authentication record so --json can PROVE which sidecar
            # (sha/run_id/policy/diagnostic_reasons) authenticated each CSV [audit v20.4 P1-10].
            auth_records = prov.authenticate_against_campaign(
                args.csv, args.status, manifest, args.campaign, require_status=True,
                allow_diagnostic=args.allow_diagnostic_status, require_full_coverage=True)
        train_runs = set(camp.runs_in_split(manifest, "train"))
        test_runs = set(camp.runs_in_split(manifest, "test"))
        if not train_runs or not test_runs:
            sys.exit("ABORT: campaign must declare train AND test runs. [audit 5]")
        val_runs = set(camp.runs_in_split(manifest, "validation"))
        tr = c.index[rid.isin(train_runs)]
        te = c.index[rid.isin(test_runs)]
        va = c.index[rid.isin(val_runs)] if val_runs else None    # for 3-split coverage [audit 8]
        if len(tr) == 0 or len(te) == 0:
            sys.exit("ABORT: campaign train {} / test {} runs not present in the file. "
                     "[audit 5]".format(sorted(train_runs), sorted(test_runs)))
        # Chronology must be train < validation < test — the validation run is NOT
        # ignored, so a run ordered AFTER the test can never be used for tuning [audit 4].
        tsv = pd.to_numeric(c["_ts"], errors="coerce")
        if tsv.notna().any():
            val_ts = tsv[rid.isin(val_runs)] if val_runs else None
            ok = camp.chronology_ok(tsv.loc[tr], tsv.loc[te], val_ts)
        else:
            ok = None
        how = "campaign hold-out: test runs {}".format(sorted(test_runs))
        single_run = False
    else:
        tr, te, how, ok = temporal_split(c)
        va = None
        # A 70/30 split by ts INSIDE one run is chronological but train/test can share
        # the same session/tool/fingerprint -> diagnostic only, never official [audit 9].
        single_run = bool(how) and how.startswith("earliest 70%")

    # Expected classes (campaign or --expected-labels) must appear in train AND test,
    # so an incomplete campaign cannot be validated as complete [audit 7]. With a
    # manifest the CLI may only CONFIRM it, never override [audit 6].
    if manifest is not None:
        m_labels = sorted(manifest["expected_labels"])
        if args.expected_labels is not None and sorted(args.expected_labels) != m_labels:
            sys.exit("ABORT: --expected-labels contradicts the campaign manifest. [audit 6]")
        want = set(m_labels)
        # EXACT class set: an UNPLANNED class (not in expected_labels) must abort, not be
        # quietly validated [audit 7].
        if not args.allow_extra_campaign_labels:
            observed = set(str(x) for x in pd.Series(c[LABEL]).dropna().unique())
            extra = sorted(observed - set(str(x) for x in m_labels))
            if extra:
                sys.exit("ABORT: class(es) {} not in campaign expected_labels {}; a campaign "
                         "declares its EXACT set. Pass --allow-extra-campaign-labels. "
                         "[audit 7]".format(extra, m_labels))
    else:
        want = set(args.expected_labels) if args.expected_labels else None
    if want and tr is not None:
        # Check EVERY split, INCLUDING validation — a class missing from validation biases
        # tuning/threshold/model selection just as badly [audit 8].
        splits_to_check = [("train", tr), ("test", te)]
        if va is not None and len(va):
            splits_to_check.append(("validation", va))
        gaps = {nm: sorted(want - set(c.loc[idx, LABEL]))
                for nm, idx in splits_to_check
                if want - set(c.loc[idx, LABEL])}
        if gaps:
            print("\n[EXPECTED-LABELS] missing {} [audit 7/8]".format(gaps))
            if not args.allow_missing_expected_labels:
                sys.exit("ABORT: expected class(es) missing from a split (above, incl. "
                         "validation); the campaign declares more classes than this split "
                         "covers. Pass --allow-missing-expected-labels (diagnostic). "
                         "[audit 7/8]")

    print("=" * 70)
    print("NIDS DATASET VALIDATION ({}, common schema) —".format(CODE_VERSION), args.csv)
    print("rows: {}  features: {} numeric + {} categorical (COMMON)".format(
        len(c), len(NUM), len(CAT)))
    print("=" * 70)
    print("\n[0] Missing per common feature:")
    na = c[NUM + CAT].isna().mean()
    print("   " + na[na > 0].round(3).to_string().replace("\n", "\n   ") if na.any() else "   none")
    check_balance(c)
    numeric_shortcut(c, y)
    categorical_lift(c, tr, te)
    if single_run and not args.allow_single_run_diagnostic:
        print("\n[4] Multiclass baseline — SKIPPED (single-run) [audit 9]")
        sys.exit("ABORT: official baseline requires at least two independent runs; a "
                 "70/30 split inside ONE run is train/test on the same session/tool "
                 "(diagnostic only). Pass --allow-single-run-diagnostic to run it as "
                 "a diagnostic. [audit 9]")
    ran = baseline(c, tr, te, how, ok, args.trust_run_order)
    # A run_id split with NO verified chronology (ok is None) only ASSUMED run
    # order via --trust-run-order — that is diagnostic, not an official pass [audit 5].
    trusted = ran and (ok is None) and args.trust_run_order
    if single_run and ran:
        print("\nDIAGNOSTIC ONLY (single-run 70/30 — NOT an official pass): the "
              "baseline above is indicative; capture >=2 runs for an official "
              "result. [audit 9]")
    elif trusted:
        print("\nDIAGNOSTIC ONLY — RUN ORDER TRUSTED, CHRONOLOGY NOT VERIFIED: the "
              "baseline assumed run 0 < run 1 < ... without timestamps; provide a "
              "'timestamp' column for an official chronological result. [audit 5]")
    # ONE explicit verdict [audit v20.3 P0-6]: any relaxation, an unauthenticated run, or
    # no campaign at all makes this DIAGNOSTIC, not official — same governance as the merge.
    v_reasons = [f for f in (
        "allow_unauthenticated_inputs", "allow_missing_required_policy",
        "allow_diagnostic_status", "allow_extra_campaign_labels", "allow_incomplete_campaign",
        "allow_missing_expected_labels", "allow_partial_schema", "allow_contract_violations",
        "allow_extra_labels", "allow_single_run_diagnostic") if getattr(args, f, False)]
    if args.trust_run_order and (ok is None):
        v_reasons.append("trusted_run_order")
    if single_run:
        v_reasons.append("single_run_70_30")
    if manifest is None:
        v_reasons.append("no_campaign")
    elif camp.bruteforce_unpinned(manifest):           # unpinned BruteForce is not official [P0-1]
        v_reasons.append("brute_force_wordlists_unpinned")
    v_reasons = sorted(set(v_reasons))
    v_official = not v_reasons
    if v_official:
        print("\nOFFICIAL: authenticated against the campaign, no diagnostic relaxations.")
    else:
        print("\nDIAGNOSTIC ONLY (official=false) — reasons: {} [audit v20.3 P0-6]".format(v_reasons))
    if args.json:
        import json as _json
        try:
            with open(args.json, "w", encoding="utf-8") as fh:
                _json.dump({"official": v_official, "diagnostic": not v_official,
                            "diagnostic_reasons": v_reasons, "csv": args.csv,
                            "campaign": args.campaign,
                            "input_authentication": auth_records},   # byte-auth chain [P1-10]
                           fh, indent=2, allow_nan=False)
        except OSError as exc:
            sys.exit("ABORT: could not write --json {}: {}. [audit v20.3 P0-6]".format(
                args.json, exc))
    print("\nDone. On imbalanced data trust LIFT / balanced-acc / macro-F1 / PR-AUC, not raw accuracy.")
    if not ran:
        sys.exit(2)


if __name__ == "__main__":
    main()
