#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
evaluate_realism.py  (version: see CODE_VERSION below — per-class, symmetric TSTR,
missing rates, safe perturbation)
=======================================================================================

Measure how realistic a SYNTHETIC NIDS dataset is versus a REAL one, on the
COMMON feature schema (feature_schema.py). Feed the REAL side with label_flows'
*_split_ready.csv* (run_id + timestamp + COMMON + label; it keeps ts for a
temporal split without the audit-only noise) [audit 14].

WHAT CHANGED vs v2 (addresses the audit)
----------------------------------------
  * --by-class: KS + Jensen-Shannon are computed globally AND per class, so a
    difference in class PROPORTION is not mistaken for a difference in realism
    [audit 6.1].
  * Symmetric TSTR: the reference (real_train->real_test) and TSTR
    (synth->real_test) are evaluated on the SAME temporally held-out real_test
    [audit 6.2].
  * Missing rates are reported per feature (real vs synth) — the missingness IS
    part of the distribution [audit 6.3].
  * Perturbation uses multiplicative log-space noise and clips at 0, so it never
    produces impossible negative packets/bytes/durations [audit 6.4].

CHECKS: KS + JS per feature; TSTR/TRTS; perturbation/fragility.
  [Survey §6.2.3; Bad Design Smells §6.1/§6.2; Arp et al. 2022 P9]

USAGE
-----
  pip install -r requirements.txt
  # Official run: SEVERAL real split-ready runs (multi-run holdout), NOT one audit file:
  python3 evaluate_realism.py --real labeled_run0_split_ready.csv labeled_run1_split_ready.csv \
      --synth synthetic_nids_dataset.csv --by-class
"""

import argparse
import hashlib
import math
import sys

import numpy as np
import pandas as pd

import campaign as camp
import provenance as prov               # shared campaign authentication [audit 9]
import feature_schema as fs

# SINGLE source of truth for THIS tool's version — the runtime banner and the code_version written
# into the report must never drift apart again [audit v20.15 doc/impl consistency].
CODE_VERSION = "evaluate_realism/v13"   # v13: release_eligible REQUIRES a complete release_quality_policy (legacy fields can't earn release) [§9]; v12: pinned thresholds


def _unit_fraction(value):
    """argparse type: a FINITE number in [0,1]. Rejects nan/inf and out-of-range so a threshold like
    `--max-domain-auc inf` can NEVER make the gate vacuously pass (metric <= inf is always True) —
    the same NaN/Inf hole closed on the merge ceiling [audit v20.20 §5]."""
    try:
        x = float(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("expected a number, got {!r}".format(value))
    if not math.isfinite(x) or not (0.0 <= x <= 1.0):
        raise argparse.ArgumentTypeError("expected a finite value in [0,1], got {!r}".format(value))
    return x


def _finite_nonneg(value):
    """argparse type: a FINITE number >= 0 (for a ratio that may exceed 1). Rejects nan/inf so a quality
    threshold can't be made vacuous by an infinite bound [audit v20.23 §8]."""
    try:
        x = float(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("expected a number, got {!r}".format(value))
    if not math.isfinite(x) or x < 0.0:
        raise argparse.ArgumentTypeError("expected a finite value >= 0, got {!r}".format(value))
    return x

try:
    from scipy.spatial.distance import jensenshannon
    from scipy.stats import ks_2samp
    from sklearn.compose import ColumnTransformer
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.metrics import balanced_accuracy_score, f1_score
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder
except ImportError as exc:
    sys.exit("Missing dependency ({}). Install: pip install -r requirements.txt".format(exc))

NUM, CAT, LABEL = fs.COMMON_NUMERIC, fs.COMMON_CATEGORICAL, fs.LABEL
# Only real time columns; run_id is handled SEPARATELY (0<1 is not chronology) [audit 4].
TIME_COLS = ["timestamp", "ts"]


def extract_time(df):
    for tc in TIME_COLS:
        if tc in df.columns:
            s = pd.to_numeric(df[tc], errors="coerce")
            if s.notna().any():
                return s
    return None


def prep(df):
    X = pd.DataFrame(index=df.index)
    for c in NUM:
        X[c] = pd.to_numeric(df[c], errors="coerce")
    for c in CAT:
        X[c] = df[c].astype("string").fillna("missing").astype(str)
    return X


def build_pipe():
    return Pipeline([
        ("pre", ColumnTransformer([
            ("num", SimpleImputer(strategy="median"), NUM),
            ("cat", OneHotEncoder(handle_unknown="ignore"), CAT),
        ])),
        ("rf", RandomForestClassifier(n_estimators=120, random_state=0, n_jobs=-1)),
    ])


def temporal_indices(time_series, frac=0.3):
    order = time_series.sort_values(kind="mergesort").index
    cut = int((1 - frac) * len(order))
    return order[:cut], order[cut:]


def js_numeric(a, b, bins=60):
    a = pd.to_numeric(a, errors="coerce").dropna().values
    b = pd.to_numeric(b, errors="coerce").dropna().values
    if len(a) == 0 or len(b) == 0:
        return np.nan
    lo, hi = min(a.min(), b.min()), max(a.max(), b.max())
    if lo == hi:
        return 0.0
    edges = np.linspace(lo, hi, bins + 1)
    pa = np.histogram(a, bins=edges)[0].astype(float)
    pb = np.histogram(b, bins=edges)[0].astype(float)
    if pa.sum() == 0 or pb.sum() == 0:
        return np.nan
    # base=2 bounds the Jensen-Shannon DISTANCE in [0,1]; without it the max is
    # sqrt(ln 2) ~= 0.833, contradicting the documented 0..1 scale [audit 10].
    return float(jensenshannon(pa / pa.sum(), pb / pb.sum(), base=2))


def js_categorical(a, b):
    cats = sorted(set(a.dropna().astype(str)) | set(b.dropna().astype(str)))
    if not cats:
        return np.nan
    pa = np.array([(a.astype(str) == c).mean() for c in cats])
    pb = np.array([(b.astype(str) == c).mean() for c in cats])
    return float(jensenshannon(pa, pb, base=2))         # 0..1 JS distance [audit 10]


def compare(real, synth, tag=""):
    print("\n[dist] {}  numeric feature   KS-stat  KS-p    JS   miss_r  miss_s".format(tag))
    js_all = []
    for c in NUM:
        a = pd.to_numeric(real[c], errors="coerce").dropna()
        b = pd.to_numeric(synth[c], errors="coerce").dropna()
        mr, ms = real[c].isna().mean(), synth[c].isna().mean()
        if len(a) < 5 or len(b) < 5:
            continue
        ks = ks_2samp(a, b)
        js = js_numeric(a, b)
        js_all.append(js)
        print("       {:<16} {:>6.3f}  {:>5.3f}  {:>5.3f}  {:>5.2f}  {:>5.2f}".format(
            c[:16], ks.statistic, ks.pvalue, js, mr, ms))
    mean_js = float(np.nanmean(js_all)) if js_all else float("nan")
    if js_all:
        print("       --> mean numeric JS: {:.3f}".format(mean_js))
    cat_js = [js_categorical(real[c], synth[c]) for c in CAT]
    print("       categorical JS:", ", ".join(
        "{}={:.2f}".format(c, j) for c, j in zip(CAT, cat_js)))
    mean_cat_js = float(np.nanmean(cat_js)) if cat_js else float("nan")
    if cat_js:
        print("       --> mean categorical JS: {:.3f}".format(mean_cat_js))
    # BOTH axes feed the REALISM QUALITY grade — a synth with identical numerics
    # but totally different protocol/TLS/JA3 must NOT score 'strong' [audit 6].
    return mean_js, mean_cat_js


def _mean_js(real, synth):
    """Quiet mean (numeric, categorical) JS between two frames (for per-class use)."""
    num = [js_numeric(pd.to_numeric(real[c], errors="coerce").dropna(),
                      pd.to_numeric(synth[c], errors="coerce").dropna())
           for c in NUM if real[c].notna().sum() >= 5 and synth[c].notna().sum() >= 5]
    cat = [js_categorical(real[c], synth[c]) for c in CAT]
    mn = float(np.nanmean(num)) if num else float("nan")
    mc = float(np.nanmean(cat)) if cat else float("nan")
    return mn, mc


def conditional_js(real, synth, labels):
    """Per-class P(X|Y) fidelity: a synth can match the GLOBAL P(X) yet mismatch the
    class-conditional distributions (mixing classes wrongly) [audit 8]. Returns
    (worst_class, worst_numeric_js, worst_categorical_js) over classes in BOTH.
    """
    worst_n = worst_c = 0.0
    worst_lab = None
    for lab in sorted(labels):
        r, s = real[real[LABEL] == lab], synth[synth[LABEL] == lab]
        if len(r) < 5 or len(s) < 5:
            continue
        mn, mc = _mean_js(r, s)
        combined = np.nanmax([0.0 if np.isnan(mn) else mn, 0.0 if np.isnan(mc) else mc])
        if combined >= np.nanmax([worst_n, worst_c]):
            worst_lab, worst_n, worst_c = lab, (0.0 if np.isnan(mn) else mn), (0.0 if np.isnan(mc) else mc)
    return worst_lab, worst_n, worst_c


def missingness_report(real, synth):
    """Per-feature missing-rate difference [audit 9]. NaN JS drops missing values, so
    a 90%-missing real vs 0%-missing synth can score JS=0 while being very different;
    the missingness AXIS catches that. Returns (max_abs_diff, worst_feature, rows)."""
    rows, worst, worst_diff = [], None, 0.0
    for c in NUM + CAT:
        mr = float(real[c].isna().mean()) if c in real.columns else float("nan")
        ms = float(synth[c].isna().mean()) if c in synth.columns else float("nan")
        diff = abs((0.0 if np.isnan(mr) else mr) - (0.0 if np.isnan(ms) else ms))
        rows.append((c, mr, ms, diff))
        if diff >= worst_diff:
            worst, worst_diff = c, diff
    return worst_diff, worst, rows


def transfer(src, dst, name):
    pipe = build_pipe()
    pipe.fit(prep(src), src[LABEL])
    pred = pipe.predict(prep(dst))
    mf1 = f1_score(dst[LABEL], pred, average="macro")
    print("  {:<30} macro-F1={:.3f}  bal-acc={:.3f}".format(
        name, mf1, balanced_accuracy_score(dst[LABEL], pred)))
    return mf1


def real_split(real, real_runid, real_time):
    """Prefer a run_id hold-out (last run); else time 70/30; else random."""
    if real_runid is not None and real_runid.nunique() > 1:
        last = real_runid.max()
        return (real.index[real_runid < last], real.index[real_runid == last],
                "hold out last run_id={}".format(int(last)))
    if real_time is not None:
        order = real_time.sort_values(kind="mergesort").index
        cut = int(0.7 * len(order))
        return order[:cut], order[cut:], "earliest 70% vs latest 30% by time"
    from sklearn.model_selection import train_test_split
    tr, te = train_test_split(real.index, test_size=0.3, random_state=0)
    return tr, te, "random 70/30 (no time!)"


def _balance_to(frame, per_class_n, seed):
    """Subsample `frame` to exactly per_class_n[label] rows for each class [audit 14]."""
    rng = np.random.default_rng(seed)
    parts = []
    for lab, n in per_class_n.items():
        pool = frame.index[frame[LABEL] == lab]
        if len(pool) == 0 or n <= 0:
            continue
        pick = rng.choice(pool, size=min(int(n), len(pool)), replace=False)
        parts.append(frame.loc[pick])
    return pd.concat(parts) if parts else frame.iloc[0:0]


def tstr_trts(real, synth, tr, te, how, balance=False, seeds=(0, 1, 2)):
    """Returns (ratio, ref_f1, tstr_f1). `ratio` alone is misleading (1.0 when BOTH
    are ~0.2), so the caller also uses the ABSOLUTE reference F1 [audit 13]."""
    print("\n[TSTR/TRTS] split:", how, " [Smells §6.1; Arp 2022 P9]")
    if balance:
        # Equalize per-class counts on BOTH sides (n_c = min(real_train_c, synth_c))
        # and average over seeds, so TSTR measures FIDELITY, not training volume —
        # the previous version only shrank synth and still trained the reference on
        # the FULL real_train [audit 14].
        rc = real.loc[tr, LABEL].value_counts().to_dict()
        sc = synth[LABEL].value_counts().to_dict()
        per_class_n = {c: min(rc.get(c, 0), sc.get(c, 0)) for c in set(rc) | set(sc)}
        print("  balanced per-class n (both sides):", dict(sorted(per_class_n.items())))
        ref_vals, tstr_vals = [], []
        for sd in seeds:
            ref_vals.append(transfer(_balance_to(real.loc[tr], per_class_n, sd),
                                     real.loc[te], "ref(balanced,seed={})".format(sd)))
            tstr_vals.append(transfer(_balance_to(synth, per_class_n, sd),
                                      real.loc[te], "TSTR(balanced,seed={})".format(sd)))
        ref, tstr = float(np.mean(ref_vals)), float(np.mean(tstr_vals))
        print("  balanced ref F1 mean={:.3f} (sd {:.3f}); TSTR F1 mean={:.3f} (sd {:.3f}) "
              "over {} seed(s)".format(ref, np.std(ref_vals), tstr, np.std(tstr_vals), len(seeds)))
    else:
        ref = transfer(real.loc[tr], real.loc[te], "real_train -> real_test (reference)")
        tstr = transfer(synth, real.loc[te], "TSTR synth -> real_test")   # SAME test set
    transfer(real.loc[tr], synth, "TRTS real_train -> synth")
    ratio = (tstr / ref) if ref > 0 else float("nan")
    if ref > 0:
        print("  --> TSTR / reference = {:.2f} (ratio; but read ABSOLUTE F1 too — a "
              "ratio of 1.0 when both are ~0.2 is NOT good) [audit 13]".format(ratio))
    print("  NOTE [audit 13/14/20]: without --tstr-balance, TSTR trains on ALL of synth "
          "vs the full real_train; unequal sizes bias it. --tstr-balance matches n per "
          "class on BOTH sides and averages over seeds. Calibrate on real_train ONLY.")
    return ratio, ref, tstr                            # for the REALISM QUALITY tier


def _prevalence(series):
    vc = pd.Series(series).astype(str).value_counts(normalize=True)
    return {k: round(float(v), 4) for k, v in vc.items()}


def domain_distinguishability(real, synth, real_runid, synth_runid, seed=0):
    """Train a classifier to tell REAL (0) from SYNTHetic (1) rows using the COMMON features. A HIGH
    held-out AUC means the two domains are EASY to separate — the generator leaves SYSTEMATIC
    artifacts (a realism red flag); an AUC near 0.5 means indistinguishable [audit v20.17 §11.6].
    Held out BY RUN — the LAST run of EACH domain separately (so the test always has both domains,
    even with different run counts) [audit v20.18 §9] — else a stratified 30% split; NOT tuned on the
    test fold. Reports BOTH `auc_raw` (global — confounded by class PREVALENCE differences) and
    `macro_auc` (mean of per-CLASS AUCs — the prevalence-ROBUST signal to judge artifacts on) plus
    the class prevalences, per-class AUC, top features and the RF params [audit v20.18 §11/§13].
    Returns a dict (auc_raw None if a fold still lacks a domain)."""
    import sklearn
    from sklearn.metrics import roc_auc_score
    Xr, Xs = prep(real).reset_index(drop=True), prep(synth).reset_index(drop=True)
    X = pd.concat([Xr, Xs], ignore_index=True)
    y = np.array([0] * len(Xr) + [1] * len(Xs))            # 0 = real, 1 = synthetic
    lab = pd.concat([real[LABEL].reset_index(drop=True), synth[LABEL].reset_index(drop=True)],
                    ignore_index=True).astype(str)
    nr = len(Xr)
    common = {"held_out_by": "run", "seed": seed, "n_real": int(nr), "n_synth": int(len(Xs)),
              "prevalence_real": _prevalence(real[LABEL]), "prevalence_synth": _prevalence(synth[LABEL]),
              "rf_params": {"n_estimators": 120, "random_state": 0},
              "sklearn_version": sklearn.__version__,       # reproducibility provenance [audit v20.20 §13]
              "held_out_runs": None}                         # filled below when held out BY RUN
    rr = pd.Series(real_runid).to_numpy(dtype=float) if real_runid is not None else None
    sr = pd.Series(synth_runid).to_numpy(dtype=float) if synth_runid is not None else None
    if (rr is not None and sr is not None and np.isfinite(rr).all() and np.isfinite(sr).all()
            and pd.unique(rr).size > 1 and pd.unique(sr).size > 1):
        r_last, s_last = np.nanmax(rr), np.nanmax(sr)      # LAST run of EACH domain -> both present
        te = np.concatenate([np.where(rr == r_last)[0], nr + np.where(sr == s_last)[0]])
        tr = np.setdiff1d(np.arange(len(y)), te)
        # EXACTLY which run of each domain was reserved for the test fold [audit v20.20 §13].
        common["held_out_runs"] = {"real": [int(r_last)], "synth": [int(s_last)]}
    else:
        from sklearn.model_selection import train_test_split
        common["held_out_by"] = "stratified"
        tr, te = train_test_split(np.arange(len(y)), test_size=0.3, random_state=seed, stratify=y)
    # Per-class TRAIN/TEST support, split by domain, so a per-class AUC can be read with its n [§13].
    def _support(idx):
        li, yi = lab.iloc[idx].to_numpy(), y[idx]
        return {cls: {"real": int(np.sum(yi[li == cls] == 0)), "synth": int(np.sum(yi[li == cls] == 1))}
                for cls in sorted(set(li))}
    common["class_support_train"], common["class_support_test"] = _support(tr), _support(te)
    if len(set(y[tr])) < 2 or len(set(y[te])) < 2:         # need BOTH domains on BOTH sides
        return dict(common, auc_raw=None, macro_auc=None, note="a fold lacked one domain")
    pipe = build_pipe()
    pipe.fit(X.iloc[tr], y[tr])
    proba = pipe.predict_proba(X.iloc[te])[:, 1]
    auc_raw = float(roc_auc_score(y[te], proba))
    per_class = {}
    labte = lab.iloc[te].to_numpy()
    for cls in sorted(set(labte)):
        m = labte == cls
        if len(set(y[te][m])) == 2:                        # both domains present for this class
            per_class[cls] = round(float(roc_auc_score(y[te][m], proba[m])), 4)
    macro = round(float(np.mean(list(per_class.values()))), 4) if per_class else None
    try:
        names = pipe.named_steps["pre"].get_feature_names_out()
        imp = pipe.named_steps["rf"].feature_importances_
        top = [{"feature": str(n), "importance": round(float(i), 5)}
               for n, i in sorted(zip(names, imp), key=lambda t: t[1], reverse=True)[:8]]
    except Exception:
        top = []
    return dict(common, auc_raw=round(auc_raw, 4), macro_auc=macro, n_train=int(len(tr)),
                n_test=int(len(te)), per_class_auc=per_class, top_features=top)


def perturbation(real, tr, te):
    """Perturb BASE features (log-space), round counts, RECOMPUTE derived, clip."""
    print("\n[fragility] perturb base features + recompute derived  [Smells §6.2]")
    if real.loc[te, LABEL].nunique() < 2:
        print("  <2 classes in test; skipping.")
        return
    base = ["tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_bytes",
            "totlen_bwd_bytes", "flow_duration"]
    rf = RandomForestClassifier(n_estimators=120, random_state=0, n_jobs=-1)
    rf.fit(prep(real.loc[tr])[NUM].fillna(0.0), real.loc[tr, LABEL])
    Xte0 = prep(real.loc[te])[NUM].fillna(0.0)
    base_f1 = f1_score(real.loc[te, LABEL], rf.predict(Xte0), average="macro")
    print("  base macro-F1: {:.3f}".format(base_f1))
    print("  noise level   macro-F1")
    rng = np.random.default_rng(0)
    f1_by_level = {}
    for level in [0.0, 0.25, 0.5, 1.0, 2.0]:
        X = Xte0.copy()
        for c in base:
            if c in X:
                X[c] = np.clip(X[c].values * np.exp(rng.normal(0, level, len(X))), 0, None)
        for c in ("tot_fwd_pkts", "tot_bwd_pkts"):        # counts are integers
            if c in X:
                X[c] = np.round(X[c].values)
        dur = np.clip(X["flow_duration"].values, 1e-6, None)   # recompute derived
        if "down_up_ratio" in X:
            X["down_up_ratio"] = (X["tot_bwd_pkts"] / np.clip(X["tot_fwd_pkts"], 1, None)).round(4)
        if "flow_bytes_s" in X:
            X["flow_bytes_s"] = ((X["totlen_fwd_bytes"] + X["totlen_bwd_bytes"]) / dur).round(2)
        if "flow_pkts_s" in X:
            X["flow_pkts_s"] = ((X["tot_fwd_pkts"] + X["tot_bwd_pkts"]) / dur).round(2)
        f1 = f1_score(real.loc[te, LABEL], rf.predict(X), average="macro")
        f1_by_level[level] = f1
        print("   {:>6.2f}       {:.3f}".format(level, f1))
    # Interpret the ACTUAL curve instead of always asserting "steep drop" [audit 7].
    strong_noise_f1 = f1_by_level[2.0]
    abs_drop = base_f1 - strong_noise_f1
    rel_drop = (abs_drop / base_f1) if base_f1 > 1e-9 else float("nan")
    if base_f1 <= 0.05:
        verdict = ("inconclusive (base macro-F1 ~= 0: the model barely separates the "
                   "classes, so there is nothing to degrade)")
    elif not np.isfinite(rel_drop) or rel_drop < 0.15:
        verdict = "stable (robust to +/-2.0 noise; abs drop {:.3f})".format(abs_drop)
    elif rel_drop < 0.40:
        verdict = "moderate degradation ({:.0%} relative drop)".format(rel_drop)
    else:
        verdict = "severe degradation ({:.0%} relative drop)".format(rel_drop)
    print("  Fragility result: {}".format(verdict))
    print("  (a drop does NOT prove a shortcut on its own — it can also reflect low "
          "separability, small samples, miscalibration, correlated features or "
          "out-of-domain noise.) [audit 7]")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _row_keys(df):
    """Normalized per-row key: float64-rounded numerics + string categoricals, so
    numerically equal values like 1 and 1.0 hash the same [audit 3]."""
    norm = pd.DataFrame(index=df.index)
    for c in fs.COMMON_NUMERIC:
        if c in df.columns:
            norm[c] = pd.to_numeric(df[c], errors="coerce").astype("float64").round(8)
    for c in fs.COMMON_CATEGORICAL:
        if c in df.columns:
            norm[c] = df[c].astype("string").fillna("NA").astype(str)
    return norm.astype(str).agg("|".join, axis=1)


def row_overlap(real, synth):
    """(fraction, count) of real rows identical to a synth row after normalizing."""
    rk, sk = _row_keys(real), set(_row_keys(synth))
    mask = rk.isin(sk)
    return float(mask.mean()), int(mask.sum())


def _emit_json(path, **fields):
    """Emit the machine-readable verdict [audit v19 P0-3]. Always echoes a one-line
    'VERDICT_JSON: {...}' to stdout (so official vs diagnostic is unambiguous without
    parsing the log) and, if a path is given, writes the full object there."""
    import json
    headline = {k: fields.get(k) for k in
                ("official", "diagnostic", "diagnostic_reasons", "integrity_passed",
                 "realism_quality", "how")}
    print("VERDICT_JSON: " + json.dumps(headline))
    if path:
        # FAIL-CLOSED: --json was explicitly requested, so a write failure must be a hard,
        # non-zero abort — a reproducible workflow may depend on this artifact [audit v20 P1-14].
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(fields, fh, indent=2, default=str)
        except OSError as exc:
            sys.exit("ABORT: could not write the requested --json {}: {}. A requested audit "
                     "artifact must not fail silently. [audit v20 P1-14]".format(path, exc))


def main():
    ap = argparse.ArgumentParser(
        description="Evaluate synthetic-vs-real realism ({}).".format(CODE_VERSION))
    ap.add_argument("--real", nargs="+", required=True,
                    help="one or more real *_split_ready.csv* runs; concatenated so a "
                         "multi-run holdout works from a single command [audit 8]")
    ap.add_argument("--synth", required=True)
    ap.add_argument("--campaign", default=None,
                    help="campaign manifest (campaign.py); its expected_labels become "
                         "the required coverage — the single source of truth [audit 11]")
    ap.add_argument("--status", nargs="+", default=None,
                    help="labeler *_run_status.json sidecars to AUTHENTICATE each --real "
                         "file against --campaign (sha == split_ready_sha256; run_id bound "
                         "to the file; campaign_id/sha/config/split == manifest) [audit 9]")
    ap.add_argument("--require-status", action="store_true",
                    help="with --campaign, ABORT unless every --real file authenticates "
                         "against the campaign via its status sidecar [audit 9]")
    ap.add_argument("--allow-diagnostic-status", action="store_true",
                    help="accept DIAGNOSTIC-policy status sidecars (default: reject) [audit 5]")
    ap.add_argument("--allow-extra-campaign-labels", action="store_true",
                    help="permit classes not in the campaign expected_labels (default: with "
                         "--campaign observed classes must EQUAL expected_labels) [audit 7]")
    ap.add_argument("--allow-incomplete-campaign", action="store_true",
                    help="with --campaign, do not require seed+day on every run [audit 11]")
    ap.add_argument("--allow-extra-synthetic-labels", action="store_true",
                    help="permit a class present ONLY in the synthetic set (default: with "
                         "--campaign, real and synth must both equal expected_labels); forces "
                         "DIAGNOSTIC ONLY [audit v19 P0-4]")
    ap.add_argument("--allow-unauthenticated-real", action="store_true",
                    help="with --campaign, run WITHOUT --status byte-authentication of the "
                         "--real files (default: authentication is required). Forces "
                         "DIAGNOSTIC ONLY [audit v20 P0-8]")
    ap.add_argument("--allow-missing-required-policy", action="store_true",
                    help="with --require-status, allow a campaign without a "
                         "required_labeling_policy (default: official mode demands one) "
                         "[audit v20 P0-9]")
    ap.add_argument("--json", default=None,
                    help="write the verdict as JSON: {official, diagnostic, "
                         "diagnostic_reasons, integrity_passed, realism_quality} [audit v19 P0-3]")
    ap.add_argument("--expected-labels", nargs="+", default=None,
                    help="classes the campaign expects; if given, real_train, "
                         "real_test AND synth must each cover them all (unless "
                         "--allow-missing-expected-labels) [audit 5]. Overridden by "
                         "--campaign's expected_labels when both are absent here.")
    ap.add_argument("--allow-missing-expected-labels", action="store_true",
                    help="DIAGNOSTIC: proceed even if a split lacks an expected class")
    ap.add_argument("--max-mean-js", type=_unit_fraction, default=0.25,
                    help="REALISM QUALITY: mean numeric JS distance at/below which the "
                         "numeric axis is 'strong'. A campaign's release_quality_policy can PIN it; "
                         "the CLI may then only TIGHTEN (lower) it [audit 6 / v20.23 §8]")
    ap.add_argument("--max-cat-js", type=_unit_fraction, default=0.25,
                    help="REALISM QUALITY: mean CATEGORICAL JS distance at/below which "
                         "the protocol/TLS/JA3 axis is 'strong' [audit 6]")
    ap.add_argument("--min-tstr-reference-ratio", type=_finite_nonneg, default=0.8,
                    help="REALISM QUALITY: TSTR/reference ratio at/above which the "
                         "predictive-transfer axis is 'strong' [audit 6]")
    ap.add_argument("--min-reference-f1", type=_unit_fraction, default=0.5,
                    help="REALISM QUALITY: the transfer axis cannot be 'strong' unless "
                         "the ABSOLUTE reference macro-F1 is at least this (a 1.0 ratio "
                         "when both models are ~0.2 is not good) [audit 13]")
    ap.add_argument("--max-cond-js", type=_unit_fraction, default=0.3,
                    help="REALISM QUALITY: worst-CLASS mean JS at/below which the "
                         "class-conditional axis is 'strong' [audit 8]")
    ap.add_argument("--max-missing-rate-difference", type=_unit_fraction, default=0.15,
                    help="REALISM QUALITY: max |missing_rate_real - missing_rate_synth| "
                         "per feature for the missingness axis to be 'strong' [audit 9]")
    ap.add_argument("--domain-distinguishability", action="store_true",
                    help="also train a real-vs-synthetic classifier and report its held-out AUC "
                         "(0.5 = indistinguishable; high = systematic generation artifacts), plus "
                         "per-class AUC and top features [audit v20.17 §11.6]")
    ap.add_argument("--max-domain-auc", type=_unit_fraction, default=None,
                    help="if set with --domain-distinguishability, a real-vs-synth macro-AUC ABOVE "
                         "this FAILS the release gate: 'release_eligible' becomes false AND the "
                         "process exits non-zero (3). It does NOT touch official/diagnostic — domain "
                         "realism is a data-quality signal, not an evaluation defect [audit v20.20 §10/§12]")
    ap.add_argument("--tstr-balance", action="store_true",
                    help="match synth per-class counts to real_train and average TSTR "
                         "over seeds (fidelity, not volume) [audit 13]")
    ap.add_argument("--allow-partial-campaign", action="store_true",
                    help="do NOT require the full ALLOWED_LABELS vocabulary; without it "
                         "(and without --expected-labels) the official run expects ALL "
                         "of {} [audit 7]".format(sorted(fs.ALLOWED_LABELS)))
    ap.add_argument("--allow-contract-violations", action="store_true",
                    help="DIAGNOSTIC: evaluate even if real/synth COMMON values or "
                         "derived relations are physically impossible (default: abort) [audit 7]")
    ap.add_argument("--allow-partial-schema", action="store_true",
                    help="DIAGNOSTIC: accept files that are NOT run_id+timestamp+15 "
                         "COMMON+label (real) / 15 COMMON+label (synth); default aborts "
                         "so missing features are not silently imputed [audit 8]")
    ap.add_argument("--by-class", action="store_true",
                    help="also compare distributions separately per class")
    ap.add_argument("--trust-run-order", action="store_true",
                    help="DIAGNOSTIC ONLY: accept a run_id split without timestamps "
                         "(run order is assumed chronological, NOT verified)")
    ap.add_argument("--allow-random-diagnostic", action="store_true",
                    help="DIAGNOSTIC ONLY: allow a random split when there is no time "
                         "at all (NOT chronological; never an official pass)")
    ap.add_argument("--allow-single-run-diagnostic", action="store_true",
                    help="DIAGNOSTIC ONLY: allow a 70/30 split inside a single run "
                         "(train/test may share a session/tool; never an official pass)")
    ap.add_argument("--max-overlap-allowed", type=float, default=0.0,
                    help="max fraction of real rows allowed to also appear in synth "
                         "before ABORT (default 0.0: ANY overlap aborts an official "
                         "run). Raising it only enables a DIAGNOSTIC run, never a "
                         "PASS [audit 7]")
    ap.add_argument("--allow-extra-labels", action="store_true",
                    help="permit labels outside feature_schema.ALLOWED_LABELS "
                         "(default: abort on any unknown class) [audit 8]")
    args = ap.parse_args()
    if not (0.0 <= args.max_overlap_allowed < 1.0):
        sys.exit("--max-overlap-allowed must be in [0.0, 1.0).")
    if args.max_domain_auc is not None and not args.domain_distinguishability:
        sys.exit("ABORT: --max-domain-auc needs --domain-distinguishability (the gate would "
                 "otherwise be silently ignored). [audit v20.18 §10]")

    # Refuse a circular evaluation on identical inputs [audit 5].
    if any(sha256(p) == sha256(args.synth) for p in args.real):
        sys.exit("ABORT: a --real file is identical (SHA-256) to --synth; realism "
                 "would be trivially 'perfect'. [audit 5]")
    # Refuse the SAME real file passed twice — it would concatenate real onto itself
    # and inflate the evaluation [audit 13].
    real_hashes = [sha256(p) for p in args.real]
    if len(real_hashes) != len(set(real_hashes)):
        sys.exit("ABORT: --real lists the same file/content more than once. [audit 13]")

    # SCHEMA-AWARE read: categorical values as strings across files (tls_version='1.3' etc.) [P0-2].
    real_full = pd.concat([fs.read_common_csv(p) for p in args.real], ignore_index=True)
    synth_full = fs.read_common_csv(args.synth)
    # Drop known-ambiguous rows if handed an *_audit.csv* (label noise) [audit 14].
    if "ambiguous" in real_full.columns:
        amb = pd.to_numeric(real_full["ambiguous"], errors="coerce").fillna(0) != 0
        if amb.any():
            print("NOTE: audit file on --real — dropping {} ambiguous row(s) (prefer "
                  "*_split_ready.csv*) [audit 14].".format(int(amb.sum())))
            real_full = real_full[~amb].reset_index(drop=True)
    # STRUCTURAL contract: real must be run_id+timestamp+15 COMMON+label; synth at
    # least 15 COMMON+label. Otherwise to_common fabricates the missing columns and
    # the metrics are computed on imputed nothing [audit 8/9].
    if not args.allow_partial_schema:
        re_err = fs.check_official_columns(real_full, require_time=True)
        se_err = fs.check_official_columns(synth_full, require_time=False)
        if re_err or se_err:
            sys.exit("ABORT: not official split-ready schema (real: {} | synth: {}). "
                     "Feed *_split_ready.csv*, or pass --allow-partial-schema "
                     "(diagnostic). [audit 8/9]".format(re_err or "ok", se_err or "ok"))
    real_time = extract_time(real_full)
    real_runid = (pd.to_numeric(real_full["run_id"], errors="coerce")
                  if "run_id" in real_full.columns else None)
    real, synth = fs.to_common(real_full), fs.to_common(synth_full)
    if real_time is not None:
        real_time = real_time.reindex(real.index)
    if real_runid is not None:
        real_runid = real_runid.reindex(real.index)
        rv = real_runid.to_numpy(dtype=float)                # [audit 7]
        if not np.isfinite(rv).all() or not np.all(rv == np.floor(rv)) or (rv < 0).any():
            sys.exit("ABORT: real run_id must be present, integer and non-negative "
                     "for EVERY row. [audit 7]")
    if LABEL not in real.columns or LABEL not in synth.columns:
        sys.exit("Both files need a 'label' column.")
    # No missing/empty labels and (unless overridden) no stray classes [audit 4/8].
    fs.require_valid_labels(real[LABEL], "real", allow_extra=args.allow_extra_labels)
    fs.require_valid_labels(synth[LABEL], "synth", allow_extra=args.allow_extra_labels)
    # Any file that influences a metric must satisfy the same physical/relational
    # contract as the official split [audit 7].
    for _nm, _d in (("real", real), ("synth", synth)):
        _errs, _warns = fs.common_contract_violations(_d)
        for _w in _warns:
            print("WARNING ({} value domain): {}".format(_nm, _w))
        if _errs and not args.allow_contract_violations:
            sys.exit("ABORT: {} COMMON contract violated: {}. Pass "
                     "--allow-contract-violations to force (diagnostic). [audit 7]".format(
                         _nm, "; ".join(_errs)))

    print("=" * 70)
    print("REALISM EVALUATION ({}, common schema) — real {} / synth {} rows".format(CODE_VERSION,
        len(real), len(synth)))
    print("=" * 70)

    # Class coverage (never hide classes behind an intersection) [audit 6].
    rl, sl = set(real[LABEL]), set(synth[LABEL])
    print("Class coverage: common={} | only_real={} | only_synth={}".format(
        sorted(rl & sl), sorted(rl - sl), sorted(sl - rl)))
    # Overlap / leakage between the two files [audit 5/7]. For an OFFICIAL run any
    # overlap aborts (default --max-overlap-allowed 0.0): a TSTR test with real
    # rows copied into synth is partly evaluating on the training data. Raising
    # the threshold only permits a DIAGNOSTIC run (overlap_diag=True forces the
    # final verdict to DIAGNOSTIC, never PASS).
    ov_frac, ov_count = row_overlap(real, synth)
    print("Row overlap (normalized, real in synth): {:.2%} ({} rows)".format(ov_frac, ov_count))
    if ov_frac > args.max_overlap_allowed:
        sys.exit("ABORT: {:.2%} of real rows are identical to synth rows (> "
                 "--max-overlap-allowed {:.2%}). An official realism evaluation must "
                 "have {}. [audit 7]".format(
                     ov_frac, args.max_overlap_allowed,
                     "ZERO overlap" if args.max_overlap_allowed == 0
                     else "overlap <= the allowed threshold"))
    overlap_diag = ov_frac > 0
    if overlap_diag:
        print("  CRITICAL WARNING: nonzero real/synth overlap -> optimistic results; "
              "DIAGNOSTIC only, never a PASS. [audit 7]")

    mean_js, mean_cat_js = compare(real, synth, tag="[global]")
    if args.by_class:
        for lab in sorted(rl | sl):                     # UNION, not intersection
            if lab not in rl:
                print("\n[dist] [class={}] MISSING in REAL (skipped)".format(lab))
            elif lab not in sl:
                print("\n[dist] [class={}] MISSING in SYNTH (skipped) [audit 6]".format(lab))
            else:
                compare(real[real[LABEL] == lab], synth[synth[LABEL] == lab],
                        tag="[class={}]".format(lab))

    # With a campaign manifest, the split is DICTATED by the manifest — NOT inferred
    # from max(run_id). real_train = train runs, real_test = test runs; validation
    # runs are held out of both. Every declared run must be present and no extra run
    # allowed, so a reserved-test run can never drift into training [audit 5].
    campaign_split = False
    unauthenticated_real = False                          # set True only via the explicit flag
    auth_records = None                                   # per-file byte-auth evidence for --json [P1-10]
    if args.campaign:
        manifest = camp.load(args.campaign,
                             require_reproducible=not args.allow_incomplete_campaign)
        if real_runid is None:
            sys.exit("ABORT: --campaign needs a run_id column on --real. [audit 5]")
        present = set(int(x) for x in real_runid.dropna().unique())
        declared = set(int(r) for r in (manifest.get("runs") or {}))
        if present != declared:
            sys.exit("ABORT: --real runs {} != campaign runs {} (no extra/missing runs "
                     "allowed). [audit 5]".format(sorted(present), sorted(declared)))
        # OFFICIAL realism REQUIRES byte-authenticated real files: each --real is one run's
        # split_ready, authenticated (bytes + run_id + campaign + policy) via the same chain
        # the merge uses. Without --status the verdict can only be DIAGNOSTIC — an
        # unauthenticated real set proves nothing about who produced it [audit v20 P0-8].
        unauthenticated_real = False
        if args.status or args.require_status:
            if not args.status:
                sys.exit("ABORT: --require-status needs --status <sidecars>. [audit 9]")
            prov.require_official_policy(manifest, args.allow_missing_required_policy)
            # Keep the per-file authentication record so the --json can PROVE which sidecar
            # (sha/run_id/policy/diagnostic_reasons) authenticated each real file [audit v20.4 P1-10].
            auth_records = prov.authenticate_against_campaign(
                args.real, args.status, manifest, args.campaign, True,
                allow_diagnostic=args.allow_diagnostic_status)
        elif args.allow_unauthenticated_real:
            unauthenticated_real = True                   # explicit: proceed, but DIAGNOSTIC
        else:
            sys.exit("ABORT: official campaign realism needs --status (one sidecar per "
                     "--real file) so the real set is byte-authenticated. Pass --status with "
                     "--require-status, or --allow-unauthenticated-real to run WITHOUT it "
                     "(forces DIAGNOSTIC ONLY). [audit v20 P0-8]")
        train_runs = set(camp.runs_in_split(manifest, "train"))
        test_runs = set(camp.runs_in_split(manifest, "test"))
        if not train_runs or not test_runs:
            sys.exit("ABORT: campaign must declare train AND test runs. [audit 5]")
        tr = real.index[real_runid.isin(train_runs)]
        te = real.index[real_runid.isin(test_runs)]
        val_idx = real.index[real_runid.isin(set(camp.runs_in_split(manifest, "validation")))]
        how = "campaign hold-out: test runs {}".format(sorted(test_runs))
        campaign_split = True
    else:
        tr, te, how = real_split(real, real_runid, real_time)
        val_idx = None
    # Fail-closed chronology [audit 4].
    if real_time is not None:
        tvals = real_time.to_numpy(dtype=float)
        if not np.isfinite(tvals).all():
            sys.exit("ABORT: real timestamp is incomplete/non-finite ({} bad rows); "
                     "an official split needs a valid ts for EVERY row. [audit 4]".format(
                         int((~np.isfinite(tvals)).sum())))
        # Chronology must be train < validation < test — validation is NOT ignored,
        # so a run ordered after the test can never be used for tuning [audit 4].
        val_ts = (real_time.loc[val_idx] if val_idx is not None and len(val_idx) else None)
        if camp.chronology_ok(real_time.loc[tr], real_time.loc[te], val_ts) is False:
            sys.exit("ABORT: real split is NOT chronological (need train < validation < "
                     "test). [audit 4]")
    elif how.startswith("hold out last run_id"):
        if not args.trust_run_order:
            sys.exit("ABORT: run_id split has NO timestamp to verify chronology "
                     "(run order does not prove time order). Pass --trust-run-order "
                     "(DIAGNOSTIC only). [audit 4]")
    elif how.startswith("random"):
        if not args.allow_random_diagnostic:
            sys.exit("ABORT: no verifiable time (no timestamp, no usable run_id). A "
                     "random split is NOT chronological; pass --allow-random-diagnostic "
                     "to run it as DIAGNOSTIC only. [audit 6]")
    elif campaign_split and not args.trust_run_order:      # run-based, no timestamp
        sys.exit("ABORT: campaign split has NO timestamp to verify that train runs "
                 "precede test runs. Pass --trust-run-order (DIAGNOSTIC only). [audit 5]")

    # A 70/30 split inside a SINGLE run/timeline is chronological but train/test may
    # share the same session/tool/fingerprint -> diagnostic only [audit 4]. A
    # campaign split is multi-run by construction.
    single_run = (not campaign_split) and ((real_runid is None) or (real_runid.nunique() < 2))
    if how.startswith("earliest 70%") and single_run and not args.allow_single_run_diagnostic:
        sys.exit("ABORT: 70/30 within a SINGLE run/timeline (train/test may share the "
                 "same session/tool/fingerprint). Use >=2 runs, or pass "
                 "--allow-single-run-diagnostic (NOT an official pass). [audit 4]")

    te_labels = set(real.loc[te, LABEL].unique())
    tr_labels = set(real.loc[tr, LABEL].unique())
    # Expected-label coverage. DEFAULT is the full ALLOWED_LABELS vocabulary, so an
    # official run silently missing a class fails unless the campaign explicitly
    # opts out (--allow-partial-campaign) or names its own set (--expected-labels)
    # [audit 7]. Each expected class must appear in real_train AND real_test AND synth.
    if args.campaign:                                     # manifest wins; CLI confirms [audit 6]
        m_labels = sorted(manifest["expected_labels"])
        if args.expected_labels is not None and sorted(args.expected_labels) != m_labels:
            sys.exit("ABORT: --expected-labels contradicts the campaign manifest. [audit 6]")
        want = set(m_labels)
        # §14 [audit v20.21]: a PINNED max_domain_auc is the PRE-REGISTERED release bar. Require the
        # detector to run and let the CLI only CONFIRM or TIGHTEN it — a more permissive CLI aborts, so
        # release-eligibility can't be judged against a threshold picked after seeing the AUC.
        # §8 [audit v20.23]: a COMPLETE release_quality_policy PRE-REGISTERS every threshold — including
        # the AXIS thresholds that DEFINE "strong". Promote its release fields to the effective pins (so
        # the gate/quality checks below read them) and TIGHTEN the axis-threshold CLI args to it: the CLI
        # may only make a threshold STRICTER, never relax it, so "strong" can't be redefined after seeing
        # the numbers (the exact CLI bypass the auditor reproduced).
        rqp = manifest.get("release_quality_policy") or {}
        for k in ("max_domain_auc", "min_overall_realism_quality", "min_domain_test_samples_per_class"):
            if k in rqp:
                manifest[k] = rqp[k]                       # the block is the source of truth for these
        for a, lower_is_stricter in (("max_mean_js", True), ("max_cat_js", True), ("max_cond_js", True),
                                     ("max_missing_rate_difference", True),
                                     ("min_tstr_reference_ratio", False), ("min_reference_f1", False)):
            if a in rqp:                                    # stricter of the pin and the CLI value
                cur = getattr(args, a)
                setattr(args, a, min(cur, rqp[a]) if lower_is_stricter else max(cur, rqp[a]))
        if manifest.get("max_domain_auc") is not None:
            _pin = float(manifest["max_domain_auc"])
            if not args.domain_distinguishability:
                sys.exit("ABORT: campaign PINS max_domain_auc={}; pass --domain-distinguishability so "
                         "the release gate actually runs. [audit v20.21 §14]".format(_pin))
            if args.max_domain_auc is None:
                args.max_domain_auc = _pin
            elif args.max_domain_auc > _pin:
                sys.exit("ABORT: --max-domain-auc {} is MORE PERMISSIVE than the campaign's pinned {}. "
                         "Match or lower it. [audit v20.21 §14]".format(args.max_domain_auc, _pin))
        # EXACT class set: an UNPLANNED class in the REAL data must abort [audit 7].
        if not args.allow_extra_campaign_labels:
            observed = set(str(x) for x in pd.Series(real[LABEL]).dropna().unique())
            extra = sorted(observed - set(str(x) for x in m_labels))
            if extra:
                sys.exit("ABORT: real class(es) {} not in campaign expected_labels {}; a "
                         "campaign declares its EXACT set. Pass --allow-extra-campaign-labels."
                         " [audit 7]".format(extra, m_labels))
        # The SYNTHETIC set must ALSO equal the campaign's classes — a class present only in
        # synthetic shifts the multiclass boundary and makes TSTR/reference asymmetric, so it
        # must abort by default (the flag that allows it is DIAGNOSTIC) [audit v19 P0-4].
        if not args.allow_extra_synthetic_labels:
            s_extra = sorted(set(str(x) for x in pd.Series(synth[LABEL]).dropna().unique())
                             - set(str(x) for x in m_labels))
            if s_extra:
                sys.exit("ABORT: synthetic-only class(es) {} not in campaign expected_labels "
                         "{}; a class only in the synthetic set biases TSTR. Pass "
                         "--allow-extra-synthetic-labels (DIAGNOSTIC). [audit v19 P0-4]".format(
                             s_extra, m_labels))
    elif args.expected_labels:
        want = set(args.expected_labels)
    else:
        want = None if args.allow_partial_campaign else set(fs.ALLOWED_LABELS)
    exp_missing = []
    if want:
        # Include real_VALIDATION so a class missing from the tuning split also fails —
        # otherwise "full expected coverage" is claimed while validation is incomplete [audit 8].
        checks = [("real_train", tr_labels), ("real_test", te_labels), ("synth", sl)]
        if val_idx is not None and len(val_idx):
            checks.insert(2, ("real_validation", set(real.loc[val_idx, LABEL])))
        for nm, have in checks:
            miss = sorted(want - have)
            if miss:
                exp_missing.append((nm, miss))
        for nm, miss in exp_missing:
            print("\n[EXPECTED-LABELS] {} is MISSING expected class(es) {} [audit 5/7/8]".format(nm, miss))
        if exp_missing and not args.allow_missing_expected_labels:
            sys.exit("ABORT: expected class(es) missing from a split (above, incl. "
                     "validation). Combine runs that cover them, name a smaller "
                     "--expected-labels set, or pass --allow-missing-expected-labels / "
                     "--allow-partial-campaign to run as DIAGNOSTIC. [audit 5/7/8]")

    passed = True
    tstr_ratio = ref_f1 = tstr_f1 = float("nan")
    if real.loc[te, LABEL].nunique() < 2:
        print("\n[TSTR ABORTED] real_test ({}) has <2 classes. [audit 4]".format(how))
        passed = False
    elif te_labels - tr_labels:
        print("\n[TSTR ABORTED] real_train is MISSING class(es) present in real_test: "
              "{} -- the real REFERENCE never saw them, so TSTR/reference is invalid "
              "(use runs where train covers all test classes, or treat as open-set). "
              "[audit 8]".format(sorted(te_labels - tr_labels)))
        passed = False
    elif te_labels - sl:
        print("\n[TSTR ABORTED] synth is missing class(es) present in real_test: {} "
              "-- an incomplete generator must not get a passing TSTR. [audit 6]".format(
                  sorted(te_labels - sl)))
        passed = False
    else:
        tstr_ratio, ref_f1, tstr_f1 = tstr_trts(real, synth, tr, te, how,
                                                balance=args.tstr_balance)
        perturbation(real, tr, te)

    # Verdict SEPARATES evaluation integrity from realism quality [audit 6].
    if passed:
        # Chronology is only VERIFIED when a timestamp exists; any run-order-only
        # split (incl. a campaign split without ts) is trusted, not verified [audit 8].
        trusted = args.trust_run_order and real_time is None
        # ANY methodological bypass makes the whole run DIAGNOSTIC — an INTEGRITY PASS must
        # not be printed just because a check was relaxed. EVERY allow-*/trust-* flag counts,
        # not only the schema/contract ones [audit v19 P0-3].
        override_flags = {
            "allow_partial_schema": args.allow_partial_schema,
            "allow_contract_violations": args.allow_contract_violations,
            "allow_extra_labels": args.allow_extra_labels,
            "allow_partial_campaign": args.allow_partial_campaign,
            "allow_diagnostic_status": args.allow_diagnostic_status,
            "allow_extra_campaign_labels": args.allow_extra_campaign_labels,
            "allow_incomplete_campaign": args.allow_incomplete_campaign,
            "allow_missing_expected_labels": args.allow_missing_expected_labels,
            "allow_extra_synthetic_labels": getattr(args, "allow_extra_synthetic_labels", False),
            "trust_run_order": args.trust_run_order,
            "allow_random_diagnostic": args.allow_random_diagnostic,
            "allow_single_run_diagnostic": args.allow_single_run_diagnostic,
            "allow_unauthenticated_real": unauthenticated_real,   # [audit v20 P0-8]
            "allow_missing_required_policy": (args.campaign is not None
                                              and args.allow_missing_required_policy),
            # An evaluation WITHOUT a campaign proves integrity but NOT provenance — it is
            # ad-hoc/diagnostic, exactly as the merge marks a no-campaign split [audit v20.3 P0-7].
            "no_campaign": args.campaign is None,
        }
        used_overrides = [k for k, v in override_flags.items() if v]
        diag_reasons = []
        if overlap_diag:
            diag_reasons.append("nonzero overlap")
        if exp_missing:
            diag_reasons.append("missing expected class")
        if trusted:
            diag_reasons.append("run order trusted, chronology not verified")
        if how.startswith("random"):
            diag_reasons.append("random split")
        if how.startswith("earliest 70%") and single_run:
            diag_reasons.append("single-run 70/30")
        if args.campaign is not None and camp.bruteforce_unpinned(manifest):
            diag_reasons.append("brute_force_wordlists_unpinned")   # [audit v20.7 P0-1]
        diag_reasons.extend(used_overrides)
        diagnostic = bool(diag_reasons)
        # Real-vs-synthetic DISTINGUISHABILITY (opt-in) [audit v20.17 §11.6 / v20.18 §10/§12]. This is
        # a REALISM signal, kept SEPARATE from `official`/`diagnostic` (which are about EVALUATION
        # integrity): a valid evaluation may reveal a poorly-realistic dataset without being
        # "diagnostic". Its own `gate` feeds a distinct `release_eligible`. The gate judges the
        # prevalence-ROBUST macro-AUC (fall back to raw only if no class had both domains); a
        # requested gate that can't be computed FAILS CLOSED [§10]. States: "not_evaluated" (detector
        # NOT run) | None (ran, no threshold) | "pass" | "fail" | "unavailable" [audit v20.20 §11].
        domain, domain_gate = None, "not_evaluated"
        if args.domain_distinguishability:
            synth_runid = (pd.to_numeric(synth_full["run_id"], errors="coerce").reindex(synth.index)
                           if "run_id" in synth_full.columns else None)
            domain = domain_distinguishability(real, synth, real_runid, synth_runid)
            metric = domain.get("macro_auc")
            if metric is None:
                metric = domain.get("auc_raw")
            if domain.get("auc_raw") is not None:
                print("\n[domain real-vs-synth] macro-AUC={} (raw={}, held out by {}); "
                      "0.5≈indistinguishable, high≈artifacts. per-class={} prevalence r/s={}/{} "
                      "top={}".format(domain.get("macro_auc"), domain.get("auc_raw"),
                                      domain.get("held_out_by"), domain.get("per_class_auc"),
                                      domain.get("prevalence_real"), domain.get("prevalence_synth"),
                                      [t["feature"] for t in domain.get("top_features", [])]))
                # §13 [audit v20.21]: per-class AUC only covers classes with BOTH domains in the test
                # holdout, so a macro-AUC can silently OMIT an expected class and a gate could "pass"
                # without ever judging it. Record which expected classes lacked real+synth test
                # support; if a gate is requested and ANY is missing, FAIL CLOSED as "unavailable".
                support = domain.get("class_support_test") or {}
                # §10 [audit v20.22]: require ENOUGH held-out support per class, not merely >=1 — a
                # per-class AUC read off 1-2 points is high-variance. The campaign may PIN the minimum.
                min_samples = manifest.get("min_domain_test_samples_per_class", 1) if args.campaign else 1
                missing = sorted(c for c in (want or set())
                                 if support.get(c, {}).get("real", 0) < min_samples
                                 or support.get(c, {}).get("synth", 0) < min_samples)
                domain["missing_domain_test_classes"] = missing
                domain["min_domain_test_samples_per_class"] = min_samples
                if args.max_domain_auc is None:
                    domain_gate = None                     # ran, no threshold -> not eligible, informational
                elif missing:
                    domain_gate = "unavailable"            # expected class(es) unjudged -> fail closed
                    print("[domain gate] UNAVAILABLE: expected class(es) {} lacked real+synth support "
                          "in the test holdout; macro-AUC did not judge them. [audit v20.21 §13]".format(
                              missing))
                else:
                    domain_gate = "pass" if metric <= args.max_domain_auc else "fail"
            else:
                print("\n[domain real-vs-synth] AUC UNAVAILABLE: {}".format(domain.get("note")))
                # requested gate couldn't run -> fail closed; no threshold -> ran-but-null.
                domain_gate = "unavailable" if args.max_domain_auc is not None else None
            domain["gate"] = domain_gate
            domain["max_domain_auc"] = args.max_domain_auc
        if diagnostic:
            print("\nDIAGNOSTIC ONLY ({}) — metrics are indicative, NOT an official "
                  "pass. [audit 5/6/7/8/P0-3]".format("; ".join(diag_reasons)))
        else:
            print("\nINTEGRITY CHECKS PASSED (distinct files, no overlap, full expected "
                  "coverage, chronological multi-run split VERIFIED by timestamp) — "
                  "REALISM NOT ENDORSED. [audit 6]")
        # Extra axes: class-CONDITIONAL fidelity (P(X|Y), worst class) [audit 8] and
        # MISSINGNESS fidelity (per-feature missing-rate difference) [audit 9].
        worst_lab, cnum, ccat = conditional_js(real, synth, set(real[LABEL]) & set(synth[LABEL]))
        cond_js = max(cnum, ccat)
        miss_diff, miss_feat, miss_rows = missingness_report(real, synth)

        # Per-axis REALISM QUALITY. The overall grade is the WEAKEST axis, so strong
        # global numerics cannot hide disjoint protocols, per-class mixing, a bad
        # missingness pattern, or a transfer that is only "good" in ratio [audit 6/8/9/13].
        def _axis(strong, moderate):
            return "strong" if strong else ("moderate" if moderate else "poor")
        num_axis = _axis(np.isfinite(mean_js) and mean_js <= args.max_mean_js,
                         np.isfinite(mean_js) and mean_js <= 2 * args.max_mean_js)
        cat_axis = _axis(np.isfinite(mean_cat_js) and mean_cat_js <= args.max_cat_js,
                         np.isfinite(mean_cat_js) and mean_cat_js <= 2 * args.max_cat_js)
        cond_axis = _axis(cond_js <= args.max_cond_js, cond_js <= 2 * args.max_cond_js)
        miss_axis = _axis(miss_diff <= args.max_missing_rate_difference,
                          miss_diff <= 2 * args.max_missing_rate_difference)
        # Transfer 'strong' needs BOTH a good ratio AND a MEANINGFUL absolute reference
        # (ratio 1.0 when both are ~0.2 is not good) [audit 13].
        ratio_strong = np.isfinite(tstr_ratio) and tstr_ratio >= args.min_tstr_reference_ratio
        ref_meaningful = np.isfinite(ref_f1) and ref_f1 >= args.min_reference_f1
        tr_axis = _axis(ratio_strong and ref_meaningful,
                        np.isfinite(tstr_ratio) and tstr_ratio >= 0.5 * args.min_tstr_reference_ratio)
        rank = {"strong": 2, "moderate": 1, "poor": 0}
        overall = min((num_axis, cat_axis, cond_axis, miss_axis, tr_axis), key=lambda a: rank[a])
        print("REALISM QUALITY (overall = weakest axis): {}".format(overall))
        print("  Numeric distribution fidelity : {} (mean JS={:.3f} vs <= {:.2f})".format(
            num_axis, mean_js, args.max_mean_js))
        print("  Categorical/protocol fidelity : {} (mean JS={:.3f} vs <= {:.2f})".format(
            cat_axis, mean_cat_js, args.max_cat_js))
        print("  Class-conditional fidelity    : {} (worst class={} JS={:.3f} vs <= {:.2f})".format(
            cond_axis, worst_lab, cond_js, args.max_cond_js))
        print("  Missingness fidelity          : {} (max |Δmiss|={:.3f} on {} vs <= {:.2f})".format(
            miss_axis, miss_diff, miss_feat, args.max_missing_rate_difference))
        print("  Predictive transfer (TSTR)    : {} (TSTR/ref={:.2f} vs >= {:.2f}; abs "
              "ref F1={:.3f} vs >= {:.2f})".format(
                  tr_axis, tstr_ratio, args.min_tstr_reference_ratio, ref_f1, args.min_reference_f1))
        print("  (INTEGRITY PASSED means the EVALUATION is valid, NOT that the data is "
              "realistic — read the axes above.)")
        # THREE separate concepts [audit v20.18 §12]: integrity_passed (the evaluation is VALID),
        # official/diagnostic (provenance), and release_eligible (integrity AND a PASSING domain
        # realism gate). Domain distinguishability is a REALISM signal, not an evaluation defect, so it
        # drives release_eligible — never `official`/`diagnostic`. FAIL-CLOSED [audit v20.20 §11]: a run
        # that never evaluated the detector (gate "not_evaluated"/None) is NOT release-eligible — only
        # an explicit "pass" earns it, so "we forgot to run the check" can never look release-ready.
        # §11 [audit v20.22]: release_eligible is NOT the domain gate alone — if the campaign PINS
        # min_overall_realism_quality, the WEAKEST realism axis must also reach it, so a dataset that is
        # distinguishable-but-"moderate" (the auditor's SYNTH-fingerprint case) is not release-eligible.
        min_q = manifest.get("min_overall_realism_quality") if args.campaign else None
        quality_ok = (min_q is None) or (rank.get(overall, 0) >= rank.get(min_q, 99))
        # §9 [audit v20.25]: release-eligibility now REQUIRES a COMPLETE, pre-registered
        # release_quality_policy. The legacy top-level fields (a bare max_domain_auc) are NOT enough —
        # they leave the AXIS thresholds that define "strong" free on the CLI. Without a complete policy
        # the run may be `official` (authenticated + reproducible) but is NOT release-eligible; the
        # reason is recorded so a release script can tell "authenticated" from "cleared for release".
        release_policy_complete = bool(args.campaign and manifest.get("release_quality_policy"))
        release_reasons = []
        if diagnostic:
            release_reasons.append("diagnostic")
        if not release_policy_complete:
            release_reasons.append("legacy_or_incomplete_release_policy")
        if domain_gate != "pass":
            release_reasons.append("domain_gate_" + str(domain_gate))
        if not quality_ok:
            release_reasons.append("overall_quality_below_bar")
        release_eligible = not release_reasons
        if min_q is not None and not quality_ok:
            print("[release] BLOCKED: overall realism quality '{}' is below the campaign's pinned "
                  "min_overall_realism_quality '{}'. [audit v20.22 §11]".format(overall, min_q))
        if args.campaign and not release_policy_complete:
            print("[release] NOT eligible: no complete release_quality_policy pinned "
                  "(legacy_or_incomplete_release_policy). [audit v20.25 §9]")
        _emit_json(
            args.json, official=not diagnostic, diagnostic=diagnostic,
            diagnostic_reasons=diag_reasons, integrity_passed=True, how=how,
            release_eligible=release_eligible, release_policy_complete=release_policy_complete,
            release_ineligible_reasons=release_reasons, domain_realism_gate=domain_gate,
            realism_quality=overall, min_overall_realism_quality=min_q,   # pre-registered bar [§11]
            code_version=CODE_VERSION,
            campaign={"path": args.campaign, "sha256": prov.sha256(args.campaign)}
                     if args.campaign else None,
            inputs={"real": [{"path": p, "sha256": prov.sha256(p)} for p in args.real],
                    "synth": {"path": args.synth, "sha256": prov.sha256(args.synth)}},
            input_authentication=auth_records,           # per-file byte-auth chain [audit v20.4 P1-10]
            classes={"expected": sorted(want) if want else None,
                     "real": sorted(set(map(str, real[LABEL].dropna().unique()))),
                     "synth": sorted(set(map(str, synth[LABEL].dropna().unique())))},
            runs=sorted(int(x) for x in real_runid.dropna().unique()) if real_runid is not None else None,
            overrides_used=used_overrides,
            thresholds={"max_mean_js": args.max_mean_js, "max_cat_js": args.max_cat_js,
                        "max_cond_js": args.max_cond_js,
                        "max_missing_rate_difference": args.max_missing_rate_difference,
                        "min_tstr_reference_ratio": args.min_tstr_reference_ratio,
                        "min_reference_f1": args.min_reference_f1},
            axes={"numeric": {"grade": num_axis, "mean_js": float(mean_js)},
                  "categorical": {"grade": cat_axis, "mean_js": float(mean_cat_js)},
                  "conditional": {"grade": cond_axis, "worst_class": worst_lab,
                                  "js": float(cond_js)},
                  "missingness": {"grade": miss_axis, "max_abs_diff": float(miss_diff),
                                  "feature": miss_feat},
                  "transfer": {"grade": tr_axis, "tstr_ref_ratio": float(tstr_ratio),
                               "ref_f1": float(ref_f1), "tstr_f1": float(tstr_f1)}},
            domain_distinguishability=domain)               # real-vs-synth AUC [audit v20.17 §11.6]
        # §9/§10 [audit v20.20/23]: a REQUESTED release gate that FAILS makes a NON-ZERO exit (3,
        # distinct from integrity failure=2), so CI/release scripts can BLOCK on it. This covers the
        # domain AUC gate (fail/unavailable) AND the pinned quality bar — previously a quality-only
        # failure printed release_eligible=false but still exited 0, so a CI running the tool alone
        # thought it succeeded. Without any opt-in gate the exit stays 0 (backward compatible).
        gate_failed = args.max_domain_auc is not None and domain_gate in ("fail", "unavailable")
        quality_failed = (min_q is not None) and (not quality_ok)
        if gate_failed or quality_failed:
            print("\nRELEASE GATE FAILED: domain gate '{}' (vs max_domain_auc {}); overall quality "
                  "'{}' (vs pinned {}). Exiting 3. [audit v20.23 §9]".format(
                      domain_gate, args.max_domain_auc, overall, min_q))
            sys.exit(3)
        sys.exit(0)
    print("\nINTEGRITY CHECKS FAILED: not all checks passed (see [TSTR ABORTED] / "
          "[EXPECTED-LABELS] above). [audit 6/7]")
    _emit_json(args.json, official=False, diagnostic=True,
               diagnostic_reasons=["integrity checks failed"], integrity_passed=False,
               how=how, realism_quality=None)
    sys.exit(2)


if __name__ == "__main__":
    main()
