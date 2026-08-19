#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 baseline_experiments.py -- Reference baselines for TLS13-H3-IDS-2026
================================================================================

PURPOSE
-------
Establish honest, reproducible reference baselines for the dataset using two
deliberately SIMPLE models -- a Random Forest (classical ML on flow features)
and a plain CNN (deep learning) -- as is appropriate for a *dataset* paper.
The goal is NOT state-of-the-art detection; it is to (a) show the dataset is
learnable, (b) give a floor for future work, and (c) EXPOSE the effect of
strong identification information (SII) via an ablation, following the S&P 2025
SoK (Wickramasinghe et al.) finding that IP/port leakage inflates accuracy.

WHAT IT DOES
------------
For each model, it trains and evaluates under TWO feature regimes:
  * "behavioural"  -> SII columns (IPs, ports, timestamps) are EXCLUDED.
                      This is the regime you should report as the real result.
  * "with_sii"     -> SII columns are INCLUDED. Expected to inflate scores;
                      reported ONLY as an ablation to demonstrate the shortcut.
The gap between the two is the headline evidence that the dataset does not
reward identity lookup and that SII must be dropped by the modeller.

METHODOLOGY (fixed, honest)
---------------------------
- Split: the dataset's own temporal split (train / val / test) is used AS GIVEN.
  We never reshuffle -- doing so would destroy the temporal guarantee and
  reintroduce leakage.
- Metrics: because the classes are imbalanced (BruteForce ~0.26%), we report
  macro-F1, balanced accuracy, per-class precision/recall/F1, and the confusion
  matrix. Overall accuracy is printed but must NOT be the headline number.
- Determinism: a fixed seed is set for reproducibility.

USAGE
-----
    pip install pandas numpy scikit-learn --break-system-packages
    # CNN also needs torch (CPU is fine):
    pip install torch --break-system-packages

    python3 baseline_experiments.py \
        --train /mnt/nids-captures/release/tls13_h3_ids_2026_train.csv \
        --val   /mnt/nids-captures/release/tls13_h3_ids_2026_val.csv   \
        --test  /mnt/nids-captures/release/tls13_h3_ids_2026_test.csv  \
        --label-col label \
        --outdir  /mnt/nids-captures/release/baselines

    # Random Forest only (skip the CNN if torch is unavailable):
    python3 baseline_experiments.py ... --models rf

OUTPUT
------
- Console tables per (model x regime).
- baseline_results.json : every metric, for pasting into the paper's tables.
  Numbers are produced by YOUR run; nothing is fabricated.
================================================================================
"""

import argparse
import json
import os
import sys
import time
from typing import List, Tuple

import numpy as np
import pandas as pd


# ------------------------------------------------------------------------------
# SII (Strong Identification Information) / non-behavioural columns
# ------------------------------------------------------------------------------
# EXPLICIT exclusion list, fixed to the TLS13-H3-IDS-2026 schema (conservative
# configuration). These columns are RETAINED in the released dataset as
# provenance/context metadata, but are EXCLUDED from the modelling features so
# that a classifier learns pure flow behaviour rather than host/port/protocol
# identity. Rationale (following Wickramasinghe et al., IEEE S&P 2025):
#   - ja3, ja3s        : TLS client/server fingerprints -> identify the host.
#   - dst_port_class   : destination port -> classic strong identifier.
#   - sni_present      : server-name presence -> host/service signal.
#   - tls_version, alpn: protocol-negotiation metadata, near-perfectly
#                        correlated with class in a lab (would be a shortcut).
#   - transport        : TCP vs QUIC -> here it correlates strongly with class
#                        (PortScan/BruteForce=TCP, DoS partly QUIC), so it is
#                        excluded to avoid a trivial transport-based shortcut.
# Anything not listed here and not the label is treated as a behavioural feature.
SII_COLUMNS = (
    "ja3", "ja3s", "dst_port_class", "sni_present", "tls_version", "alpn",
    "transport",
)

# Columns that are neither features nor SII: the label and any split marker.
NON_FEATURE_HINTS = ("label", "class", "target", "_split", "split")


def classify_columns(df: pd.DataFrame, label_col: str) -> Tuple[List[str], List[str]]:
    """Partition columns into (behavioural_features, sii_features).

    A column is SII iff its name is in the explicit SII_COLUMNS list. The label
    column (and any split marker) is excluded from both lists. Everything else is
    a behavioural feature. The decision is printed so it is fully auditable, and
    we warn if any expected SII column is missing from the file (schema drift).
    """
    behavioural, sii = [], []
    present = set(df.columns)
    for col in df.columns:
        if col == label_col:
            continue  # the target
        # Check the explicit SII list FIRST: some SII names (e.g. dst_port_class)
        # contain a NON_FEATURE_HINT substring ("class") and would otherwise be
        # mis-dropped as a non-feature and silently omitted from the ablation.
        if col in SII_COLUMNS:
            sii.append(col)
            continue
        if any(h in col.lower() for h in NON_FEATURE_HINTS):
            continue  # a split marker or other non-feature bookkeeping column
        behavioural.append(col)
    missing = [c for c in SII_COLUMNS if c not in present]
    if missing:
        print(f"    [warn] expected SII columns absent from file (schema drift?): {missing}")
    return behavioural, sii


# ------------------------------------------------------------------------------
# Feature-matrix construction
# ------------------------------------------------------------------------------
def build_matrix(df: pd.DataFrame, feature_cols: List[str]) -> np.ndarray:
    """Turn the selected columns into a numeric matrix.

    - numeric columns are used as-is;
    - non-numeric (categorical) columns are integer-encoded via a stable hash,
      which is enough for tree models and for a CNN's embedding-free input.
    Missing values are filled with 0 after coercion. This is intentionally
    simple: a dataset baseline should not depend on elaborate preprocessing.
    """
    cols = []
    for c in feature_cols:
        s = df[c]
        if pd.api.types.is_numeric_dtype(s):
            cols.append(pd.to_numeric(s, errors="coerce").fillna(0.0).to_numpy())
        else:
            # stable per-value integer code (hash into a bounded range)
            codes = s.astype(str).map(lambda v: (hash(v) % 100003)).astype(float)
            cols.append(codes.to_numpy())
    if not cols:
        raise SystemExit("ERROR: no feature columns selected -- check --label-col.")
    return np.column_stack(cols)


def encode_labels(y_train, y_val, y_test):
    """Map class strings to integers using the TRAIN classes as the reference."""
    classes = sorted(pd.unique(y_train))
    idx = {c: i for i, c in enumerate(classes)}
    # unseen labels in val/test (should not happen here) map to -1 and are dropped
    def enc(y):
        return np.array([idx.get(v, -1) for v in y])
    return enc(y_train), enc(y_val), enc(y_test), classes


# ------------------------------------------------------------------------------
# Metrics (imbalance-aware) -- the honest reporting the SoK and reviewers expect
# ------------------------------------------------------------------------------
def evaluate(y_true, y_pred, classes) -> dict:
    from sklearn.metrics import (
        accuracy_score, balanced_accuracy_score, f1_score,
        classification_report, confusion_matrix,
    )
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro")),
        "weighted_f1": float(f1_score(y_true, y_pred, average="weighted")),
        "per_class": classification_report(
            y_true, y_pred, target_names=classes, output_dict=True, zero_division=0
        ),
        "confusion": confusion_matrix(y_true, y_pred).tolist(),
    }


def print_report(tag: str, m: dict, classes: List[str]):
    line = "=" * 72
    print(f"\n{line}\n {tag}\n{line}")
    print(f"  accuracy           : {m['accuracy']:.4f}   <-- do NOT headline this")
    print(f"  balanced accuracy  : {m['balanced_accuracy']:.4f}")
    print(f"  macro-F1           : {m['macro_f1']:.4f}   <-- headline metric")
    print(f"  weighted-F1        : {m['weighted_f1']:.4f}")
    print("  per-class F1:")
    for c in classes:
        f1 = m["per_class"].get(c, {}).get("f1-score", 0.0)
        print(f"      {c:12}: {f1:.4f}")


# ------------------------------------------------------------------------------
# Model 1: Random Forest
# ------------------------------------------------------------------------------
def run_random_forest(Xtr, ytr, Xte, yte, classes, seed) -> dict:
    from sklearn.ensemble import RandomForestClassifier
    # Modest, standard settings; class_weight balances the rare BruteForce class.
    clf = RandomForestClassifier(
        n_estimators=200, max_depth=None, n_jobs=-1,
        class_weight="balanced", random_state=seed,
    )
    t0 = time.time()
    clf.fit(Xtr, ytr)
    dt = time.time() - t0
    pred = clf.predict(Xte)
    m = evaluate(yte, pred, classes)
    m["fit_seconds"] = round(dt, 1)
    return m


# ------------------------------------------------------------------------------
# Model 2: plain 1-D CNN (PyTorch, CPU-friendly)
# ------------------------------------------------------------------------------
def run_cnn(Xtr, ytr, Xte, yte, classes, seed, epochs=15) -> dict:
    try:
        import torch
        import torch.nn as nn
        from torch.utils.data import DataLoader, TensorDataset
    except ImportError:
        print("  [skip] torch not installed -- run: pip install torch --break-system-packages")
        return {"skipped": "torch not installed"}

    torch.manual_seed(seed)
    np.random.seed(seed)

    # Standardise features (z-score) using TRAIN statistics only -- no test leakage.
    mu = Xtr.mean(axis=0, keepdims=True)
    sd = Xtr.std(axis=0, keepdims=True) + 1e-8
    Xtr_n = (Xtr - mu) / sd
    Xte_n = (Xte - mu) / sd

    n_classes = len(classes)
    n_feat = Xtr_n.shape[1]

    # A deliberately plain CNN: treat the feature vector as a length-n_feat, 1-channel
    # signal and apply two conv+pool blocks, then a linear head. No architectural tricks
    # (this is the "pure CNN" baseline; your CNN-ECA-Transformer is a different paper).
    class PlainCNN(nn.Module):
        def __init__(self):
            super().__init__()
            self.net = nn.Sequential(
                nn.Conv1d(1, 32, kernel_size=3, padding=1), nn.ReLU(),
                nn.MaxPool1d(2),
                nn.Conv1d(32, 64, kernel_size=3, padding=1), nn.ReLU(),
                nn.AdaptiveMaxPool1d(4),
                nn.Flatten(),
                nn.Linear(64 * 4, 128), nn.ReLU(), nn.Dropout(0.3),
                nn.Linear(128, n_classes),
            )

        def forward(self, x):
            return self.net(x.unsqueeze(1))  # add channel dim -> (B,1,n_feat)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = PlainCNN().to(device)

    # class weights to counter imbalance (inverse frequency, normalised)
    counts = np.bincount(ytr, minlength=n_classes).astype(float)
    weights = (counts.sum() / (counts + 1e-9))
    weights = weights / weights.sum() * n_classes
    crit = nn.CrossEntropyLoss(weight=torch.tensor(weights, dtype=torch.float32, device=device))
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)

    tr_ds = TensorDataset(torch.tensor(Xtr_n, dtype=torch.float32),
                          torch.tensor(ytr, dtype=torch.long))
    tr_dl = DataLoader(tr_ds, batch_size=512, shuffle=True)

    t0 = time.time()
    model.train()
    for ep in range(epochs):
        tot = 0.0
        for xb, yb in tr_dl:
            xb, yb = xb.to(device), yb.to(device)
            opt.zero_grad()
            loss = crit(model(xb), yb)
            loss.backward()
            opt.step()
            tot += float(loss) * len(xb)
        print(f"    epoch {ep+1:2d}/{epochs}  loss={tot/len(tr_ds):.4f}")
    dt = time.time() - t0

    model.eval()
    with torch.no_grad():
        logits = model(torch.tensor(Xte_n, dtype=torch.float32, device=device))
        pred = logits.argmax(1).cpu().numpy()
    m = evaluate(yte, pred, classes)
    m["fit_seconds"] = round(dt, 1)
    return m


# ------------------------------------------------------------------------------
# Orchestration: for each model, run both feature regimes
# ------------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Reference baselines (RF + CNN) with SII ablation.")
    ap.add_argument("--train", required=True)
    ap.add_argument("--val", required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--label-col", default="label")
    ap.add_argument("--models", nargs="+", default=["rf", "cnn"], choices=["rf", "cnn"])
    ap.add_argument("--epochs", type=int, default=15, help="CNN epochs")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--outdir", default="baselines")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    print("[i] loading splits...")
    tr = pd.read_csv(args.train)
    va = pd.read_csv(args.val)
    te = pd.read_csv(args.test)
    print(f"    train={len(tr):,}  val={len(va):,}  test={len(te):,}")

    if args.label_col not in tr.columns:
        raise SystemExit(f"ERROR: label column '{args.label_col}' not found. "
                         f"Columns: {list(tr.columns)[:20]}...")

    behavioural, sii = classify_columns(tr, args.label_col)
    print(f"\n[i] feature partition:")
    print(f"    behavioural features ({len(behavioural)}): {behavioural[:12]}{' ...' if len(behavioural)>12 else ''}")
    print(f"    SII (excluded by default) ({len(sii)}): {sii}")

    ytr_s, yva_s, yte_s = tr[args.label_col].astype(str), va[args.label_col].astype(str), te[args.label_col].astype(str)
    ytr, yva, yte, classes = encode_labels(ytr_s, yva_s, yte_s)
    print(f"    classes: {classes}")

    # two regimes: behavioural-only (report this) and with-SII (ablation)
    regimes = {
        "behavioural": behavioural,
        "with_sii": behavioural + sii,
    }

    results = {"classes": classes, "sii_columns": sii,
               "behavioural_columns": behavioural, "runs": {}}

    for model_name in args.models:
        for regime_name, feats in regimes.items():
            tag = f"{model_name.upper()} | regime={regime_name} | {len(feats)} features"
            Xtr = build_matrix(tr, feats)
            Xte = build_matrix(te, feats)

            if model_name == "rf":
                m = run_random_forest(Xtr, ytr, Xte, yte, classes, args.seed)
            else:
                m = run_cnn(Xtr, ytr, Xte, yte, classes, args.seed, epochs=args.epochs)

            if "skipped" not in m:
                print_report(tag, m, classes)
            results["runs"][f"{model_name}_{regime_name}"] = m

    # headline: the SII gap (evidence the dataset does not reward identity lookup)
    print("\n" + "#" * 72)
    print(" SII ABLATION SUMMARY (macro-F1)")
    print("#" * 72)
    for model_name in args.models:
        b = results["runs"].get(f"{model_name}_behavioural", {})
        s = results["runs"].get(f"{model_name}_with_sii", {})
        if "macro_f1" in b and "macro_f1" in s:
            gap = s["macro_f1"] - b["macro_f1"]
            print(f"  {model_name.upper():4}: behavioural={b['macro_f1']:.4f}  "
                  f"with_SII={s['macro_f1']:.4f}  (SII inflation={gap:+.4f})")

    out = os.path.join(args.outdir, "baseline_results.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False)
    print(f"\n[i] all metrics written to {out}")
    print("[i] Report the 'behavioural' numbers as the result; use the SII gap as evidence.")


if __name__ == "__main__":
    main()
