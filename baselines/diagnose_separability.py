#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 diagnose_separability.py -- Why is binary detection ~perfect on TLS13-H3-IDS-2026?
================================================================================

The binary baselines reach F1 ~ 0.999 and stay there under every occlusion
regime (SII, SNI, JA3, TCP-window removal). That rules out identifier leakage
and any single-feature shortcut, but it does NOT tell us WHETHER the separation
is (A) legitimate attack behaviour or (B) a generator/OS-stack artifact --
benign traffic is generated on NB2 (Windows) and attacks on NB3 (Linux), so a
model could be separating OS stacks rather than attack behaviour.

This script runs two cheap diagnostics to distinguish (A) from (B):

  1. FEATURE IMPORTANCE (Random Forest, cleanest regime): which features carry
     the decision? Volumetric/rate features (packets/s, bytes/s, flow duration,
     fwd/bwd counts) => behaviour (Reading A). OS-correlated features (window
     sizes, header sizes, TTL-like fields) => possible artifact (Reading B).

  2. VOLUME-ONLY PROBE: train using ONLY a handful of behaviour-intrinsic,
     OS-agnostic rate/volume features. If F1 stays high, the separation is
     genuinely behavioural (A). If it collapses, the earlier score leaned on
     platform-correlated features (B).

Neither diagnostic re-runs the full 90-cell grid; each trains one or two RFs.

USAGE
-----
    python3 diagnose_separability.py \
        --train /mnt/nids-captures/release/tls13_h3_ids_2026_train.csv \
        --test  /mnt/nids-captures/release/tls13_h3_ids_2026_test.csv \
        --label-col label --benign-label BENIGN

OUTPUT
------
Console: top-20 feature importances + volume-only F1. Also writes
diagnose_separability.json next to the test CSV's directory.
================================================================================
"""

import argparse
import json
import os

import numpy as np
import pandas as pd


# Columns excluded from any model (identifiers + the label). Mirrors the SII /
# SNI / protocol / fingerprint / window groups used by the binary baseline,
# so this diagnostic runs on the same "clean" feature space (CTD regime).
EXCLUDE = {
    "label",
    "dst_port_class",           # SII (port-derived)
    "sni_present",              # SNI presence
    "transport",                # protocol
    "ja3", "ja3s",              # fingerprints
    "fwd_init_window_size", "bwd_init_window_size",   # TCP window (OS-correlated)
    "fwd_last_window_size", "bwd_last_window_size",
}

# OS-agnostic behaviour-intrinsic features for the volume-only probe. These
# describe HOW MUCH and HOW FAST traffic flows -- properties of the attack
# behaviour (flooding, scanning) rather than of the host's TCP stack.
VOLUME_ONLY = [
    "flow_duration", "flow_pkts_s", "flow_bytes_s",
    "tot_fwd_pkts", "tot_bwd_pkts",
    "totlen_fwd_bytes", "totlen_bwd_bytes",
    "down_up_ratio",
]


def to_binary(y, benign):
    """BENIGN -> 0, everything else -> 1 (ATTACK)."""
    b = str(benign).strip().casefold()
    return (y.astype(str).str.strip().str.casefold() != b).astype(int).to_numpy()


def fit_numeric_encoder(df, cols):
    """Fit a DETERMINISTIC encoding for `cols` on the TRAINING frame only.

    Numeric columns pass through as-is. Categorical (string) columns are
    one-hot encoded with a category vocabulary learned HERE (train only), so the
    transform is reproducible run-to-run and unseen test categories map to
    all-zeros. This mirrors baseline_experiments_binary.py and deliberately
    avoids Python's per-process-randomized hash() (PYTHONHASHSEED), which made an
    earlier version of this script non-deterministic for categorical features.
    """
    from sklearn.preprocessing import OneHotEncoder
    numeric_cols = [c for c in cols if pd.api.types.is_numeric_dtype(df[c])]
    categorical_cols = [c for c in cols if c not in numeric_cols]
    encoder = None
    if categorical_cols:
        encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
        encoder.fit(df[categorical_cols].astype(str).fillna(""))
    # Feature names in output order: numeric columns first, then one-hot columns.
    feature_names = list(numeric_cols)
    if encoder is not None:
        feature_names += list(encoder.get_feature_names_out(categorical_cols))
    return {"numeric": numeric_cols, "categorical": categorical_cols,
            "encoder": encoder, "feature_names": feature_names}


def apply_numeric_encoder(df, enc):
    """Transform `df` with an encoder from fit_numeric_encoder (train-fitted)."""
    blocks = []
    if enc["numeric"]:
        blocks.append(
            df[enc["numeric"]].apply(pd.to_numeric, errors="coerce")
                              .fillna(0.0).to_numpy())
    if enc["encoder"] is not None:
        blocks.append(
            enc["encoder"].transform(df[enc["categorical"]].astype(str).fillna("")))
    return np.column_stack(blocks) if blocks else np.empty((len(df), 0))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--label-col", default="label")
    ap.add_argument("--benign-label", default="BENIGN")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import f1_score, classification_report

    tr = pd.read_csv(args.train)
    te = pd.read_csv(args.test)
    ytr = to_binary(tr[args.label_col], args.benign_label)
    yte = to_binary(te[args.label_col], args.benign_label)

    # ---- Diagnostic 1: feature importance on the clean (CTD-like) space ------
    clean_cols = [c for c in tr.columns if c not in EXCLUDE]
    print(f"[1] Feature importance on {len(clean_cols)} clean features "
          f"(identifiers + TCP-window excluded)")
    enc = fit_numeric_encoder(tr, clean_cols)      # fit on TRAIN only
    Xtr = apply_numeric_encoder(tr, enc)
    Xte = apply_numeric_encoder(te, enc)
    rf = RandomForestClassifier(n_estimators=300, n_jobs=-1,
                                class_weight="balanced", random_state=args.seed)
    rf.fit(Xtr, ytr)
    f1_clean = f1_score(yte, rf.predict(Xte))
    # Importances are per OUTPUT column (one-hot expands a categorical into
    # several); use the encoder's feature names so the mapping is correct.
    imp = sorted(zip(enc["feature_names"], rf.feature_importances_),
                 key=lambda x: -x[1])
    print(f"    clean-regime test F1 = {f1_clean:.4f}")
    print("    top 20 features by importance:")
    for feat, val in imp[:20]:
        print(f"      {val:.4f}  {feat}")

    # ---- Diagnostic 2: volume-only probe -------------------------------------
    vol_cols = [c for c in VOLUME_ONLY if c in tr.columns]
    print(f"\n[2] Volume-only probe using {len(vol_cols)} OS-agnostic "
          f"rate/volume features: {vol_cols}")
    enc_v = fit_numeric_encoder(tr, vol_cols)      # all numeric here, but keep it uniform
    Xtr_v = apply_numeric_encoder(tr, enc_v)
    Xte_v = apply_numeric_encoder(te, enc_v)
    rf_v = RandomForestClassifier(n_estimators=300, n_jobs=-1,
                                  class_weight="balanced", random_state=args.seed)
    rf_v.fit(Xtr_v, ytr)
    f1_vol = f1_score(yte, rf_v.predict(Xte_v))
    print(f"    volume-only test F1 = {f1_vol:.4f}")
    print(classification_report(yte, rf_v.predict(Xte_v),
                                target_names=["BENIGN", "ATTACK"], zero_division=0))

    # ---- interpretation hint -------------------------------------------------
    print("=" * 72)
    print(" INTERPRETATION")
    print("=" * 72)
    if f1_vol >= 0.95:
        print("  Volume-only F1 is high => separation is behavioural (Reading A):")
        print("  attacks differ from benign in rate/volume, independent of OS stack.")
    else:
        print("  Volume-only F1 dropped => the near-perfect score leaned on")
        print("  platform-correlated features (Reading B). Report the OS-stack")
        print("  confound (benign=Windows/NB2, attack=Linux/NB3) as a limitation.")
    print("  Cross-check the top-20 list above: rate/volume names support (A);")
    print("  window/header/TTL-like names support (B).")

    out = {
        "clean_regime_f1": float(f1_clean),
        "clean_features_n": len(clean_cols),
        "top_importances": [(f, float(v)) for f, v in imp[:30]],
        "volume_only_f1": float(f1_vol),
        "volume_only_features": vol_cols,
    }
    dst = os.path.join(os.path.dirname(os.path.abspath(args.test)),
                       "diagnose_separability.json")
    with open(dst, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\n[i] written {dst}")


if __name__ == "__main__":
    main()
