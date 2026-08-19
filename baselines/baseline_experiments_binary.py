#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
baseline_experiments_corrected.py
Binary ATTACK-vs-BENIGN baselines and SII/SNI occlusion study for TLS13-H3-IDS-2026
================================================================================

PURPOSE
-------
Run reproducible train/validation/test baseline experiments on the official dataset
splits while explicitly measuring the effect of Strong Identification Information
(SII) and SNI-related shortcuts.

The primary regimes adapt the occlusion logic from:
    Wickramasinghe et al., "SoK: Decoding the Enigma of Encrypted Network Traffic
    Classifiers", IEEE Symposium on Security and Privacy, 2025.

For a tabular flow-feature dataset, exclusion of a feature column is preferable to
randomizing raw packet bytes because it avoids injecting arbitrary synthetic values
into the feature space. Therefore, these regimes are an adaptation of the paper's
A1/D1/D2 logic rather than a byte-for-byte reproduction:

    A1_all_network
        All network-derived model features, including SII/SNI if present.
        Experimental bookkeeping identifiers are NEVER allowed into a model.

    D1_no_sii
        A1 minus Strong Identification Information:
        MAC addresses, IP addresses, source/destination protocol ports, and direct
        port-derived service identifiers.

    D2_no_sii_sni
        D1 minus SNI fields and SNI-presence indicators.

Optional paper-inspired regime:

    CTD_paper_clean
        D2 minus session-specific contextual/temporal header artifacts when such
        columns exist (IP ID/checksum, TCP seq/ack, TCP window-size / TCP option
        timestamp fields). Aggregate behavioural timing features such as flow IAT
        are NOT removed by this rule.

Optional dataset-specific sensitivity regimes:

    P_no_protocol
        D2 minus direct transport/protocol indicators. This is NOT called SII in
        the SoK; it is provided separately because protocol identity can become a
        shortcut in controlled NIDS datasets.

    F_no_fingerprints
        D2 minus JA3/JA3S/JA4-style fingerprints. Again, this is separate from SII.

MODELS
------
- Random Forest: classical sparse tabular baseline.
- MLP: preferred simple neural tabular baseline.
- 1-D CNN: optional architectural baseline. The CNN is intentionally simple, but
  note that feature order is a schema choice and not a natural spatial sequence.

METHODOLOGICAL GUARANTEES
-------------------------
1. Official train/validation/test files are never reshuffled across splits.
2. Preprocessing is FIT ON TRAIN ONLY and applied unchanged to validation/test.
3. Categorical features use deterministic OneHotEncoder; Python hash() is never used.
4. Unknown validation/test categories are safely ignored by the train-fitted encoder.
5. Unseen validation/test LABELS cause an immediate failure; they are never dropped.
6. Deep models use validation F1 for early stopping/model selection.
7. Test is evaluated only after model selection.
8. Experimental identifiers (run_id, flow_id, event_id, timestamps, campaign IDs,
   split markers, etc.) are excluded in every regime.
9. Metrics include F1, balanced accuracy, multiclass MCC, per-class metrics,
   confusion matrix, and one-vs-rest average precision when probabilities exist.
10. Input SHA-256 hashes, package versions, feature partitions, hyperparameters,
    seeds, and class counts are written to the output directory.

DEPENDENCIES
------------
Required:
    pip install pandas numpy scipy scikit-learn

Optional for MLP/CNN:
    pip install torch

EXAMPLE
-------
python3 baseline_experiments_corrected.py \
    --train /mnt/nids-captures/release/tls13_h3_ids_2026_train.csv \
    --val   /mnt/nids-captures/release/tls13_h3_ids_2026_val.csv \
    --test  /mnt/nids-captures/release/tls13_h3_ids_2026_test.csv \
    --label-col label \
    --models rf mlp cnn \
    --regimes A1 D1 D2 \
    --seeds 42 43 44 45 46 \
    --outdir /mnt/nids-captures/release/baselines_corrected

For the paper-inspired combined clean regime:
    add --include-ctd

For dataset-specific protocol/fingerprint sensitivity analyses:
    add --include-protocol-ablation --include-fingerprint-ablation

================================================================================
"""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import math
import os
import platform
import random
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd

SCRIPT_VERSION = "2.2.0-binary"

# -----------------------------------------------------------------------------
# Feature-name policy
# -----------------------------------------------------------------------------
#
# The policy is deliberately fail-closed for experimental metadata: columns that
# identify a run, event, split, file, campaign, or timestamp are NEVER model inputs.
#
# SII follows the SoK's definition: MAC addresses, IP addresses, protocol ports.
# Direct port-derived service classes are conservatively grouped with SII because
# they encode essentially the same identifying information after feature engineering.
#

BOOKKEEPING_EXACT = {
    "run_id", "runid", "attempt_id", "attemptid", "campaign_id", "campaignid",
    "config_id", "configid", "scenario_id", "scenarioid", "event_id", "eventid",
    "annotation_id", "annotationid", "flow_id", "flowid", "uid",
    "split", "_split", "dataset_split", "fold", "pcap", "pcap_path", "file",
    "filename", "file_name", "source_file", "capture_file",
    "timestamp", "ts", "time", "start_utc", "end_utc", "start_ts", "end_ts",
    "attack", "attack_type", "attack_name", "event_label", "label_source",
    "ground_truth", "groundtruth", "orchestrator_version",
}

BOOKKEEPING_PATTERNS = (
    r"^(?:run|attempt|campaign|config|scenario|event|annotation|flow)[_-]?id$",
    r"^(?:pcap|capture|source)[_-]?(?:file|path|name)$",
    r"^(?:start|end)[_-]?(?:utc|ts|time|timestamp)$",
    r"^(?:absolute_)?timestamp$",
    r"^(?:split|fold|partition)$",
    r"^(?:attack|event)[_-]?(?:label|name|type)$",
)

SII_PATTERNS = (
    # MAC addresses.
    r"^(?:src|source|orig|dst|dest|destination|resp)[_-]?mac(?:_addr(?:ess)?)?$",
    r"^(?:eth|ether)[._-]?(?:src|dst)$",
    r"^mac[._-]?(?:src|dst)$",
    # IP addresses / endpoint addresses.
    r"^(?:src|source|orig|dst|dest|destination|resp)[_-]?(?:ip|ipaddr|ip_addr|address|addr)$",
    r"^id[._-]?(?:orig|resp)[._-]?h$",
    # Source/destination protocol ports.
    r"^(?:src|source|orig|dst|dest|destination|resp)[_-]?port$",
    r"^(?:sport|dport)$",
    r"^id[._-]?(?:orig|resp)[._-]?p$",
    # Conservative engineered derivatives of protocol ports.
    r"^(?:src|dst|source|destination)[_-]?port[_-]?(?:class|category|bucket)$",
    r"^(?:service|service_port|port_service|port_class)$",
)

SNI_PATTERNS = (
    r"^sni$",
    r"^sni[_-]?(?:value|name|host|hostname|present|presence)$",
    r"^(?:tls|ssl)[_-]?(?:sni|server_name|servername)$",
    r"^server[_-]?name(?:[_-]?indication)?$",
)

# Contextual artifacts described by the SoK. These are included only in the
# optional CTD_paper_clean regime.
CONTEXTUAL_ARTIFACT_PATTERNS = (
    r"^(?:ip|ipv4)[_-]?(?:id|identification)$",
    r"^(?:ip|ipv4)[_-]?(?:header[_-]?)?checksum$",
    r"^(?:tcp[_-]?)?(?:seq|sequence|sequence_number)$",
    r"^(?:tcp[_-]?)?(?:ack|acknowledgment|acknowledgement|ack_number)$",
)

TEMPORAL_ARTIFACT_PATTERNS = (
    r"^(?:tcp[_-]?)?(?:tsval|tsecr|timestamp_option|option_timestamp)$",
    r"^(?:fwd|bwd|forward|backward)?[_-]?(?:init|initial|last)?[_-]?window(?:_size)?$",
    r"^(?:tcp[_-]?)?window(?:_size)?$",
)

PROTOCOL_PATTERNS = (
    r"^(?:transport|protocol|proto|l4_protocol|l4_proto)$",
    r"^(?:is_)?(?:tcp|udp|quic)$",
)

FINGERPRINT_PATTERNS = (
    r"^ja3$",
    r"^ja3s$",
    r"^ja4$",
    r"^ja4s$",
    r"^(?:tls|ssl)[_-]?(?:fingerprint|client_fingerprint|server_fingerprint)$",
)


def normalize_name(name: str) -> str:
    """Normalize a column name for policy matching."""
    return re.sub(r"[^a-z0-9]+", "_", str(name).strip().lower()).strip("_")


def matches_any(name: str, patterns: Sequence[str]) -> bool:
    """Return True when a normalized name matches any anchored policy regex."""
    n = normalize_name(name)
    return any(re.fullmatch(pattern, n, flags=re.IGNORECASE) for pattern in patterns)


def is_bookkeeping(name: str, label_col: str) -> bool:
    """Return True for columns that must never enter any model."""
    n = normalize_name(name)
    if n == normalize_name(label_col):
        return True
    if n in BOOKKEEPING_EXACT:
        return True
    return matches_any(n, BOOKKEEPING_PATTERNS)


def classify_feature_groups(columns: Sequence[str], label_col: str) -> Dict[str, List[str]]:
    """Classify columns into auditable paper-aligned groups."""
    groups = {
        "bookkeeping": [],
        "sii": [],
        "sni": [],
        "contextual_artifacts": [],
        "temporal_artifacts": [],
        "protocol": [],
        "fingerprints": [],
        "other_network_features": [],
    }

    for col in columns:
        if is_bookkeeping(col, label_col):
            groups["bookkeeping"].append(col)
        elif matches_any(col, SII_PATTERNS):
            groups["sii"].append(col)
        elif matches_any(col, SNI_PATTERNS):
            groups["sni"].append(col)
        elif matches_any(col, CONTEXTUAL_ARTIFACT_PATTERNS):
            groups["contextual_artifacts"].append(col)
        elif matches_any(col, TEMPORAL_ARTIFACT_PATTERNS):
            groups["temporal_artifacts"].append(col)
        elif matches_any(col, PROTOCOL_PATTERNS):
            groups["protocol"].append(col)
        elif matches_any(col, FINGERPRINT_PATTERNS):
            groups["fingerprints"].append(col)
        else:
            groups["other_network_features"].append(col)

    return groups


def build_regimes(
    columns: Sequence[str],
    label_col: str,
    requested: Sequence[str],
    include_ctd: bool,
    include_protocol_ablation: bool,
    include_fingerprint_ablation: bool,
) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
    """Build A1/D1/D2 and optional sensitivity feature regimes."""
    groups = classify_feature_groups(columns, label_col)

    all_network = [c for c in columns if c not in groups["bookkeeping"]]
    d1 = [c for c in all_network if c not in groups["sii"]]
    d2 = [c for c in d1 if c not in groups["sni"]]

    regimes: Dict[str, List[str]] = {
        "A1_all_network": all_network,
        "D1_no_sii": d1,
        "D2_no_sii_sni": d2,
    }

    if include_ctd:
        removable = set(
            groups["contextual_artifacts"]
            + groups["temporal_artifacts"]
        )
        regimes["CTD_paper_clean"] = [c for c in d2 if c not in removable]

    if include_protocol_ablation:
        removable = set(groups["protocol"])
        regimes["P_no_protocol"] = [c for c in d2 if c not in removable]

    if include_fingerprint_ablation:
        removable = set(groups["fingerprints"])
        regimes["F_no_fingerprints"] = [c for c in d2 if c not in removable]

    alias = {
        "A1": "A1_all_network",
        "D1": "D1_no_sii",
        "D2": "D2_no_sii_sni",
        "CTD": "CTD_paper_clean",
        "P": "P_no_protocol",
        "F": "F_no_fingerprints",
    }

    if requested:
        selected: Dict[str, List[str]] = {}
        for item in requested:
            key = alias.get(item, item)
            if key not in regimes:
                raise SystemExit(
                    f"ERROR: requested regime '{item}' is unavailable. "
                    f"Available regimes: {list(regimes)}"
                )
            selected[key] = regimes[key]
        regimes = selected

    for name, features in regimes.items():
        if not features:
            raise SystemExit(f"ERROR: regime '{name}' contains no model features.")

    return regimes, groups


# -----------------------------------------------------------------------------
# Reproducibility / provenance helpers
# -----------------------------------------------------------------------------

def sha256_file(path: str, chunk_size: int = 8 * 1024 * 1024) -> str:
    """Compute SHA-256 without loading the full file into RAM."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def package_versions() -> Dict[str, Optional[str]]:
    """Collect relevant package/runtime versions."""
    versions: Dict[str, Optional[str]] = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "numpy": np.__version__,
        "pandas": pd.__version__,
    }
    try:
        import sklearn
        versions["scikit_learn"] = sklearn.__version__
    except Exception:
        versions["scikit_learn"] = None
    try:
        import scipy
        versions["scipy"] = scipy.__version__
    except Exception:
        versions["scipy"] = None
    try:
        import torch
        versions["torch"] = torch.__version__
        versions["cuda_available"] = str(torch.cuda.is_available())
        versions["cuda_version"] = getattr(torch.version, "cuda", None)
    except Exception:
        versions["torch"] = None
        versions["cuda_available"] = None
        versions["cuda_version"] = None
    return versions


def set_global_seed(seed: int) -> None:
    """Set deterministic seeds for Python, NumPy, and PyTorch when available."""
    random.seed(seed)
    np.random.seed(seed)
    try:
        import torch
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
        try:
            torch.use_deterministic_algorithms(True, warn_only=True)
        except Exception:
            pass
        if hasattr(torch.backends, "cudnn"):
            torch.backends.cudnn.deterministic = True
            torch.backends.cudnn.benchmark = False
    except ImportError:
        pass


# -----------------------------------------------------------------------------
# Split/schema validation and label encoding
# -----------------------------------------------------------------------------

def validate_dataframe_schema(
    train: pd.DataFrame,
    val: pd.DataFrame,
    test: pd.DataFrame,
    label_col: str,
) -> None:
    """Fail early on schema conditions that would invalidate the experiment."""
    for split_name, df in (("train", train), ("val", val), ("test", test)):
        if label_col not in df.columns:
            raise SystemExit(
                f"ERROR: label column '{label_col}' missing from {split_name}. "
                f"Columns begin with: {list(df.columns)[:20]}"
            )
        if df.columns.duplicated().any():
            dup = df.columns[df.columns.duplicated()].tolist()
            raise SystemExit(f"ERROR: duplicate columns in {split_name}: {dup}")
        if len(df) == 0:
            raise SystemExit(f"ERROR: {split_name} split is empty.")

    train_columns = set(train.columns)
    for split_name, df in (("val", val), ("test", test)):
        missing = sorted(train_columns - set(df.columns))
        if missing:
            raise SystemExit(
                f"ERROR: {split_name} is missing columns present in train: {missing}"
            )


def encode_labels_strict(
    train_labels: pd.Series,
    val_labels: pd.Series,
    test_labels: pd.Series,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[str]]:
    """Encode labels from train and abort if val/test contains an unseen class."""
    classes = sorted(str(x) for x in pd.unique(train_labels.astype(str)))
    mapping = {label: idx for idx, label in enumerate(classes)}

    def encode(series: pd.Series, split_name: str) -> np.ndarray:
        values = series.astype(str).tolist()
        unseen = sorted(set(values) - set(mapping))
        if unseen:
            raise SystemExit(
                f"ERROR: {split_name} contains labels unseen in train: {unseen}. "
                "This is not silently dropped because it changes the evaluation task."
            )
        return np.asarray([mapping[v] for v in values], dtype=np.int64)

    return (
        encode(train_labels, "train"),
        encode(val_labels, "validation"),
        encode(test_labels, "test"),
        classes,
    )


def class_counts(labels: Sequence[str]) -> Dict[str, int]:
    return dict(Counter(str(x) for x in labels))


def encode_binary_attack_labels(
    train_labels: pd.Series,
    val_labels: pd.Series,
    test_labels: pd.Series,
    benign_label: str,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[str], Dict[str, Any]]:
    """Collapse the original multiclass labels into BENIGN=0 and ATTACK=1.

    The mapping is intentionally simple and auditable:
      - labels exactly matching --benign-label (case-insensitive) -> BENIGN (0)
      - every other original class -> ATTACK (1)

    This is appropriate when the scientific task is binary intrusion detection.
    Original attack-family labels remain recorded in the manifest for provenance.
    """
    benign_norm = str(benign_label).strip().casefold()

    def encode(series: pd.Series, split_name: str):
        raw = series.astype(str)
        normalized = raw.str.strip().str.casefold()
        y = (normalized != benign_norm).astype(np.int64).to_numpy()
        original = sorted(raw.unique().tolist())
        binary_counts = {
            "BENIGN": int(np.sum(y == 0)),
            "ATTACK": int(np.sum(y == 1)),
        }
        if binary_counts["BENIGN"] == 0 or binary_counts["ATTACK"] == 0:
            raise SystemExit(
                f"ERROR: binary {split_name} split must contain both BENIGN and ATTACK. "
                f"Observed counts: {binary_counts}; benign label='{benign_label}'."
            )
        return y, original, binary_counts

    y_train, train_original, train_counts = encode(train_labels, "train")
    y_val, val_original, val_counts = encode(val_labels, "validation")
    y_test, test_original, test_counts = encode(test_labels, "test")

    metadata = {
        "benign_label_raw": benign_label,
        "positive_class": "ATTACK",
        "negative_class": "BENIGN",
        "original_classes": {
            "train": train_original,
            "validation": val_original,
            "test": test_original,
        },
        "binary_counts": {
            "train": train_counts,
            "validation": val_counts,
            "test": test_counts,
        },
    }
    return y_train, y_val, y_test, ["BENIGN", "ATTACK"], metadata


# -----------------------------------------------------------------------------
# Train-fitted preprocessing
# -----------------------------------------------------------------------------

@dataclass
class PreparedRegime:
    name: str
    features: List[str]
    numeric_features: List[str]
    categorical_features: List[str]
    preprocessor: Any
    X_train: Any
    X_val: Any
    X_test: Any
    feature_count_after_encoding: int


def make_onehot_encoder():
    """Create a version-compatible deterministic OneHotEncoder."""
    from sklearn.preprocessing import OneHotEncoder
    try:
        return OneHotEncoder(
            handle_unknown="ignore",
            sparse_output=True,
            dtype=np.float32,
        )
    except TypeError:
        # Compatibility with scikit-learn < 1.2.
        return OneHotEncoder(
            handle_unknown="ignore",
            sparse=True,
            dtype=np.float32,
        )


def prepare_regime(
    name: str,
    features: List[str],
    train: pd.DataFrame,
    val: pd.DataFrame,
    test: pd.DataFrame,
) -> PreparedRegime:
    """Fit all preprocessing on TRAIN only and transform val/test unchanged."""
    from sklearn.compose import ColumnTransformer
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    for split_name, df in (("train", train), ("val", val), ("test", test)):
        missing = [c for c in features if c not in df.columns]
        if missing:
            raise SystemExit(
                f"ERROR: regime '{name}' requires columns missing from {split_name}: {missing}"
            )

    # Data type is determined from TRAIN only. Validation/test never re-infer how
    # a feature should be encoded.
    numeric = [c for c in features if pd.api.types.is_numeric_dtype(train[c])]
    categorical = [c for c in features if c not in numeric]

    transformers = []
    if numeric:
        numeric_pipe = Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
            ]
        )
        transformers.append(("numeric", numeric_pipe, numeric))

    if categorical:
        categorical_pipe = Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="constant", fill_value="__MISSING__")),
                ("onehot", make_onehot_encoder()),
            ]
        )
        transformers.append(("categorical", categorical_pipe, categorical))

    if not transformers:
        raise SystemExit(f"ERROR: no usable features in regime '{name}'.")

    preprocessor = ColumnTransformer(
        transformers=transformers,
        remainder="drop",
        sparse_threshold=1.0,
        verbose_feature_names_out=True,
    )

    X_train = preprocessor.fit_transform(train[features])
    X_val = preprocessor.transform(val[features])
    X_test = preprocessor.transform(test[features])

    # Force float32 to keep memory predictable.
    X_train = X_train.astype(np.float32, copy=False)
    X_val = X_val.astype(np.float32, copy=False)
    X_test = X_test.astype(np.float32, copy=False)

    n_out = int(X_train.shape[1])
    if n_out <= 0:
        raise SystemExit(f"ERROR: preprocessing produced zero features for '{name}'.")

    return PreparedRegime(
        name=name,
        features=list(features),
        numeric_features=numeric,
        categorical_features=categorical,
        preprocessor=preprocessor,
        X_train=X_train,
        X_val=X_val,
        X_test=X_test,
        feature_count_after_encoding=n_out,
    )


def dense_batch(X: Any, indices: np.ndarray) -> np.ndarray:
    """Convert only the requested batch to a dense float32 array."""
    batch = X[indices]
    if hasattr(batch, "toarray"):
        batch = batch.toarray()
    return np.asarray(batch, dtype=np.float32)


def transform_for_deep(
    prepared: PreparedRegime,
    max_features: int,
    random_state: int,
) -> Tuple[Any, Any, Any, Dict[str, Any]]:
    """Optionally reduce a very wide sparse matrix using train-fitted TruncatedSVD."""
    Xtr, Xva, Xte = prepared.X_train, prepared.X_val, prepared.X_test
    n_features = int(Xtr.shape[1])

    meta: Dict[str, Any] = {
        "input_features": n_features,
        "used_truncated_svd": False,
        "output_features": n_features,
    }

    if n_features <= max_features:
        return Xtr, Xva, Xte, meta

    from sklearn.decomposition import TruncatedSVD
    from sklearn.preprocessing import StandardScaler

    max_rank = max(2, min(int(Xtr.shape[0]) - 1, n_features - 1))
    n_components = max(2, min(int(max_features), max_rank))

    svd = TruncatedSVD(n_components=n_components, random_state=random_state)
    Xtr_d = svd.fit_transform(Xtr).astype(np.float32, copy=False)
    Xva_d = svd.transform(Xva).astype(np.float32, copy=False)
    Xte_d = svd.transform(Xte).astype(np.float32, copy=False)

    # Center/scale the SVD components using TRAIN statistics only.
    scaler = StandardScaler()
    Xtr_d = scaler.fit_transform(Xtr_d).astype(np.float32, copy=False)
    Xva_d = scaler.transform(Xva_d).astype(np.float32, copy=False)
    Xte_d = scaler.transform(Xte_d).astype(np.float32, copy=False)

    meta.update(
        {
            "used_truncated_svd": True,
            "output_features": int(n_components),
            "explained_variance_ratio_sum": float(
                np.sum(svd.explained_variance_ratio_)
            ),
        }
    )
    return Xtr_d, Xva_d, Xte_d, meta


# -----------------------------------------------------------------------------
# Metrics
# -----------------------------------------------------------------------------

def evaluate(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    classes: Sequence[str],
    probabilities: Optional[np.ndarray] = None,
) -> Dict[str, Any]:
    """Compute binary intrusion-detection metrics with ATTACK as positive class."""
    from sklearn.metrics import (
        accuracy_score,
        average_precision_score,
        balanced_accuracy_score,
        confusion_matrix,
        f1_score,
        matthews_corrcoef,
        precision_score,
        recall_score,
        roc_auc_score,
    )

    labels = np.asarray([0, 1], dtype=int)
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    tn, fp, fn, tp = (int(x) for x in cm.ravel())

    precision = float(precision_score(y_true, y_pred, pos_label=1, zero_division=0))
    recall = float(recall_score(y_true, y_pred, pos_label=1, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, pos_label=1, zero_division=0))
    specificity = float(tn / (tn + fp)) if (tn + fp) else 0.0
    fpr = float(fp / (fp + tn)) if (fp + tn) else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) else 0.0
    npv = float(tn / (tn + fn)) if (tn + fn) else 0.0

    result: Dict[str, Any] = {
        "positive_class": "ATTACK",
        "negative_class": "BENIGN",
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "precision": precision,
        "recall": recall,
        "sensitivity_tpr": recall,
        "specificity_tnr": specificity,
        "f1": f1,
        "mcc": float(matthews_corrcoef(y_true, y_pred)),
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "negative_predictive_value": npv,
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "support": {
            "BENIGN": int(np.sum(y_true == 0)),
            "ATTACK": int(np.sum(y_true == 1)),
        },
    }

    if probabilities is not None:
        probabilities = np.asarray(probabilities, dtype=float)
        if probabilities.ndim == 2 and probabilities.shape[1] >= 2:
            attack_score = probabilities[:, 1]
        elif probabilities.ndim == 1:
            attack_score = probabilities
        else:
            attack_score = None

        if attack_score is not None:
            if len(np.unique(y_true)) == 2:
                result["roc_auc"] = float(roc_auc_score(y_true, attack_score))
                result["pr_auc_average_precision"] = float(
                    average_precision_score(y_true, attack_score)
                )
            else:
                result["roc_auc"] = None
                result["pr_auc_average_precision"] = None

    return result

def print_metrics(tag: str, split_name: str, metrics: Dict[str, Any]) -> None:
    """Print binary ATTACK-vs-BENIGN metrics."""
    line = "=" * 88
    print(f"\n{line}\n{tag} | {split_name.upper()} | positive class=ATTACK\n{line}")
    print(f"  accuracy           : {metrics['accuracy']:.4f}")
    print(f"  balanced accuracy  : {metrics['balanced_accuracy']:.4f}")
    print(f"  precision (attack) : {metrics['precision']:.4f}")
    print(f"  recall / TPR       : {metrics['recall']:.4f}")
    print(f"  specificity / TNR  : {metrics['specificity_tnr']:.4f}")
    print(f"  F1 (attack)        : {metrics['f1']:.4f}")
    print(f"  MCC                : {metrics['mcc']:.4f}")
    if metrics.get("roc_auc") is not None:
        print(f"  ROC-AUC            : {metrics['roc_auc']:.4f}")
    if metrics.get("pr_auc_average_precision") is not None:
        print(f"  PR-AUC / AP        : {metrics['pr_auc_average_precision']:.4f}")
    print(
        f"  confusion [TN FP; FN TP] = {metrics['confusion_matrix']} "
        f"| support={metrics['support']}"
    )


# -----------------------------------------------------------------------------
# Random Forest
# -----------------------------------------------------------------------------

def run_random_forest(
    prepared: PreparedRegime,
    y_train: np.ndarray,
    y_val: np.ndarray,
    y_test: np.ndarray,
    classes: Sequence[str],
    seed: int,
    n_estimators: int,
) -> Dict[str, Any]:
    """Train a fixed Random Forest on train, then evaluate validation and test."""
    from sklearn.ensemble import RandomForestClassifier

    set_global_seed(seed)

    model = RandomForestClassifier(
        n_estimators=int(n_estimators),
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        class_weight="balanced",
        n_jobs=-1,
        random_state=int(seed),
    )

    t0 = time.perf_counter()
    model.fit(prepared.X_train, y_train)
    fit_seconds = time.perf_counter() - t0

    result: Dict[str, Any] = {
        "model": "RandomForestClassifier",
        "seed": int(seed),
        "hyperparameters": {
            "n_estimators": int(n_estimators),
            "max_depth": None,
            "class_weight": "balanced",
        },
        "fit_seconds": float(fit_seconds),
    }

    for split_name, X, y in (
        ("validation", prepared.X_val, y_val),
        ("test", prepared.X_test, y_test),
    ):
        t1 = time.perf_counter()
        pred = model.predict(X)
        proba = model.predict_proba(X)
        infer_seconds = time.perf_counter() - t1
        result[split_name] = evaluate(y, pred, classes, proba)
        result[split_name]["inference_seconds"] = float(infer_seconds)

    return result


# -----------------------------------------------------------------------------
# PyTorch deep baselines
# -----------------------------------------------------------------------------

def _torch_predict(
    model: Any,
    X: Any,
    batch_size: int,
    device: str,
) -> Tuple[np.ndarray, np.ndarray]:
    """Batch prediction to avoid loading the entire split onto the GPU."""
    import torch

    model.eval()
    preds: List[np.ndarray] = []
    probs: List[np.ndarray] = []

    n = int(X.shape[0])
    with torch.no_grad():
        for start in range(0, n, batch_size):
            stop = min(n, start + batch_size)
            idx = np.arange(start, stop)
            xb_np = dense_batch(X, idx)
            xb = torch.as_tensor(xb_np, dtype=torch.float32, device=device)
            logits = model(xb)
            p = torch.softmax(logits, dim=1)
            probs.append(p.cpu().numpy())
            preds.append(p.argmax(dim=1).cpu().numpy())

    return np.concatenate(preds), np.concatenate(probs)


def run_torch_model(
    model_kind: str,
    X_train: Any,
    y_train: np.ndarray,
    X_val: Any,
    y_val: np.ndarray,
    X_test: Any,
    y_test: np.ndarray,
    classes: Sequence[str],
    seed: int,
    epochs: int,
    patience: int,
    batch_size: int,
    learning_rate: float,
) -> Dict[str, Any]:
    """Train MLP/CNN with validation F1 early stopping and final test once."""
    try:
        import torch
        import torch.nn as nn
    except ImportError:
        return {"skipped": "torch is not installed"}

    set_global_seed(seed)

    n_classes = len(classes)
    n_features = int(X_train.shape[1])
    device = "cuda" if torch.cuda.is_available() else "cpu"

    class MLP(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(n_features, 256),
                nn.ReLU(),
                nn.Dropout(0.25),
                nn.Linear(256, 128),
                nn.ReLU(),
                nn.Dropout(0.25),
                nn.Linear(128, n_classes),
            )

        def forward(self, x):
            return self.net(x)

    class PlainCNN(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.features = nn.Sequential(
                nn.Conv1d(1, 32, kernel_size=3, padding=1),
                nn.ReLU(),
                nn.MaxPool1d(2),
                nn.Conv1d(32, 64, kernel_size=3, padding=1),
                nn.ReLU(),
                nn.AdaptiveMaxPool1d(4),
            )
            self.head = nn.Sequential(
                nn.Flatten(),
                nn.Linear(64 * 4, 128),
                nn.ReLU(),
                nn.Dropout(0.30),
                nn.Linear(128, n_classes),
            )

        def forward(self, x):
            x = x.unsqueeze(1)
            return self.head(self.features(x))

    if model_kind == "mlp":
        model = MLP().to(device)
    elif model_kind == "cnn":
        model = PlainCNN().to(device)
    else:
        raise ValueError(f"Unsupported torch model: {model_kind}")

    counts = np.bincount(y_train, minlength=n_classes).astype(np.float64)
    if np.any(counts == 0):
        missing = [classes[i] for i, c in enumerate(counts) if c == 0]
        raise SystemExit(f"ERROR: train split has zero samples for classes: {missing}")

    weights = counts.sum() / counts
    weights = weights / weights.mean()
    weight_tensor = torch.tensor(weights, dtype=torch.float32, device=device)

    criterion = nn.CrossEntropyLoss(weight=weight_tensor)
    optimizer = torch.optim.Adam(model.parameters(), lr=float(learning_rate))

    best_state = copy.deepcopy(model.state_dict())
    best_val_f1 = -math.inf
    best_epoch = 0
    no_improve = 0
    history: List[Dict[str, Any]] = []

    rng = np.random.default_rng(seed)
    n_train = len(y_train)

    t0 = time.perf_counter()

    for epoch in range(1, int(epochs) + 1):
        model.train()
        order = rng.permutation(n_train)
        loss_sum = 0.0

        for start in range(0, n_train, batch_size):
            idx = order[start : start + batch_size]
            xb_np = dense_batch(X_train, idx)
            xb = torch.as_tensor(xb_np, dtype=torch.float32, device=device)
            yb = torch.as_tensor(y_train[idx], dtype=torch.long, device=device)

            optimizer.zero_grad(set_to_none=True)
            logits = model(xb)
            loss = criterion(logits, yb)
            loss.backward()
            optimizer.step()
            loss_sum += float(loss.detach().cpu()) * len(idx)

        val_pred, val_prob = _torch_predict(model, X_val, batch_size, device)
        val_metrics = evaluate(y_val, val_pred, classes, val_prob)
        val_f1 = float(val_metrics["f1"])

        history.append(
            {
                "epoch": int(epoch),
                "train_loss": float(loss_sum / n_train),
                "validation_attack_f1": val_f1,
                "validation_balanced_accuracy": float(val_metrics["balanced_accuracy"]),
            }
        )

        print(
            f"    epoch {epoch:3d}/{epochs} "
            f"loss={loss_sum/n_train:.5f} val_attack_f1={val_f1:.5f}"
        )

        if val_f1 > best_val_f1 + 1e-8:
            best_val_f1 = val_f1
            best_epoch = epoch
            best_state = copy.deepcopy(model.state_dict())
            no_improve = 0
        else:
            no_improve += 1

        if no_improve >= int(patience):
            print(
                f"    early stopping at epoch {epoch}; "
                f"best epoch={best_epoch}, best val F1={best_val_f1:.5f}"
            )
            break

    fit_seconds = time.perf_counter() - t0

    # Restore the checkpoint selected exclusively on validation data.
    model.load_state_dict(best_state)

    result: Dict[str, Any] = {
        "model": "MLP" if model_kind == "mlp" else "Plain1DCNN",
        "seed": int(seed),
        "device": device,
        "fit_seconds": float(fit_seconds),
        "best_epoch": int(best_epoch),
        "best_validation_attack_f1": float(best_val_f1),
        "class_weights": {
            classes[i]: float(weights[i]) for i in range(n_classes)
        },
        "history": history,
        "hyperparameters": {
            "epochs_max": int(epochs),
            "patience": int(patience),
            "batch_size": int(batch_size),
            "learning_rate": float(learning_rate),
        },
    }

    for split_name, X, y in (
        ("validation", X_val, y_val),
        ("test", X_test, y_test),
    ):
        t1 = time.perf_counter()
        pred, prob = _torch_predict(model, X, batch_size, device)
        infer_seconds = time.perf_counter() - t1
        result[split_name] = evaluate(y, pred, classes, prob)
        result[split_name]["inference_seconds"] = float(infer_seconds)

    return result


# -----------------------------------------------------------------------------
# Aggregation / reporting
# -----------------------------------------------------------------------------

def summarize_seed_runs(seed_runs: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate binary test metrics across repeated seeds."""
    metrics = (
        "accuracy",
        "balanced_accuracy",
        "precision",
        "recall",
        "specificity_tnr",
        "f1",
        "mcc",
        "roc_auc",
        "pr_auc_average_precision",
    )

    out: Dict[str, Any] = {"n_runs": len(seed_runs), "test_metrics": {}}
    for metric in metrics:
        values = []
        for run in seed_runs:
            if "skipped" in run:
                continue
            value = (run.get("test") or {}).get(metric)
            if value is not None and math.isfinite(float(value)):
                values.append(float(value))
        if values:
            arr = np.asarray(values, dtype=float)
            out["test_metrics"][metric] = {
                "mean": float(arr.mean()),
                "std": float(arr.std(ddof=0)),
                "min": float(arr.min()),
                "max": float(arr.max()),
                "values": values,
            }
    return out


def write_summary_csv(results: Dict[str, Any], path: str) -> None:
    """Write one compact binary-metric row per model/regime/seed/split."""
    fields = [
        "model", "regime", "seed", "split",
        "accuracy", "balanced_accuracy", "precision", "recall",
        "specificity_tnr", "f1", "mcc", "roc_auc",
        "pr_auc_average_precision", "false_positive_rate", "false_negative_rate",
    ]
    rows: List[Dict[str, Any]] = []

    for model_name, by_regime in results["experiments"].items():
        for regime_name, seed_runs in by_regime.items():
            for run in seed_runs:
                if "skipped" in run:
                    continue
                for split in ("validation", "test"):
                    m = run.get(split) or {}
                    rows.append(
                        {
                            "model": model_name,
                            "regime": regime_name,
                            "seed": run.get("seed"),
                            "split": split,
                            "accuracy": m.get("accuracy"),
                            "balanced_accuracy": m.get("balanced_accuracy"),
                            "precision": m.get("precision"),
                            "recall": m.get("recall"),
                            "specificity_tnr": m.get("specificity_tnr"),
                            "f1": m.get("f1"),
                            "mcc": m.get("mcc"),
                            "roc_auc": m.get("roc_auc"),
                            "pr_auc_average_precision": m.get("pr_auc_average_precision"),
                            "false_positive_rate": m.get("false_positive_rate"),
                            "false_negative_rate": m.get("false_negative_rate"),
                        }
                    )

    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _latex_escape(text: str) -> str:
    """Escape a short label for use in ordinary LaTeX table cells."""
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(ch, ch) for ch in str(text))


def _mean_std_from_seed_runs(
    seed_runs: Sequence[Dict[str, Any]],
    metric: str,
    split: str = "test",
) -> Tuple[Optional[float], Optional[float], int]:
    """Return mean, population standard deviation, and count for a metric."""
    values: List[float] = []
    for run in seed_runs:
        if "skipped" in run:
            continue
        value = (run.get(split) or {}).get(metric)
        if value is None:
            continue
        value = float(value)
        if math.isfinite(value):
            values.append(value)
    if not values:
        return None, None, 0
    arr = np.asarray(values, dtype=float)
    return float(arr.mean()), float(arr.std(ddof=0)), int(arr.size)


def _latex_metric(
    seed_runs: Sequence[Dict[str, Any]],
    metric: str,
    split: str,
    decimals: int,
) -> str:
    """Format a metric as mean +/- std when repeated seeds are available."""
    mean, std, n = _mean_std_from_seed_runs(seed_runs, metric, split)
    if mean is None:
        return "--"
    if n <= 1:
        return f"{mean:.{decimals}f}"
    return (
        f"${mean:.{decimals}f}"
        rf"\,\pm\,"
        f"{std:.{decimals}f}$"
    )


def write_latex_sii_benchmark(
    results: Dict[str, Any],
    path: str,
    split: str = "test",
    decimals: int = 3,
) -> bool:
    """Write the main binary A1-vs-D1 LaTeX benchmark table."""
    experiments = results.get("experiments") or {}
    model_labels = {
        "rf": "Random Forest",
        "mlp": "MLP",
        "cnn": "1-D CNN",
    }
    rows: List[str] = []
    max_seed_count = 0

    for model_name, by_regime in experiments.items():
        for regime_name, sii_label in (
            ("A1_all_network", "Included (A1)"),
            ("D1_no_sii", "Removed (D1)"),
        ):
            seed_runs = (by_regime or {}).get(regime_name) or []
            valid_runs = [r for r in seed_runs if "skipped" not in r]
            if not valid_runs:
                continue
            max_seed_count = max(max_seed_count, len(valid_runs))

            metrics = [
                _latex_metric(seed_runs, "accuracy", split, decimals),
                _latex_metric(seed_runs, "precision", split, decimals),
                _latex_metric(seed_runs, "recall", split, decimals),
                _latex_metric(seed_runs, "f1", split, decimals),
                _latex_metric(seed_runs, "mcc", split, decimals),
                _latex_metric(seed_runs, "pr_auc_average_precision", split, decimals),
            ]
            model_label = _latex_escape(model_labels.get(model_name, model_name))
            sii_cell = _latex_escape(sii_label)
            rows.append(
                f"{model_label} & {sii_cell} & "
                + " & ".join(metrics)
                + r" \\"
            )

    if not rows:
        return False

    if max_seed_count > 1:
        value_note = (
            f"Values are mean $\\pm$ standard deviation across "
            f"{max_seed_count} random seeds."
        )
    else:
        value_note = "A single random seed was used."

    lines = [
        r"\begin{table*}[t]",
        r"\centering",
        (
            r"\caption{Binary attack-detection performance on the held-out test split "
            r"with and without Strong Identification Information (SII). "
            r"ATTACK is the positive class; BENIGN is the negative class. "
            + value_note
            + r"}"
        ),
        r"\label{tab:benchmark_sii_binary}",
        r"\small",
        r"\setlength{\tabcolsep}{4.0pt}",
        r"\begin{tabular}{@{}llcccccc@{}}",
        r"\toprule",
        (
            r"\textbf{Model} & \textbf{SII} & \textbf{Accuracy} & "
            r"\textbf{Precision} & \textbf{Recall} & "
            r"\textbf{$F_1$} & \textbf{MCC} & \textbf{PR-AUC} \\"
        ),
        r"\midrule",
    ]

    previous_model = None
    for row in rows:
        current_model = row.split(" & ", 1)[0]
        if previous_model is not None and current_model != previous_model:
            lines.append(r"\addlinespace[2pt]")
        lines.append(row)
        previous_model = current_model

    lines.extend(
        [
            r"\bottomrule",
            r"\end{tabular}",
            r"\end{table*}",
            "",
            r"% Requires \usepackage{booktabs}.",
            r"% Precision, Recall and F1 use ATTACK as the positive class.",
            (
                r"% A1 retains SII; D1 removes MAC addresses, IP addresses, "
                r"and protocol ports (plus direct port-derived identifiers)."
            ),
        ]
    )

    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return True

def write_latex_sii_effect(
    results: Dict[str, Any],
    path: str,
    split: str = "test",
    decimals: int = 3,
) -> bool:
    """Write a compact table quantifying the A1-D1 SII performance difference."""
    experiments = results.get("experiments") or {}
    model_labels = {
        "rf": "Random Forest",
        "mlp": "MLP",
        "cnn": "1-D CNN",
    }
    rows: List[str] = []

    for model_name, by_regime in experiments.items():
        a1_runs = (by_regime or {}).get("A1_all_network") or []
        d1_runs = (by_regime or {}).get("D1_no_sii") or []
        if not a1_runs or not d1_runs:
            continue

        def paired_delta(metric: str) -> Tuple[Optional[float], Optional[float], int]:
            a1_by_seed = {
                int(r["seed"]): float((r.get(split) or {}).get(metric))
                for r in a1_runs
                if "skipped" not in r
                and (r.get(split) or {}).get(metric) is not None
            }
            d1_by_seed = {
                int(r["seed"]): float((r.get(split) or {}).get(metric))
                for r in d1_runs
                if "skipped" not in r
                and (r.get(split) or {}).get(metric) is not None
            }
            common = sorted(set(a1_by_seed) & set(d1_by_seed))
            values = [a1_by_seed[s] - d1_by_seed[s] for s in common]
            if not values:
                return None, None, 0
            arr = np.asarray(values, dtype=float)
            return float(arr.mean()), float(arr.std(ddof=0)), len(values)

        delta_f1, delta_f1_std, n_f1 = paired_delta("f1")
        delta_mcc, delta_mcc_std, n_mcc = paired_delta("mcc")
        if delta_f1 is None or delta_mcc is None:
            continue

        def fmt(mean: float, std: float, n: int) -> str:
            if n <= 1:
                return f"{mean:+.{decimals}f}"
            return (
                f"${mean:+.{decimals}f}"
                rf"\,\pm\,"
                f"{std:.{decimals}f}$"
            )

        rows.append(
            f"{_latex_escape(model_labels.get(model_name, model_name))} & "
            f"{fmt(delta_f1, delta_f1_std or 0.0, n_f1)} & "
            f"{fmt(delta_mcc, delta_mcc_std or 0.0, n_mcc)} "
            r"\\"
        )

    if not rows:
        return False

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        (
            r"\caption{Effect of Strong Identification Information (SII) on the "
            r"held-out test split. Positive values indicate higher performance "
            r"when SII is available (A1) than after SII removal (D1).}"
        ),
        r"\label{tab:sii_effect}",
        r"\small",
        r"\begin{tabular}{@{}lcc@{}}",
        r"\toprule",
        r"\textbf{Model} & $\Delta$ \textbf{$F_1$} & $\Delta$ \textbf{MCC} \\",
        r"\midrule",
        *rows,
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
        "",
        r"% Requires \usepackage{booktabs}.",
    ]
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return True


def print_ablation_summary(results: Dict[str, Any]) -> None:
    """Print paper-aligned A1->D1 and D1->D2 F1 differences."""
    print("\n" + "#" * 96)
    print(" PAPER-ALIGNED OCCLUSION SUMMARY — TEST F1")
    print("#" * 96)

    for model_name, by_regime in results["aggregates"].items():
        a1 = (((by_regime.get("A1_all_network") or {}).get("test_metrics") or {}).get("f1") or {}).get("mean")
        d1 = (((by_regime.get("D1_no_sii") or {}).get("test_metrics") or {}).get("f1") or {}).get("mean")
        d2 = (((by_regime.get("D2_no_sii_sni") or {}).get("test_metrics") or {}).get("f1") or {}).get("mean")

        print(f"\n{model_name.upper()}")
        if a1 is not None:
            print(f"  A1 all network features       : {a1:.4f}")
        if d1 is not None:
            print(f"  D1 without SII                : {d1:.4f}")
        if d2 is not None:
            print(f"  D2 without SII + SNI          : {d2:.4f}")
        if a1 is not None and d1 is not None:
            print(f"  SII contribution (A1 - D1)   : {a1 - d1:+.4f}")
        if d1 is not None and d2 is not None:
            print(f"  SNI contribution (D1 - D2)   : {d1 - d2:+.4f}")

    print(
        "\nInterpretation: a positive A1-D1 gap quantifies performance attributable "
        "to SII availability. It does NOT prove that the dataset 'does not reward' "
        "identifiers; it measures how much a classifier can exploit them."
    )


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=(
            "Binary ATTACK-vs-BENIGN A1/D1/D2 SII/SNI experiments for a tabular "
            "encrypted-traffic NIDS dataset."
        )
    )
    ap.add_argument("--train", required=True, help="Official training CSV")
    ap.add_argument("--val", required=True, help="Official validation CSV")
    ap.add_argument("--test", required=True, help="Official test CSV")
    ap.add_argument("--label-col", default="label")
    ap.add_argument("--benign-label", default="BENIGN", help="Original label treated as the negative class; all other labels become ATTACK")
    ap.add_argument(
        "--models",
        nargs="+",
        default=["rf", "mlp", "cnn"],
        choices=["rf", "mlp", "cnn"],
    )
    ap.add_argument(
        "--regimes",
        nargs="+",
        default=["A1", "D1", "D2"],
        help="Any of A1 D1 D2 CTD P F or their full regime names",
    )
    ap.add_argument("--include-ctd", action="store_true")
    ap.add_argument("--include-protocol-ablation", action="store_true")
    ap.add_argument("--include-fingerprint-ablation", action="store_true")
    ap.add_argument(
        "--require-sii",
        action="store_true",
        help="Abort if no SII column is detected in the training schema",
    )

    ap.add_argument("--seeds", nargs="+", type=int, default=[42])
    ap.add_argument("--rf-trees", type=int, default=300)
    ap.add_argument("--epochs", type=int, default=50)
    ap.add_argument("--patience", type=int, default=7)
    ap.add_argument("--batch-size", type=int, default=512)
    ap.add_argument("--learning-rate", type=float, default=1e-3)
    ap.add_argument(
        "--deep-max-features",
        type=int,
        default=512,
        help=(
            "If one-hot output is wider than this, deep models use train-fitted "
            "TruncatedSVD to this dimensionality."
        ),
    )
    ap.add_argument(
        "--preprocess-seed",
        type=int,
        default=42,
        help="Seed for train-fitted TruncatedSVD preprocessing",
    )
    ap.add_argument(
        "--latex-decimals",
        type=int,
        default=3,
        help="Decimal places used in generated LaTeX tables",
    )
    ap.add_argument(
        "--no-latex",
        action="store_true",
        help="Disable automatic LaTeX table generation",
    )
    ap.add_argument("--outdir", default="baselines_corrected")
    return ap


def main() -> None:
    args = build_arg_parser().parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    print("=" * 100)
    print("BINARY ATTACK-vs-BENIGN BASELINE / SII-SNI OCCLUSION EXPERIMENTS")
    print("=" * 100)
    print(f"Script version : {SCRIPT_VERSION}")
    print(f"Train          : {args.train}")
    print(f"Validation     : {args.val}")
    print(f"Test           : {args.test}")
    print(f"Models         : {args.models}")
    print(f"Seeds          : {args.seeds}")

    print("\n[1/7] Loading official splits...")
    train = pd.read_csv(args.train, low_memory=False)
    val = pd.read_csv(args.val, low_memory=False)
    test = pd.read_csv(args.test, low_memory=False)
    print(f"      train={len(train):,} val={len(val):,} test={len(test):,}")

    print("[2/7] Validating schema and labels...")
    validate_dataframe_schema(train, val, test, args.label_col)

    y_train, y_val, y_test, classes, binary_label_meta = encode_binary_attack_labels(
        train[args.label_col],
        val[args.label_col],
        test[args.label_col],
        benign_label=args.benign_label,
    )
    print(f"      binary classes={classes} (positive=ATTACK)")
    print(f"      binary counts={binary_label_meta['binary_counts']}")

    print("[3/7] Building paper-aligned feature regimes...")
    regimes, groups = build_regimes(
        train.columns.tolist(),
        args.label_col,
        args.regimes,
        args.include_ctd,
        args.include_protocol_ablation,
        args.include_fingerprint_ablation,
    )

    if args.require_sii and not groups["sii"]:
        raise SystemExit(
            "ERROR: --require-sii was requested but no SII column was detected. "
            "A1-vs-D1 cannot measure SII impact on this release schema."
        )

    if not groups["sii"]:
        print(
            "      [WARN] No direct SII column was detected. A1 and D1 may be "
            "identical; this means the release may already have removed SII."
        )

    for group_name, cols in groups.items():
        print(f"      {group_name:24s} ({len(cols):3d}): {cols}")

    for regime_name, cols in regimes.items():
        print(f"      regime {regime_name:20s}: {len(cols)} raw columns")

    provenance = {
        "script_version": SCRIPT_VERSION,
        "created_utc": pd.Timestamp.utcnow().isoformat(),
        "inputs": {
            "train": {
                "path": str(Path(args.train).resolve()),
                "sha256": sha256_file(args.train),
                "rows": int(len(train)),
                "columns": int(len(train.columns)),
                "original_class_counts": class_counts(train[args.label_col].astype(str)),
                "binary_class_counts": binary_label_meta["binary_counts"]["train"],
            },
            "validation": {
                "path": str(Path(args.val).resolve()),
                "sha256": sha256_file(args.val),
                "rows": int(len(val)),
                "columns": int(len(val.columns)),
                "original_class_counts": class_counts(val[args.label_col].astype(str)),
                "binary_class_counts": binary_label_meta["binary_counts"]["validation"],
            },
            "test": {
                "path": str(Path(args.test).resolve()),
                "sha256": sha256_file(args.test),
                "rows": int(len(test)),
                "columns": int(len(test.columns)),
                "original_class_counts": class_counts(test[args.label_col].astype(str)),
                "binary_class_counts": binary_label_meta["binary_counts"]["test"],
            },
        },
        "environment": package_versions(),
        "label_column": args.label_col,
        "classes": classes,
        "binary_label_mapping": binary_label_meta,
        "feature_groups": groups,
        "regimes": regimes,
        "arguments": vars(args),
    }

    with open(outdir / "experiment_manifest.json", "w", encoding="utf-8") as fh:
        json.dump(provenance, fh, indent=2, ensure_ascii=False)

    results: Dict[str, Any] = {
        "script_version": SCRIPT_VERSION,
        "classes": classes,
        "binary_label_mapping": binary_label_meta,
        "feature_groups": groups,
        "regimes": {k: v for k, v in regimes.items()},
        "experiments": {m: {} for m in args.models},
        "aggregates": {m: {} for m in args.models},
    }

    print("[4/7] Running regimes...")

    for regime_idx, (regime_name, feature_cols) in enumerate(regimes.items(), start=1):
        print("\n" + "=" * 100)
        print(
            f"REGIME {regime_idx}/{len(regimes)}: {regime_name} "
            f"({len(feature_cols)} raw columns)"
        )
        print("=" * 100)

        prepared = prepare_regime(
            regime_name, feature_cols, train, val, test
        )

        print(
            f"      numeric={len(prepared.numeric_features)} "
            f"categorical={len(prepared.categorical_features)} "
            f"encoded_features={prepared.feature_count_after_encoding}"
        )

        deep_cache: Optional[Tuple[Any, Any, Any, Dict[str, Any]]] = None
        if any(m in {"mlp", "cnn"} for m in args.models):
            deep_cache = transform_for_deep(
                prepared,
                max_features=args.deep_max_features,
                random_state=args.preprocess_seed,
            )
            print(f"      deep preprocessing={deep_cache[3]}")

        for model_name in args.models:
            print(f"\n--- MODEL={model_name.upper()} | REGIME={regime_name} ---")
            seed_runs: List[Dict[str, Any]] = []

            for seed in args.seeds:
                print(f"\n  seed={seed}")

                if model_name == "rf":
                    run = run_random_forest(
                        prepared,
                        y_train,
                        y_val,
                        y_test,
                        classes,
                        seed=seed,
                        n_estimators=args.rf_trees,
                    )
                else:
                    if deep_cache is None:
                        raise RuntimeError("Deep preprocessing cache not initialized.")
                    Xtr_d, Xva_d, Xte_d, deep_meta = deep_cache
                    run = run_torch_model(
                        model_name,
                        Xtr_d,
                        y_train,
                        Xva_d,
                        y_val,
                        Xte_d,
                        y_test,
                        classes,
                        seed=seed,
                        epochs=args.epochs,
                        patience=args.patience,
                        batch_size=args.batch_size,
                        learning_rate=args.learning_rate,
                    )
                    run["deep_preprocessing"] = deep_meta

                if "skipped" not in run:
                    print_metrics(
                        f"{model_name.upper()} | {regime_name} | seed={seed}",
                        "validation",
                        run["validation"],
                    )
                    print_metrics(
                        f"{model_name.upper()} | {regime_name} | seed={seed}",
                        "test",
                        run["test"],
                    )
                else:
                    print(f"      [SKIP] {run['skipped']}")

                seed_runs.append(run)

            results["experiments"][model_name][regime_name] = seed_runs
            results["aggregates"][model_name][regime_name] = summarize_seed_runs(seed_runs)

    print("\n[5/7] Writing results...")
    with open(outdir / "baseline_results.json", "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False)

    write_summary_csv(results, str(outdir / "baseline_summary.csv"))

    latex_written = []
    if not args.no_latex:
        sii_table = outdir / "benchmark_sii_table.tex"
        if write_latex_sii_benchmark(
            results,
            str(sii_table),
            split="test",
            decimals=args.latex_decimals,
        ):
            latex_written.append(sii_table)

        sii_effect_table = outdir / "sii_effect_table.tex"
        if write_latex_sii_effect(
            results,
            str(sii_effect_table),
            split="test",
            decimals=args.latex_decimals,
        ):
            latex_written.append(sii_effect_table)

    with open(outdir / "feature_partition.json", "w", encoding="utf-8") as fh:
        json.dump(
            {
                "groups": groups,
                "regimes": regimes,
                "note": (
                    "A1/D1/D2 adapt the SoK occlusion logic to a tabular feature "
                    "dataset. The task is binary ATTACK vs BENIGN. D1 removes SII columns; D2 additionally removes SNI."
                ),
            },
            fh,
            indent=2,
            ensure_ascii=False,
        )

    print("[6/7] Paper-aligned ablation interpretation...")
    print_ablation_summary(results)

    print("\n[7/7] Complete.")
    print(f"      Results JSON : {outdir / 'baseline_results.json'}")
    print(f"      Summary CSV  : {outdir / 'baseline_summary.csv'}")
    print(f"      Manifest     : {outdir / 'experiment_manifest.json'}")
    print(f"      Feature map  : {outdir / 'feature_partition.json'}")
    if not args.no_latex:
        if latex_written:
            for latex_path in latex_written:
                print(f"      LaTeX table  : {latex_path}")
        else:
            print("      LaTeX table  : not generated (A1/D1 results unavailable)")


if __name__ == "__main__":
    main()
