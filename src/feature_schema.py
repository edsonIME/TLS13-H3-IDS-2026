#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
feature_schema.py
=================

Single source of truth for the COMMON feature schema shared by the REAL pipeline
(Zeek conn.log/ssl.log/quic.log) and the SYNTHETIC generator. This fixes the
"0 common features" problem: both sides are mapped to the SAME column names so
that validate_dataset.py and evaluate_realism.py actually compare like with like.

Only features that can be computed from a Zeek flow record are included, so the
synthetic data does not advertise features the real pipeline cannot produce.

  common name        <- Zeek conn.log (or derived)
  flow_duration      <- duration
  tot_fwd_pkts       <- orig_pkts
  tot_bwd_pkts       <- resp_pkts
  totlen_fwd_bytes   <- orig_ip_bytes (IP-level volume, matches the synthetic
                        pkts*size; falls back to orig_bytes) [audit 6]
  totlen_bwd_bytes   <- resp_ip_bytes (falls back to resp_bytes)
  down_up_ratio      <- resp_pkts / max(orig_pkts, 1)          (derived)
  flow_bytes_s       <- (totlen_fwd_bytes+totlen_bwd_bytes) / duration (derived;
                        i.e. IP-level orig_ip_bytes+resp_ip_bytes, NOT payload
                        orig_bytes+resp_bytes — falls back to payload only if the
                        ip_bytes are absent) [audit 6/14]
  flow_pkts_s        <- (orig_pkts+resp_pkts) / duration       (derived)
  sni_present        <- 1 if ssl.server_name or quic.server_name else 0
  transport          <- proto (TCP/UDP)
  dst_port_class     <- class of id.resp_p
  tls_version        <- ssl.version (or "1.3" for QUIC)
  alpn               <- ssl.next_protocol or quic.client_protocol
  ja3, ja3s          <- ssl.ja3 / ssl.ja3s
"""

import math

COMMON_NUMERIC = ["flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
                  "totlen_fwd_bytes", "totlen_bwd_bytes", "down_up_ratio",
                  "flow_bytes_s", "flow_pkts_s", "sni_present"]
COMMON_CATEGORICAL = ["transport", "dst_port_class", "tls_version", "alpn",
                      "ja3", "ja3s"]
COMMON = COMMON_NUMERIC + COMMON_CATEGORICAL
LABEL = "label"

# Value domains for the categorical/bounded features [audit 4]. Used to reject
# physically-impossible values (inf, negatives, fractional counts, out-of-domain
# categories) in the OFFICIAL split, while still allowing NaN as "missing".
TRANSPORT_DOMAIN = {"TCP", "UDP", "UNKNOWN"}
PORT_CLASS_DOMAIN = {"well_known", "registered", "ephemeral", "unknown"}
TLS_VERSION_DOMAIN = {"none", "1.0", "1.1", "1.2", "1.3"}
ALPN_DOMAIN = {"h2", "h3", "http/1.1", "none"}       # open-ish -> warn, do not abort
INTEGER_NUMERIC = {"tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_bytes",
                   "totlen_bwd_bytes"}               # counts/byte totals are integers

# --- EXTENDED schema (COMMON + zeek-flowmeter) -------------------------------------
# COMMON is UNCHANGED on purpose: it is the cross-dataset comparable core that
# merge/validate and the tests reference. EXTENDED is what the split-ready CSV
# actually carries once flowmeter.log is joined. The import is lazy so this module
# still imports on a host without the flowmeter (CI, an older checkout).
try:
    import flowmeter_schema as _fms
    FLOWMETER = list(_fms.FLOWMETER_FEATURES)
except ImportError:                                   # flowmeter not installed
    FLOWMETER = []
EXTENDED = COMMON + FLOWMETER

# Single source of truth for the dataset LABEL vocabulary [audit 8]. BENIGN is a
# valid dataset label (the annotations only carry the ATTACK subset). Every stage
# — generator, labeler, merge, validator, realism — checks against this set so a
# stray class (e.g. "UnknownAttack") can never sail through an evaluator.
ALLOWED_LABELS = {"BENIGN", "PortScan", "BruteForce", "DoS"}

# Columns that are CATEGORICAL/text and must be read as STRINGS, so a value like
# tls_version="1.3" is a string in EVERY file. Without this, pandas infers "1.3" as the float
# 1.3 in a file where the whole column looks numeric, but as object in another, and merge then
# rejects a perfectly valid run on a spurious dtype mismatch [audit v20.7 P0-2].
_STR_COLUMNS = set(COMMON_CATEGORICAL) | {LABEL}


def read_common_csv(path, extra_str=()):
    """Read a split-ready / COMMON CSV with SCHEMA-AWARE dtypes: categorical + label columns as
    strings (so tls_version='1.3' never becomes a float), numeric columns inferred. Only columns
    actually present are typed, so it works on ML, split-ready or audit files [audit v20.7 P0-2]."""
    import pandas as pd
    present = pd.read_csv(path, nrows=0).columns
    want = _STR_COLUMNS | set(extra_str)
    dtypes = {c: str for c in present if c in want}
    return pd.read_csv(path, dtype=dtypes)


def unknown_labels(labels, allowed=None):
    """Return the SORTED set of labels not in `allowed` (default ALLOWED_LABELS).

    `labels` may be any iterable (a pandas Series, list, set…); values are
    compared as strings so 1 vs "1" style mismatches do not hide a bad label.
    Blank/NaN values are ignored here (use require_valid_labels to reject those).
    """
    allowed = ALLOWED_LABELS if allowed is None else allowed
    seen = {str(x) for x in labels if not _label_blank(x)}
    return sorted(seen - {str(a) for a in allowed})


def _label_blank(x):
    """True if a label value is missing/empty (None, NaN, '', 'nan', 'None')."""
    if x is None:
        return True
    try:
        if x != x:                                   # NaN != NaN
            return True
    except (TypeError, ValueError):
        pass
    return str(x).strip() in ("", "nan", "None")


def check_common_value_domains(df):
    """Return (errors, warnings) for physically-impossible COMMON values [audit 4].

    NaN is allowed (missingness). ERRORS: inf, negative, fractional counts,
    sni_present not in {0,1}, or transport/dst_port_class/tls_version out of
    domain. WARNINGS: undocumented ALPN (open domain). Imports pandas/numpy
    lazily so feature_schema stays light for the labeler.
    """
    import numpy as np
    import pandas as pd
    errors, warnings = [], []
    for col in COMMON_NUMERIC:
        if col not in df.columns:
            continue
        v = pd.to_numeric(df[col], errors="coerce").to_numpy(dtype=float)
        vp = v[~np.isnan(v)]                             # drop missing
        if vp.size and np.isinf(vp).any():
            errors.append("{}: {} inf".format(col, int(np.isinf(vp).sum())))
        fin = vp[np.isfinite(vp)]
        if fin.size and (fin < 0).any():
            errors.append("{}: {} negative".format(col, int((fin < 0).sum())))
        if col in INTEGER_NUMERIC and fin.size:
            frac = fin != np.floor(fin)
            if frac.any():
                errors.append("{}: {} fractional (integer count expected)".format(
                    col, int(frac.sum())))
    if "sni_present" in df.columns:
        s = pd.to_numeric(df["sni_present"], errors="coerce").dropna()
        bad = s[~s.isin([0, 1])]
        if len(bad):
            errors.append("sni_present: {} value(s) not in {{0,1}}".format(len(bad)))
    for col, domain in (("transport", TRANSPORT_DOMAIN),
                        ("dst_port_class", PORT_CLASS_DOMAIN),
                        ("tls_version", TLS_VERSION_DOMAIN)):
        if col in df.columns:
            out = sorted(set(df[col].dropna().astype(str)) - domain)
            if out:
                errors.append("{}: out-of-domain {}".format(col, out))
    if "alpn" in df.columns:
        out = sorted(set(df["alpn"].dropna().astype(str)) - ALPN_DOMAIN)
        if out:
            warnings.append("alpn: undocumented value(s) {}".format(out))
    return errors, warnings


def check_common_relational_constraints(df, rel_tol=0.02, abs_tol=0.02):
    """Return a list of DERIVED-feature inconsistencies among COMMON columns [audit 6].

    A row can pass per-feature domain checks yet be internally impossible (e.g.
    flow_bytes_s that does not equal (bytes)/duration). Verifies, with a combined
    relative+absolute tolerance so legitimate rounding does not trip it:
        down_up_ratio ~= tot_bwd_pkts / max(tot_fwd_pkts, 1)
        flow_bytes_s  ~= (totlen_fwd_bytes + totlen_bwd_bytes) / flow_duration
        flow_pkts_s   ~= (tot_fwd_pkts + tot_bwd_pkts) / flow_duration
    Rows with NaN in any needed field, or non-positive duration, are skipped.
    """
    import numpy as np
    import pandas as pd

    def col(c):
        return (pd.to_numeric(df[c], errors="coerce").to_numpy(dtype=float)
                if c in df.columns else None)

    dur, fwp, bwp = col("flow_duration"), col("tot_fwd_pkts"), col("tot_bwd_pkts")
    fb, bb = col("totlen_fwd_bytes"), col("totlen_bwd_bytes")
    dur_r, fbs, fps = col("down_up_ratio"), col("flow_bytes_s"), col("flow_pkts_s")

    def n_bad(stored, expected):
        m = np.isfinite(stored) & np.isfinite(expected)
        return int((m & (np.abs(stored - expected) > abs_tol + rel_tol * np.abs(expected))).sum())

    errs = []
    # A non-positive duration with a FINITE rate is impossible (rate = x/0) [audit 10].
    if dur is not None:
        nonpos = np.isfinite(dur) & (dur <= 0)
        for rname, rvals in (("flow_bytes_s", fbs), ("flow_pkts_s", fps)):
            if rvals is not None:
                k = int((nonpos & np.isfinite(rvals)).sum())
                if k:
                    errs.append("{} finite with duration<=0 in {} row(s)".format(rname, k))
    if dur_r is not None and fwp is not None and bwp is not None:
        k = n_bad(dur_r, bwp / np.maximum(fwp, 1))
        if k:
            errs.append("down_up_ratio inconsistent in {} row(s)".format(k))
    if fbs is not None and fb is not None and bb is not None and dur is not None:
        d = np.where(dur > 0, dur, np.nan)
        k = n_bad(fbs, (fb + bb) / d)
        if k:
            errs.append("flow_bytes_s inconsistent in {} row(s)".format(k))
    if fps is not None and fwp is not None and bwp is not None and dur is not None:
        d = np.where(dur > 0, dur, np.nan)
        k = n_bad(fps, (fwp + bwp) / d)
        if k:
            errs.append("flow_pkts_s inconsistent in {} row(s)".format(k))
    return errs


def check_official_columns(df, require_time=True):
    """Errors if the RAW input is not an official split-ready frame [audit 8/9].

    Runs on the ORIGINAL dataframe BEFORE to_common(), so it catches (a) the COMMON
    columns being ABSENT (to_common would otherwise silently fabricate them as NA
    and the pipeline would impute — making "9 numeric + 6 categorical" a lie), and
    (b) NON-NUMERIC JUNK like 'BAD' in a numeric column (to_numeric-coerce would
    turn it into NaN and hide it). require_time=True demands run_id + timestamp
    (a real split-ready file); the synthetic file may omit them.
    """
    import pandas as pd
    errors = []
    needed = (["run_id", "timestamp"] if require_time else []) + list(COMMON) + [LABEL]
    missing = [c for c in needed if c not in df.columns]
    if missing:
        errors.append("missing official column(s): {}".format(missing))
    for col in COMMON_NUMERIC:
        if col in df.columns:
            coerced = pd.to_numeric(df[col], errors="coerce")
            n_bad = int((df[col].notna() & coerced.isna()).sum())    # junk, not blank
            if n_bad:
                errors.append("{}: {} non-numeric junk (e.g. 'BAD')".format(col, n_bad))
    return errors


def common_contract_violations(df):
    """One entry point for the full numeric/categorical CONTRACT [audit 7].

    Combines value-domain checks (inf/negative/fractional/out-of-domain) with the
    relational consistency of the derived features. Returns (errors, warnings).
    EVERY tool that can influence a metric (labeler, generator, merge, validator,
    realism) should call this so an impossible external file cannot slip through.
    """
    errors, warnings = check_common_value_domains(df)
    errors = list(errors) + check_common_relational_constraints(df)
    return errors, warnings


def require_valid_labels(labels, where="", allow_extra=False):
    """Fail-closed label check for EVERY pipeline entry point [audit 4/8].

    Rejects (SystemExit) any missing/empty label first, then (unless allow_extra)
    any label outside ALLOWED_LABELS. Pandas-free so feature_schema stays light.
    """
    ctx = (" in " + where) if where else ""
    vals = list(labels)
    n_blank = sum(1 for x in vals if _label_blank(x))
    if n_blank:
        raise SystemExit("ABORT: label is missing/empty in {} row(s){}. Every row "
                         "needs a valid label. [audit 4]".format(n_blank, ctx))
    if not allow_extra:
        unk = unknown_labels(vals)
        if unk:
            raise SystemExit("ABORT: unknown label(s) {} not in {}{}. Pass "
                             "--allow-extra-labels to override. [audit 8]".format(
                                 unk, sorted(ALLOWED_LABELS), ctx))


def _f(x, default=0.0):
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


def _i(x, default=0):
    try:
        return int(float(x))
    except (TypeError, ValueError):
        return default


def port_class(port):
    """Encode a raw port into a coarse class (avoids the raw-port shortcut)."""
    try:
        p = int(port)
    except (TypeError, ValueError):
        return "unknown"
    return "well_known" if p < 1024 else ("registered" if p < 49152 else "ephemeral")


_TLS_TABLE = {"TLSv13": "1.3", "TLSv12": "1.2", "TLSv11": "1.1", "TLSv10": "1.0",
              "TLSv1.3": "1.3", "TLSv1.2": "1.2", "TLSv1.1": "1.1", "TLSv1.0": "1.0"}


def normalize_tls(v):
    """Normalize TLS version tokens so Zeek ('TLSv13') and synthetic ('1.3')
    share the same category domain [audit 4.6]."""
    if v is None:
        return "none"
    s = str(v).strip()
    if s in ("", "-", "nan", "None", "(empty)"):
        return "none"
    return _TLS_TABLE.get(s, s)


def _fn(x):
    """Parse to float, or NaN if missing/invalid (preserves missingness)."""
    try:
        return float(x)
    except (TypeError, ValueError):
        return float("nan")


def zeek_row_to_common(conn, ssl, quic):
    """Map one Zeek flow (conn + merged ssl/quic dicts) to COMMON features.

    Missing numeric fields are kept as NaN (NOT zero), consistent with
    to_common(), so a real zero is distinguishable from "unknown" [audit 2].
    Imputation belongs in the model pipeline, not here.
    """
    nan = float("nan")
    dur = _fn(conn.get("duration"))
    ofp, rfp = _fn(conn.get("orig_pkts")), _fn(conn.get("resp_pkts"))
    # IP-level bytes to match the synthetic volume (pkts*size); fall back to
    # payload bytes only if ip_bytes are absent [audit 6].
    ob = _fn(conn.get("orig_ip_bytes"))
    if math.isnan(ob):
        ob = _fn(conn.get("orig_bytes"))
    rb = _fn(conn.get("resp_ip_bytes"))
    if math.isnan(rb):
        rb = _fn(conn.get("resp_bytes"))
    tot_bytes = nan if (math.isnan(ob) or math.isnan(rb)) else ob + rb
    tot_pkts = nan if (math.isnan(ofp) or math.isnan(rfp)) else ofp + rfp

    def rate(num):                                   # num / duration, NaN-aware
        # duration <= 0 (a 0-length or incomplete flow) must yield NaN, NOT a giant
        # rate from dividing by 1e-6 — those extremes act as shortcuts [audit 10].
        if math.isnan(num) or math.isnan(dur) or dur <= 0:
            return nan
        return round(num / dur, 2)

    down_up = nan if (math.isnan(rfp) or math.isnan(ofp)) else round(rfp / max(ofp, 1), 4)
    proto = (conn.get("proto") or "unknown").upper()
    raw_ver = ssl.get("version")
    tls_version = normalize_tls(raw_ver) if raw_ver else ("1.3" if quic else "none")
    return {
        "flow_duration": nan if math.isnan(dur) else round(dur, 6),
        "tot_fwd_pkts": ofp,
        "tot_bwd_pkts": rfp,
        "totlen_fwd_bytes": ob,
        "totlen_bwd_bytes": rb,
        "down_up_ratio": down_up,
        "flow_bytes_s": rate(tot_bytes),
        "flow_pkts_s": rate(tot_pkts),
        "sni_present": 1 if (ssl.get("server_name") or quic.get("server_name")) else 0,
        "transport": proto,
        "dst_port_class": port_class(conn.get("id.resp_p")),
        "tls_version": tls_version,
        "alpn": ssl.get("next_protocol") or quic.get("client_protocol") or "none",
        "ja3": ssl.get("ja3") or "none",
        "ja3s": ssl.get("ja3s") or "none",
    }


def select_common(df):
    """Return a DataFrame with exactly the COMMON columns (+ label if present).

    Missing common columns are added as NA, so a real and a synthetic file are
    always comparable even if one lacks a column.
    """
    import pandas as pd
    out = pd.DataFrame(index=df.index)
    for c in COMMON:
        out[c] = df[c] if c in df.columns else pd.NA
    if LABEL in df.columns:
        out[LABEL] = df[LABEL].values
    return out


def to_common(df):
    """Normalize EITHER a synthetic/ML file (already common) OR a Zeek audit
    file (raw conn/ssl/quic columns) to the COMMON schema.

    This is what lets evaluate_realism.py compare the real audit CSV against the
    synthetic dataset on the same columns.
    """
    import numpy as np
    import pandas as pd

    if "flow_duration" in df.columns:            # already common (synth / ML)
        return select_common(df)

    def col(name):                               # missing column -> NA series
        return df[name] if name in df.columns else pd.Series([None] * len(df), index=df.index)

    # Preserve NaN so missingness is measurable [audit 5]; imputation belongs in
    # the MODEL pipeline, not here. dur_safe is used only to avoid /0 in rates.
    dur = pd.to_numeric(col("duration"), errors="coerce")
    ofp = pd.to_numeric(col("orig_pkts"), errors="coerce")
    rfp = pd.to_numeric(col("resp_pkts"), errors="coerce")
    ob = pd.to_numeric(col("orig_ip_bytes"), errors="coerce")   # IP-level [audit 6]
    ob = ob.where(ob.notna(), pd.to_numeric(col("orig_bytes"), errors="coerce"))
    rb = pd.to_numeric(col("resp_ip_bytes"), errors="coerce")
    rb = rb.where(rb.notna(), pd.to_numeric(col("resp_bytes"), errors="coerce"))
    # duration <= 0 -> NaN rates (not a 1e-6-divided giant) [audit 10].
    dur_pos = dur.where(dur > 0)

    out = pd.DataFrame(index=df.index)
    out["flow_duration"] = dur.round(6)
    out["tot_fwd_pkts"] = ofp                       # kept float to allow NaN
    out["tot_bwd_pkts"] = rfp
    out["totlen_fwd_bytes"] = ob
    out["totlen_bwd_bytes"] = rb
    out["down_up_ratio"] = (rfp / ofp.clip(lower=1)).round(4)
    out["flow_bytes_s"] = ((ob + rb) / dur_pos).round(2)
    out["flow_pkts_s"] = ((ofp + rfp) / dur_pos).round(2)
    out["sni_present"] = (col("server_name").notna() | col("quic_sni").notna()).astype(int)
    out["transport"] = col("proto").astype("string").str.upper().fillna("unknown")
    if "dst_port_class" in df.columns:
        out["dst_port_class"] = df["dst_port_class"]
    else:
        out["dst_port_class"] = col("id.resp_p").apply(port_class)
    qv = col("quic_version")
    ver = col("version").map(normalize_tls)             # TLSv13 -> 1.3, etc.
    ver = ver.where(~((ver == "none") & qv.notna()), "1.3")   # QUIC implies 1.3
    out["tls_version"] = ver
    alpn = col("next_protocol").astype("string").fillna(col("quic_alpn").astype("string"))
    out["alpn"] = alpn.fillna("none")
    out["ja3"] = col("ja3").astype("string").fillna("none")
    out["ja3s"] = col("ja3s").astype("string").fillna("none")
    if LABEL in df.columns:
        out[LABEL] = df[LABEL].values
    return out
