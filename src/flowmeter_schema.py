#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
flowmeter_schema.py — feature schema for the zeek-flowmeter log (flowmeter/v1).

Kept SEPARATE from feature_schema.py on purpose: that module is exercised by the
repository's tests and by every stage of the pipeline, so the flowmeter feature set
lives here and is imported from there. Breaking this file cannot break the COMMON
schema.

SOURCE: zeek-flowmeter (https://github.com/zeek-flowmeter/zeek-flowmeter), a port of
CICFlowMeter to Zeek. It writes flowmeter.log with a `uid` matching conn.log, so it
joins exactly like ssl.log and quic.log already do in label_flows.py.

WHAT THIS MODULE DECIDES
------------------------
The raw log carries 81 columns (uid + 80 measures). Not all of them are usable, and
the reasons were MEASURED on a real 45-minute capture (19.820 flows: 10.227 TCP,
9.593 UDP), not assumed:

  * DROP_CONSTANT (4) — constant across BOTH transports in the reference capture.
    URG is effectively unused by modern stacks; CWR/ECE need ECN, which the lab does
    not enable. Zero information, so they are not published as features.
    RE-CHECK these if the lab ever enables ECN.

  * TCP_ONLY (10) — TCP flag counters and window sizes. These do not EXIST for a UDP
    flow. The flowmeter writes 0; we write NaN instead, because 0 is a legitimate
    count ("no RST was seen on this TCP flow") and NaN means "not applicable to this
    transport". Conflating the two is a silent lie in the published dataset.

  * COLLIDES_WITH_COMMON (2) — flow_duration and down_up_ratio already exist in
    feature_schema.COMMON_NUMERIC, computed from conn.log. Two columns with one name
    cannot coexist in a CSV, and conn.log is the canonical source, so the flowmeter
    copies are dropped. Near-duplicates with DIFFERENT names (fwd_pkts_tot vs
    tot_fwd_pkts) are KEPT: they are computed differently and the redundancy is
    visible to anyone reading the header.

Net: 80 - 4 - 10(kept, NaN on UDP) ... see FLOWMETER_FEATURES below for the exact set.

A WARNING THAT BELONGS IN THE DATASHEET
---------------------------------------
The TCP_ONLY columns identify the transport perfectly (NaN <=> UDP). So does
fwd_header_size_min (8 for UDP, 20+ for TCP). This is NOT fixable by feature
engineering — TCP and UDP flows genuinely differ. It only stops being a LABEL leak
when both attack and benign traffic exist on both transports. That is a campaign
design requirement, not a schema one.

NAMING: Zeek writes dotted names (fwd_iat.min). Dots are replaced with underscores
(fwd_iat_min) so the columns survive pandas/formula interfaces downstream. The
mapping is mechanical and reversible.
"""

import math

# ---------------------------------------------------------------- raw log layout

# The 81 columns of flowmeter.log, in file order, as emitted by zeek-flowmeter
# against Zeek 7.0. Verified against a real capture; do not reorder.
FLOWMETER_RAW_FIELDS = [
    "uid", "flow_duration", "fwd_pkts_tot", "bwd_pkts_tot", "fwd_data_pkts_tot",
    "bwd_data_pkts_tot", "fwd_pkts_per_sec", "bwd_pkts_per_sec", "flow_pkts_per_sec",
    "down_up_ratio", "fwd_header_size_tot", "fwd_header_size_min", "fwd_header_size_max",
    "bwd_header_size_tot", "bwd_header_size_min", "bwd_header_size_max",
    "flow_FIN_flag_count", "flow_SYN_flag_count", "flow_RST_flag_count",
    "fwd_PSH_flag_count", "bwd_PSH_flag_count", "flow_ACK_flag_count",
    "fwd_URG_flag_count", "bwd_URG_flag_count", "flow_CWR_flag_count",
    "flow_ECE_flag_count",
    "fwd_pkts_payload.min", "fwd_pkts_payload.max", "fwd_pkts_payload.tot",
    "fwd_pkts_payload.avg", "fwd_pkts_payload.std",
    "bwd_pkts_payload.min", "bwd_pkts_payload.max", "bwd_pkts_payload.tot",
    "bwd_pkts_payload.avg", "bwd_pkts_payload.std",
    "flow_pkts_payload.min", "flow_pkts_payload.max", "flow_pkts_payload.tot",
    "flow_pkts_payload.avg", "flow_pkts_payload.std",
    "fwd_iat.min", "fwd_iat.max", "fwd_iat.tot", "fwd_iat.avg", "fwd_iat.std",
    "bwd_iat.min", "bwd_iat.max", "bwd_iat.tot", "bwd_iat.avg", "bwd_iat.std",
    "flow_iat.min", "flow_iat.max", "flow_iat.tot", "flow_iat.avg", "flow_iat.std",
    "payload_bytes_per_second",
    "fwd_subflow_pkts", "bwd_subflow_pkts", "fwd_subflow_bytes", "bwd_subflow_bytes",
    "fwd_bulk_bytes", "bwd_bulk_bytes", "fwd_bulk_packets", "bwd_bulk_packets",
    "fwd_bulk_rate", "bwd_bulk_rate",
    "active.min", "active.max", "active.tot", "active.avg", "active.std",
    "idle.min", "idle.max", "idle.tot", "idle.avg", "idle.std",
    "fwd_init_window_size", "bwd_init_window_size",
    "fwd_last_window_size", "bwd_last_window_size",
]

# ------------------------------------------------------------------- exclusions

# Constant across BOTH transports in the reference capture -> zero information.
DROP_CONSTANT = [
    "fwd_URG_flag_count", "bwd_URG_flag_count",
    "flow_CWR_flag_count", "flow_ECE_flag_count",
]

# Already provided by feature_schema.COMMON_NUMERIC from conn.log (canonical source).
COLLIDES_WITH_COMMON = ["flow_duration", "down_up_ratio"]

# Meaningless for a non-TCP flow: written as NaN, never as 0.
TCP_ONLY = frozenset([
    "flow_FIN_flag_count", "flow_SYN_flag_count", "flow_RST_flag_count",
    "fwd_PSH_flag_count", "bwd_PSH_flag_count", "flow_ACK_flag_count",
    "fwd_init_window_size", "bwd_init_window_size",
    "fwd_last_window_size", "bwd_last_window_size",
])


def normalize_name(field):
    """Zeek's dotted names -> underscore names safe for downstream tooling."""
    return field.replace(".", "_")


_EXCLUDED = set(DROP_CONSTANT) | set(COLLIDES_WITH_COMMON) | {"uid"}

# Raw field names that are published, in file order.
FLOWMETER_SOURCE_FIELDS = [f for f in FLOWMETER_RAW_FIELDS if f not in _EXCLUDED]

# Published column names (what appears in the split-ready CSV header).
FLOWMETER_FEATURES = [normalize_name(f) for f in FLOWMETER_SOURCE_FIELDS]

# Counts/flags are integers; rates, times and std-devs are not. Used by the value-domain
# check to reject fractional counts the same way feature_schema.INTEGER_NUMERIC does.
FLOWMETER_INTEGER = frozenset(normalize_name(f) for f in FLOWMETER_SOURCE_FIELDS if (
    f.endswith("_flag_count")
    or f.endswith("_pkts_tot")
    or f.endswith("_data_pkts_tot")
    or f.endswith("_header_size_tot")
    or f.endswith("_header_size_min")
    or f.endswith("_header_size_max")
    or f.endswith("_subflow_pkts")
    or f.endswith("_subflow_bytes")
    or f.endswith("_bulk_packets")
    or f.endswith("_bulk_bytes")
    or f.endswith("_window_size")
))


def _fn(x):
    """Parse to float, or NaN if missing/invalid. Mirrors feature_schema._fn so a
    Zeek '-' (unset) becomes NaN rather than 0."""
    if x is None:
        return float("nan")
    s = str(x).strip()
    if s in ("", "-", "(empty)", "nan", "None"):
        return float("nan")
    try:
        return float(s)
    except ValueError:
        return float("nan")


def flowmeter_row_to_features(fm_row, transport):
    """Map one flowmeter.log row to the published feature dict.

    fm_row     -- dict for this uid from flowmeter.log, or {} when the join found
                  nothing (every published column then comes out NaN, which is the
                  honest representation of a missing measurement).
    transport  -- "TCP" / "UDP" / "UNKNOWN", from feature_schema's transport feature.
                  TCP_ONLY columns are NaN for anything that is not TCP.
    """
    nan = float("nan")
    is_tcp = str(transport).upper() == "TCP"
    out = {}
    for raw in FLOWMETER_SOURCE_FIELDS:
        name = normalize_name(raw)
        if raw in TCP_ONLY and not is_tcp:
            out[name] = nan          # not applicable to this transport, NOT zero
        else:
            out[name] = _fn(fm_row.get(raw))
    return out


def check_flowmeter_domains(rows):
    """Return a list of human-readable domain violations across `rows`.

    Checks the same three things feature_schema does for COMMON: no infinities, no
    negatives where the measure cannot be negative, and integral values where the
    measure is a count. NaN is always allowed — it means missing/not-applicable.
    """
    problems = []
    for name in FLOWMETER_FEATURES:
        vals = [r.get(name) for r in rows]
        fin = [v for v in vals if isinstance(v, float) and not math.isnan(v)]
        if any(math.isinf(v) for v in fin):
            problems.append("{}: contains infinity".format(name))
        if any(v < 0 for v in fin):
            problems.append("{}: contains negative values".format(name))
        if name in FLOWMETER_INTEGER and any(v != int(v) for v in fin):
            problems.append("{}: integer measure has fractional values".format(name))
    return problems
