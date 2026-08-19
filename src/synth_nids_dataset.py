#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
synth_nids_dataset.py
=====================

Synthetic Network Intrusion Detection (NIDS) dataset generator for MODERN
ENCRYPTED traffic (HTTPS over TLS 1.3, HTTP/3-QUIC, plus legacy TLS 1.2), with
best practices from the NIDS-dataset literature baked in.

BEST PRACTICES INCORPORATED (see boas_praticas_nids_referenciado.md)
-------------------------------------------------------------------
  * No shortcut features: we do NOT emit source IP / TTL / flow-id. The raw
    destination port is kept but FLAGGED as shortcut-prone and complemented by
    an encoded `dst_port_class` (well_known/registered/ephemeral), because a
    single feature like destination port can yield 70-100% accuracy.
        [Arp et al. 2022, P4 Spurious Correlations] and
        ["...Survey, Limitations, and Recommendations", §6.3 "shortcuts"].
  * Temporal structure: each flow carries a `run_id` and a `timestamp` so users
    can build a TEMPORAL train/test split (train earlier runs, test later ones)
    instead of a naive shuffle/cross-validation that leaks attacks.
        [Ring et al. 2019, "Predefined Subsets"] and [Arp et al. 2022, P3].
  * Domain randomization: profile parameters are jittered PER RUN so attacks are
    not homogeneous, enabling cross-run generalization tests.
        ["Bad Design Smells in Benchmark NIDS Datasets", §6.1; Smell 1].
  * Realistic class imbalance (optional): attacks as a small minority, matching
    real base rates; pair with PR/MCC metrics, not accuracy.
        [Arp et al. 2022, P7/P8; Survey §6.3 "all that glitters"].
  * Benign traffic hits the SAME services/ports as the attacks, so a model
    cannot separate classes on an incidental port/service artifact.
        ["Bad Design Smells...", §6.3].

SCOPE / SAFETY
--------------
Purely synthetic: it does NOT send packets or touch any host. It fabricates
flow records from parametric distributions. It is a PROTOTYPING/augmentation
tool; for high realism, capture real traffic in the isolated testbed (runbook).

OUTPUT
------
A CSV with one flow per row (numeric + categorical features + `label`).

USAGE
-----
    python3 synth_nids_dataset.py
    python3 synth_nids_dataset.py --runs 4 --imbalance
    python3 synth_nids_dataset.py --attacks PortScan DoS --seed 7
"""

import argparse
import hashlib
import json
import subprocess
import sys

import numpy as np
import pandas as pd

import feature_schema as fs        # single source of truth for the common schema

CODE_VERSION = "synth/v16"


def _git_commit():
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True,
                             text=True, timeout=5)
        return out.stdout.strip() or None if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def write_metadata(out_path, args, df):
    """Emit <out>.metadata.json automatically (seed/sha256/class_counts) [audit 19].

    The provenance sidecar is PRODUCED BY THE GENERATOR, not maintained by hand,
    so it can never drift from the CSV it describes.
    """
    sha = hashlib.sha256()
    with open(out_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha.update(chunk)
    # Record EVERY resolved argument (not just a few) plus the raw argv, so the metadata
    # actually REPRODUCES the file. Omitting --benign/--attack-each/--attacks made the old
    # "command" fall back to defaults and regenerate a DIFFERENT dataset [audit 10].
    arguments = {
        "benign": int(args.benign), "attack_each": int(args.attack_each),
        "attacks": list(args.attacks), "runs": int(args.runs), "seed": int(args.seed),
        "profile": args.profile, "schema": args.schema, "imbalance": bool(args.imbalance),
        "out": args.out,
    }
    command = ("python synth_nids_dataset.py --runs {runs} --benign {benign} "
               "--attack-each {attack_each} --attacks {attacks} --seed {seed} "
               "--profile {profile} --schema {schema}{imb} --out {out}".format(
                   runs=arguments["runs"], benign=arguments["benign"],
                   attack_each=arguments["attack_each"],
                   attacks=" ".join(map(str, args.attacks)), seed=arguments["seed"],
                   profile=arguments["profile"], schema=arguments["schema"],
                   out=arguments["out"], imb=(" --imbalance" if args.imbalance else "")))
    meta = {
        "generator": "synth_nids_dataset.py", "generator_version": CODE_VERSION,
        "git_commit": _git_commit(),
        "command": command, "arguments": arguments, "argv": list(sys.argv),
        # Kept at top level too for backward compatibility with earlier readers.
        "seed": args.seed, "runs": args.runs, "profile": args.profile,
        "schema": args.schema, "imbalance": bool(args.imbalance),
        "n_rows": int(len(df)), "columns": list(df.columns), "sha256": sha.hexdigest(),
        "class_counts": {str(k): int(v) for k, v in df["label"].value_counts().items()},
        "note": ("Synthetic PROTOTYPE from a parametric generator — NOT evidence about "
                 "the real testbed. Re-run the command to reproduce; sha256 must match."),
    }
    with open(out_path.replace(".csv", "") + ".metadata.json", "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    return meta["sha256"]


# ===========================================================================
# 1) ENCRYPTED-PROTOCOL MODEL
# ===========================================================================
PROTOCOL_TABLE = {
    "HTTPS-TLS13": {"transport": "TCP", "port": 443, "tls": "1.3", "enc": 1,
                    "alpn": [("h2", 0.7), ("http/1.1", 0.3)]},
    "HTTPS-TLS12": {"transport": "TCP", "port": 443, "tls": "1.2", "enc": 1,
                    "alpn": [("h2", 0.5), ("http/1.1", 0.5)]},
    "HTTP3-QUIC":  {"transport": "UDP", "port": 443, "tls": "1.3", "enc": 1,
                    "alpn": [("h3", 1.0)]},
    "HTTP-plain":  {"transport": "TCP", "port": 80,  "tls": "none", "enc": 0,
                    "alpn": [("http/1.1", 1.0)]},
    "TCP-probe":   {"transport": "TCP", "port": None, "tls": "none", "enc": 0,
                    "alpn": [("none", 1.0)]},
    # Benign NON-TLS services so a model cannot treat tls=none / ja3=none / sni=0
    # as a perfect PortScan tell [audit 16]. These reuse the BENIGN flow-stats
    # profile (a coarse approximation of duration/size, not per-service tuned).
    "DNS":         {"transport": "UDP", "port": 53,  "tls": "none", "enc": 0,
                    "alpn": [("none", 1.0)]},
    "NTP":         {"transport": "UDP", "port": 123, "tls": "none", "enc": 0,
                    "alpn": [("none", 1.0)]},
    "HTTP-health": {"transport": "TCP", "port": 8080, "tls": "none", "enc": 0,
                    "alpn": [("http/1.1", 1.0)]},
    "TCP-refused": {"transport": "TCP", "port": 3306, "tls": "none", "enc": 0,
                    "alpn": [("none", 1.0)]},
}

TLS13_CIPHERS = ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
                 "TLS_CHACHA20_POLY1305_SHA256"]
TLS12_CIPHERS = ["ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384",
                 "ECDHE-ECDSA-CHACHA20-POLY1305"]


# ===========================================================================
# 2) PER-CLASS TRAFFIC PROFILES
# ===========================================================================
CLASS_PROFILES = {
    "BENIGN": {
        "duration_median": 4.0, "duration_sigma": 1.0,
        "fwd_pkts_median": 12, "fwd_pkts_sigma": 0.8,
        "bwd_pkts_median": 14, "bwd_pkts_sigma": 0.9,
        "fwd_size_mean": 210, "fwd_size_sd": 90,
        "bwd_size_mean": 900, "bwd_size_sd": 500,
        "fin_p": 0.70, "rst_p": 0.05,
    },
    "PortScan": {
        "duration_median": 0.02, "duration_sigma": 0.6,
        "fwd_pkts_median": 1, "fwd_pkts_sigma": 0.2,
        "bwd_pkts_median": 1, "bwd_pkts_sigma": 0.4,
        "fwd_size_mean": 40, "fwd_size_sd": 6,
        "bwd_size_mean": 44, "bwd_size_sd": 8,
        "fin_p": 0.02, "rst_p": 0.70,
    },
    "BruteForce": {
        # HTTPS login attempts: POST with credentials, and the server returns a
        # FULL login page, so response sizes OVERLAP benign pages instead of
        # being a trivial separator [audit 3.1/3.2].
        "duration_median": 0.6, "duration_sigma": 0.9,
        "fwd_pkts_median": 9, "fwd_pkts_sigma": 0.7,
        "bwd_pkts_median": 10, "bwd_pkts_sigma": 0.8,
        "fwd_size_mean": 300, "fwd_size_sd": 140,
        "bwd_size_mean": 800, "bwd_size_sd": 450,
        "fin_p": 0.55, "rst_p": 0.12,
    },
    "DoS": {
        # Slow-HTTP (slowloris / slowhttptest -H): ONE connection held open a
        # long time, dribbling partial headers -> long duration, few packets,
        # tiny throughput. Matches the testbed tool, NOT a SYN flood [audit 3.4].
        "duration_median": 60.0, "duration_sigma": 0.7,
        "fwd_pkts_median": 6, "fwd_pkts_sigma": 0.8,
        "bwd_pkts_median": 3, "bwd_pkts_sigma": 0.9,
        "fwd_size_mean": 70, "fwd_size_sd": 40,
        "bwd_size_mean": 120, "bwd_size_sd": 90,
        "fin_p": 0.10, "rst_p": 0.35,
    },
}

# Benign shares ports 443/80 with the attacks so the class boundary cannot be an
# incidental port artifact [Bad Design Smells, §6.3].
# Protocol mix per class. Two profiles [audit 8]:
#   testbed (default): matches the lab EXACTLY — Caddy forces TLS 1.3 and the
#     tools use HTTPS/TCP, so NO TLS 1.2 and NO plain HTTP are generated.
#   broad: a wider scenario that ALSO includes TLS 1.2 / plain HTTP; use it only
#     when you explicitly want a dataset that is NOT a replica of this testbed.
L7_MIX_TESTBED = {
    # The testbed profile only includes NON-TLS benign that the REAL lab actually
    # produces: DNS + NTP served by the NB1 infra [audit 14.1]. health checks
    # (8080) and refused DB connections (3306) are NOT demonstrated in the current
    # testbed, so they live in the BROAD profile until implemented for real. Even
    # just DNS/NTP make tls=none / ja3=none / sni=0 no longer a free PortScan tell.
    "BENIGN":     [("HTTPS-TLS13", 0.66), ("HTTP3-QUIC", 0.18), ("DNS", 0.11),
                   ("NTP", 0.05)],
    "PortScan":   [("TCP-probe", 1.0)],
    "BruteForce": [("HTTPS-TLS13", 1.0)],
    "DoS":        [("HTTPS-TLS13", 1.0)],
}
L7_MIX_BROAD = {
    "BENIGN":     [("HTTPS-TLS13", 0.48), ("HTTP3-QUIC", 0.16),
                   ("HTTPS-TLS12", 0.10), ("HTTP-plain", 0.06), ("DNS", 0.10),
                   ("NTP", 0.04), ("HTTP-health", 0.04), ("TCP-refused", 0.02)],
    "PortScan":   [("TCP-probe", 1.0)],
    "BruteForce": [("HTTPS-TLS13", 0.70), ("HTTPS-TLS12", 0.20),
                   ("HTTP-plain", 0.10)],
    "DoS":        [("HTTPS-TLS13", 0.50), ("HTTP3-QUIC", 0.30),
                   ("HTTPS-TLS12", 0.20)],
}
L7_MIX = L7_MIX_TESTBED          # active profile; overridden in main by --profile

SNI_P = {"BENIGN": 0.98, "PortScan": 0.0, "BruteForce": 0.85, "DoS": 0.85}

# Per-L7-protocol flow-stats overrides for the NON-TLS benign services, so DNS/NTP/
# health/refused do NOT inherit the generic 4-second web-browsing profile [audit 8].
# They are short and small; TCP-refused is scan-LIKE (1 pkt + RST) on purpose, so a
# model cannot treat "short + RST" as a free PortScan tell.
PROTO_STATS_OVERRIDE = {
    "DNS":         {"duration_median": 0.02, "duration_sigma": 0.5,
                    "fwd_pkts_median": 1, "bwd_pkts_median": 1,
                    "fwd_size_mean": 60, "fwd_size_sd": 15,
                    "bwd_size_mean": 120, "bwd_size_sd": 60, "fin_p": 0.0, "rst_p": 0.0},
    "NTP":         {"duration_median": 0.01, "duration_sigma": 0.4,
                    "fwd_pkts_median": 1, "bwd_pkts_median": 1,
                    "fwd_size_mean": 76, "fwd_size_sd": 4,
                    "bwd_size_mean": 76, "bwd_size_sd": 4, "fin_p": 0.0, "rst_p": 0.0},
    "HTTP-health": {"duration_median": 0.05, "duration_sigma": 0.5,
                    "fwd_pkts_median": 3, "bwd_pkts_median": 2,
                    "fwd_size_mean": 120, "fwd_size_sd": 30,
                    "bwd_size_mean": 200, "bwd_size_sd": 60, "fin_p": 0.8, "rst_p": 0.02},
    "TCP-refused": {"duration_median": 0.005, "duration_sigma": 0.5,
                    "fwd_pkts_median": 1, "bwd_pkts_median": 1,
                    "fwd_size_mean": 44, "fwd_size_sd": 4,
                    "bwd_size_mean": 40, "bwd_size_sd": 4, "fin_p": 0.0, "rst_p": 0.95},
}

# How many DISTINCT client fingerprints each class uses. Crucially, the attack
# tools' fingerprints are drawn FROM the benign pool (overlap), so JA3 alone is
# NOT a clean label proxy [audit 3.3]. JA3S is shared (same victim TLS stack).
JA3_CLIENTS = {"BENIGN": 50, "BruteForce": 3, "DoS": 2, "PortScan": 0}
N_SERVER_FPS = 3

ATTACK_CLASSES = ["PortScan", "BruteForce", "DoS"]

# NOTE: source IP, MAC and TTL are intentionally ABSENT (shortcut artifacts).
# `dst_port` is kept but marked shortcut-prone; use `dst_port_class` for ML.
COLUMN_ORDER = [
    "run_id", "timestamp", "transport", "ip_proto", "dst_port", "dst_port_class",
    "l7_protocol", "is_encrypted", "tls_version", "tls_cipher", "alpn",
    "sni_present", "ja3", "ja3s", "tls_handshake_ms", "flow_duration",
    "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_bytes", "totlen_bwd_bytes",
    "fwd_pkt_len_mean", "bwd_pkt_len_mean", "flow_bytes_s", "flow_pkts_s",
    "flow_iat_mean", "flow_iat_std", "syn_flag_cnt", "ack_flag_cnt",
    "fin_flag_cnt", "rst_flag_cnt", "psh_flag_cnt", "down_up_ratio", "label",
]
TCP_FLAG_COLS = ["syn_flag_cnt", "ack_flag_cnt", "fin_flag_cnt",
                 "rst_flag_cnt", "psh_flag_cnt"]
SECONDS_PER_DAY = 86400
BASE_TS = 1_752_710_400  # arbitrary epoch anchor for run 0 (2025-07-17 UTC)
# Concentrated attack window per class (seconds), matching the real tools:
# PortScan/BruteForce last minutes, slow-HTTP DoS ~2 min [audit 7].
ATTACK_WINDOW_SEC = {"PortScan": 300, "BruteForce": 600, "DoS": 130}


# ===========================================================================
# 3) HELPER SAMPLERS
# ===========================================================================
def lognormal_from_median(rng, median, sigma, size):
    """Sample a lognormal parameterized by its MEDIAN (median == exp(mu))."""
    mu = np.log(np.maximum(median, 1e-9))
    return rng.lognormal(mean=mu, sigma=sigma, size=size)


def weighted_choice(rng, options):
    """Pick one label from a list of (label, weight) pairs."""
    labels = [o for o, _ in options]
    weights = np.array([w for _, w in options], dtype=float)
    weights /= weights.sum()
    return rng.choice(labels, p=weights)


def rand_ja3(rng):
    """Return a fake but well-formed 32-hex-char JA3/JA3S-style fingerprint."""
    return "".join("%x" % d for d in rng.integers(0, 16, size=32))


def build_ja3_pools(rng):
    """Build OVERLAPPING client pools + one shared server pool.

    Benign spans the whole client-fingerprint space; each attack tool reuses a
    few fingerprints that ALSO appear in benign traffic, so a classifier cannot
    perfectly separate classes on JA3 [audit 3.3]. JA3S is shared across all
    classes because every flow hits the same victim server.
    """
    client_space = [rand_ja3(rng) for _ in range(JA3_CLIENTS["BENIGN"])]
    server_pool = [rand_ja3(rng) for _ in range(N_SERVER_FPS)]
    pools = {"_server": server_pool, "BENIGN": client_space, "PortScan": []}
    for cls in ("BruteForce", "DoS"):
        idx = rng.choice(len(client_space), size=JA3_CLIENTS[cls], replace=False)
        pools[cls] = [client_space[i] for i in idx]   # subset of benign space
    return pools


def port_class(port):
    """Encode a raw port into a coarse class to avoid the port shortcut.

    Keeping only well_known/registered/ephemeral preserves informational value
    while preventing the model from memorizing a specific port number
    [Survey §6.3 "shortcuts"; Arp et al. 2022, P4].
    """
    if port < 1024:
        return "well_known"
    if port < 49152:
        return "registered"
    return "ephemeral"


def jitter_profile(profile, rng, frac=0.35):
    """Domain randomization: return a copy with medians/means randomly scaled.

    Applied PER RUN so that attacks are not homogeneous across the dataset,
    which lets users test cross-run generalization instead of overfitting a
    single fixed configuration ["Bad Design Smells...", §6.1, Smell 1].
    """
    out = dict(profile)
    for key, value in profile.items():
        if key.endswith("_median") or key.endswith("_mean"):
            out[key] = float(value) * float(rng.uniform(1.0 - frac, 1.0 + frac))
    return out


# ===========================================================================
# 4) SAMPLING ONE CLASS
# ===========================================================================
def sample_l7_meta(name, n, rng, pools):
    """Sample the encrypted-protocol / TLS metadata columns for `n` flows."""
    mix = L7_MIX[name]
    proto_names = [p for p, _ in mix]
    proto_w = np.array([w for _, w in mix], dtype=float)
    proto_w /= proto_w.sum()
    chosen = rng.choice(proto_names, size=n, p=proto_w)

    cpool, spool = pools[name], pools["_server"]
    rows = []
    for proto in chosen:
        t = PROTOCOL_TABLE[proto]
        enc = t["enc"]
        transport = t["transport"]
        # PortScan probes span the same range nmap uses (1-4096), incl. 1-19
        # and 1025-4096 [audit 8.5].
        port = int(rng.integers(1, 4097)) if t["port"] is None else t["port"]
        if t["tls"] == "1.3":
            cipher = str(rng.choice(TLS13_CIPHERS))
        elif t["tls"] == "1.2":
            cipher = str(rng.choice(TLS12_CIPHERS))
        else:
            cipher = "none"
        # JA3/JA3S come from ssl.log in the real pipeline; QUIC is only in quic.log
        # and the common schema does NOT extract a JA3 from it. So QUIC flows must
        # carry ja3/ja3s = none to match the real side [audit 15].
        is_quic = (proto == "HTTP3-QUIC")
        ja3 = str(rng.choice(cpool)) if (enc and cpool and not is_quic) else "none"
        ja3s = str(rng.choice(spool)) if (enc and spool and not is_quic) else "none"
        if enc:
            base = 15.0 if proto == "HTTP3-QUIC" else (30.0 if t["tls"] == "1.3" else 70.0)
            handshake_ms = round(float(rng.lognormal(np.log(base), 0.4)), 2)
        else:
            handshake_ms = 0.0
        rows.append({
            "transport": transport,
            "ip_proto": 6 if transport == "TCP" else 17,
            "dst_port": port,
            "dst_port_class": port_class(port),
            "l7_protocol": proto,
            "is_encrypted": enc,
            "tls_version": t["tls"],
            "tls_cipher": cipher,
            "alpn": str(weighted_choice(rng, t["alpn"])),
            "sni_present": int(enc and rng.random() < SNI_P[name]),
            "ja3": ja3,
            "ja3s": ja3s,
            "tls_handshake_ms": handshake_ms,
        })
    return pd.DataFrame(rows)


def sample_flow_stats(name, profile, n, rng):
    """Sample the numeric flow-statistics columns for `n` flows (consistent)."""
    duration = lognormal_from_median(
        rng, profile["duration_median"], profile["duration_sigma"], n)
    # Round the duration ONCE here so the stored value and the derived rates below
    # are computed from the SAME number (self-consistent) [audit 6].
    duration = np.round(np.clip(duration, 1e-4, None), 6)

    tot_fwd = np.maximum(1, lognormal_from_median(
        rng, profile["fwd_pkts_median"], profile["fwd_pkts_sigma"], n)).astype(int)
    tot_bwd = np.maximum(0, lognormal_from_median(
        rng, profile["bwd_pkts_median"], profile["bwd_pkts_sigma"], n)).astype(int)

    fwd_size = np.clip(
        rng.normal(profile["fwd_size_mean"], profile["fwd_size_sd"], n), 20, 1500)
    bwd_size = np.clip(
        rng.normal(profile["bwd_size_mean"], profile["bwd_size_sd"], n), 0, 1500)

    totlen_fwd = (tot_fwd * fwd_size).astype(int)
    totlen_bwd = (tot_bwd * bwd_size).astype(int)
    tot_pkts = tot_fwd + tot_bwd
    tot_bytes = totlen_fwd + totlen_bwd

    flow_bytes_s = tot_bytes / duration
    flow_pkts_s = tot_pkts / duration
    flow_iat_mean = duration / np.maximum(tot_pkts, 1)
    flow_iat_std = flow_iat_mean * rng.uniform(0.2, 0.8, n)

    # One SYN per connection attempt for ALL classes. Slow-HTTP DoS is not a SYN
    # flood, so we no longer inflate SYNs for DoS [audit 3.4].
    syn_cnt = np.ones(n, dtype=int)
    ack_cnt = np.maximum(0, tot_pkts - syn_cnt)
    fin_cnt = (rng.random(n) < profile["fin_p"]).astype(int)
    rst_cnt = (rng.random(n) < profile["rst_p"]).astype(int)
    psh_cnt = np.maximum(0, (tot_fwd * rng.uniform(0.1, 0.4, n)).astype(int))

    down_up_ratio = tot_bwd / np.maximum(tot_fwd, 1)

    return pd.DataFrame({
        "flow_duration": np.round(duration, 6),
        "tot_fwd_pkts": tot_fwd,
        "tot_bwd_pkts": tot_bwd,
        "totlen_fwd_bytes": totlen_fwd,
        "totlen_bwd_bytes": totlen_bwd,
        "fwd_pkt_len_mean": np.round(fwd_size, 2),
        "bwd_pkt_len_mean": np.round(bwd_size, 2),
        "flow_bytes_s": np.round(flow_bytes_s, 2),
        "flow_pkts_s": np.round(flow_pkts_s, 2),
        "flow_iat_mean": np.round(flow_iat_mean, 6),
        "flow_iat_std": np.round(flow_iat_std, 6),
        "syn_flag_cnt": syn_cnt,
        "ack_flag_cnt": ack_cnt,
        "fin_flag_cnt": fin_cnt,
        "rst_flag_cnt": rst_cnt,
        "psh_flag_cnt": psh_cnt,
        "down_up_ratio": np.round(down_up_ratio, 4),
    })


def sample_class(name, n, rng, pools, profiles):
    """Combine TLS metadata + flow statistics for one class into a DataFrame.

    Flow-stats are sampled PER L7 protocol group so a non-TLS benign service
    (DNS/NTP/health/refused) gets its own duration/size profile instead of the
    generic web profile [audit 8]; TLS/attack protocols keep the class profile.
    """
    meta = sample_l7_meta(name, n, rng, pools)
    base_profile = profiles[name]
    stats_parts = []
    for proto, idx in meta.groupby("l7_protocol").groups.items():
        idx = list(idx)
        prof = dict(base_profile)
        prof.update(PROTO_STATS_OVERRIDE.get(proto, {}))     # {} for TLS/attack protos
        part = sample_flow_stats(name, prof, len(idx), rng)
        part.index = idx
        stats_parts.append(part)
    stats = pd.concat(stats_parts).sort_index()
    df = pd.concat([meta, stats], axis=1)
    df["label"] = name
    return df


# ===========================================================================
# 5) DATASET ASSEMBLY (multi-run, temporal, optionally imbalanced)
# ===========================================================================
def build_dataset(n_benign, n_attack_each, attacks, seed, runs=1, imbalance=False):
    """Assemble the dataset over one or more temporally ordered runs.

    Each run r is stamped with run_id=r and timestamps inside "day r", enabling
    a temporal split (train run 0..k-1, test run k) that avoids data snooping
    [Arp et al. 2022, P3; Ring et al. 2019, "Predefined Subsets"].
    """
    rng = np.random.default_rng(seed)
    pools = build_ja3_pools(rng)

    frames = []
    for r in range(runs):
        # Domain randomization for this run [Bad Design Smells, §6.1].
        run_profiles = {c: jitter_profile(p, rng) for c, p in CLASS_PROFILES.items()}

        parts = [sample_class("BENIGN", n_benign, rng, pools, run_profiles)]
        for atk in attacks:
            parts.append(sample_class(atk, n_attack_each, rng, pools, run_profiles))
        df_r = pd.concat(parts, ignore_index=True)

        # Temporal stamp: benign spans the whole day; each attack class sits in
        # a CONCENTRATED window at a random offset (realistic bursts) [audit 7].
        df_r["run_id"] = r
        day_start = BASE_TS + r * SECONDS_PER_DAY
        ts = np.empty(len(df_r), dtype=float)
        lbl = df_r["label"].values
        ben = lbl == "BENIGN"
        ts[ben] = day_start + rng.uniform(0, SECONDS_PER_DAY, int(ben.sum()))
        for atk in attacks:
            mask = lbl == atk
            n = int(mask.sum())
            if n == 0:
                continue
            dur = ATTACK_WINDOW_SEC.get(atk, 300)
            w_start = day_start + rng.uniform(0, SECONDS_PER_DAY - dur)
            ts[mask] = w_start + rng.uniform(0, dur, n)
        df_r["timestamp"] = ts.astype(int)
        frames.append(df_r)

    df = pd.concat(frames, ignore_index=True)

    # TCP flags do not apply to UDP/QUIC flows -> zero them out.
    udp = df["transport"] == "UDP"
    df.loc[udp, TCP_FLAG_COLS] = 0

    # Order by time so a temporal split is a simple row cut; keep within-run
    # class mixing by a stable sort on timestamp only.
    df = df.sort_values("timestamp", kind="mergesort").reset_index(drop=True)
    return df[COLUMN_ORDER]


def summarize(df):
    """Print a short human-readable summary and run basic sanity checks."""
    print("Rows :", len(df), "| Columns:", df.shape[1],
          "| Runs:", df["run_id"].nunique())
    print("\nLabel distribution (overall):")
    print(df["label"].value_counts())
    print("\nAttack share: {:.2f}% (real NIDS traffic is attack-minority; use "
          "PR-AUC/MCC, not accuracy) [Arp 2022 P8]".format(
              100 * (df["label"] != "BENIGN").mean()))

    enc = int(df["is_encrypted"].sum())
    print("\nEncrypted flows: {} ({:.1f}%)".format(enc, 100 * df["is_encrypted"].mean()))
    print("TLS version distribution:")
    print(df["tls_version"].value_counts())

    print("\nDistinct JA3 (client) per class (benign diverse; tools reuse few):")
    print(df.groupby("label")["ja3"].nunique())

    print("\nSanity checks:")
    print("  any NaN?        ", bool(df.isna().any().any()))
    print("  duration > 0?   ", bool((df["flow_duration"] > 0).all()))
    print("  bytes/s finite? ", bool(np.isfinite(df["flow_bytes_s"]).all()))
    print("  no src IP/TTL columns (shortcut-free)? ",
          not any(c in df.columns for c in ["src_ip", "ttl", "flow_id"]))
    print("\nTip: split TEMPORALLY by run_id/timestamp (train early, test late),"
          " never a naive shuffle/10-fold [Ring 2019; Arp 2022 P3].")



def _add_flowmeter_columns(df, rng):
    """Derive the 74 zeek-flowmeter feature columns from the flow quantities already in
    `df`, so a `common`-schema file satisfies the EXTENDED contract the real pipeline now
    emits. Values are self-consistent and in-domain -- NOT a model of real traffic; the
    split/merge tests that consume this need schema-valid rows, not realism. Any column the
    generator already produced is skipped, so no pandas '.1' duplicate is created."""
    import numpy as np
    import pandas as pd
    n = len(df)
    fwd = df["tot_fwd_pkts"].to_numpy(dtype=float)
    bwd = df["tot_bwd_pkts"].to_numpy(dtype=float)
    lfwd = df["totlen_fwd_bytes"].to_numpy(dtype=float)
    lbwd = df["totlen_bwd_bytes"].to_numpy(dtype=float)
    dur = df["flow_duration"].to_numpy(dtype=float)
    tot = np.maximum(fwd + bwd, 1)

    def pos(a):
        return np.round(np.clip(a, 0, None), 6)

    cols = {
        "fwd_pkts_tot": fwd.astype(int), "bwd_pkts_tot": bwd.astype(int),
        "fwd_data_pkts_tot": np.maximum(0, fwd - 1).astype(int),
        "bwd_data_pkts_tot": np.maximum(0, bwd - 1).astype(int),
        "fwd_pkts_per_sec": pos(fwd / np.maximum(dur, 1e-4)),
        "bwd_pkts_per_sec": pos(bwd / np.maximum(dur, 1e-4)),
        "flow_pkts_per_sec": pos(tot / np.maximum(dur, 1e-4)),
        "fwd_header_size_tot": (fwd * 20).astype(int),
        "fwd_header_size_min": np.full(n, 20, int), "fwd_header_size_max": np.full(n, 20, int),
        "bwd_header_size_tot": (bwd * 20).astype(int),
        "bwd_header_size_min": np.where(bwd > 0, 20, 0).astype(int),
        "bwd_header_size_max": np.where(bwd > 0, 20, 0).astype(int),
        "flow_FIN_flag_count": (rng.random(n) < 0.5).astype(int),
        "flow_SYN_flag_count": np.ones(n, int),
        "flow_RST_flag_count": (rng.random(n) < 0.1).astype(int),
        "fwd_PSH_flag_count": np.maximum(0, (fwd * rng.uniform(0.1, 0.3, n))).astype(int),
        "bwd_PSH_flag_count": np.maximum(0, (bwd * rng.uniform(0.1, 0.3, n))).astype(int),
        "flow_ACK_flag_count": np.maximum(0, tot - 1).astype(int),
        "fwd_pkts_payload.min": np.zeros(n, int),
        "fwd_pkts_payload.max": pos(np.where(fwd > 0, lfwd / np.maximum(fwd, 1) * 1.5, 0)),
        "fwd_pkts_payload.tot": lfwd.astype(int),
        "fwd_pkts_payload.avg": pos(lfwd / np.maximum(fwd, 1)),
        "fwd_pkts_payload.std": pos(lfwd / np.maximum(fwd, 1) * rng.uniform(0.1, 0.5, n)),
        "bwd_pkts_payload.min": np.zeros(n, int),
        "bwd_pkts_payload.max": pos(np.where(bwd > 0, lbwd / np.maximum(bwd, 1) * 1.5, 0)),
        "bwd_pkts_payload.tot": lbwd.astype(int),
        "bwd_pkts_payload.avg": pos(lbwd / np.maximum(bwd, 1)),
        "bwd_pkts_payload.std": pos(lbwd / np.maximum(bwd, 1) * rng.uniform(0.1, 0.5, n)),
        "flow_pkts_payload.min": np.zeros(n, int),
        "flow_pkts_payload.max": pos((lfwd + lbwd) / tot * 1.5),
        "flow_pkts_payload.tot": (lfwd + lbwd).astype(int),
        "flow_pkts_payload.avg": pos((lfwd + lbwd) / tot),
        "flow_pkts_payload.std": pos((lfwd + lbwd) / tot * rng.uniform(0.1, 0.5, n)),
    }
    for pre, cnt in (("fwd_iat", fwd), ("bwd_iat", bwd), ("flow_iat", tot)):
        avg = dur / np.maximum(cnt, 1)
        cols[pre + ".min"] = pos(avg * rng.uniform(0.1, 0.5, n))
        cols[pre + ".max"] = pos(avg * rng.uniform(1.5, 3.0, n))
        cols[pre + ".avg"] = pos(avg)
        cols[pre + ".tot"] = pos(dur)
        cols[pre + ".std"] = pos(avg * rng.uniform(0.2, 0.8, n))
    cols["payload_bytes_per_second"] = pos((lfwd + lbwd) / np.maximum(dur, 1e-4))
    cols["fwd_subflow_pkts"] = fwd.astype(int)
    cols["bwd_subflow_pkts"] = bwd.astype(int)
    cols["fwd_subflow_bytes"] = lfwd.astype(int)
    cols["bwd_subflow_bytes"] = lbwd.astype(int)
    for c in ("fwd_bulk_bytes", "bwd_bulk_bytes", "fwd_bulk_packets", "bwd_bulk_packets",
              "fwd_bulk_rate", "bwd_bulk_rate"):
        cols[c] = np.zeros(n, int)
    for pre in ("active", "idle"):
        base = dur * rng.uniform(0.1, 0.4, n) if pre == "active" else dur * rng.uniform(0.0, 0.2, n)
        cols[pre + ".min"] = pos(base * 0.5)
        cols[pre + ".max"] = pos(base * 1.5)
        cols[pre + ".tot"] = pos(base)
        cols[pre + ".avg"] = pos(base)
        cols[pre + ".std"] = pos(base * rng.uniform(0.1, 0.5, n))
    cols["fwd_init_window_size"] = np.full(n, 64240, int)
    cols["bwd_init_window_size"] = np.where(bwd > 0, 65535, 0).astype(int)
    cols["fwd_last_window_size"] = np.full(n, 501, int)
    cols["bwd_last_window_size"] = np.where(bwd > 0, 501, 0).astype(int)

    ren = {k: k.replace(".", "_") for k in cols}
    existing = set(df.columns)
    add = pd.DataFrame({ren[k]: v for k, v in cols.items() if ren[k] not in existing},
                       index=df.index)
    return pd.concat([df, add], axis=1)


def main():
    parser = argparse.ArgumentParser(
        description="Synthetic NIDS dataset generator (encrypted, best-practice) ({}).".format(
            CODE_VERSION))
    parser.add_argument("--benign", type=int, default=10000,
                        help="benign flows PER RUN (default: 10000)")
    parser.add_argument("--attack-each", type=int, default=3000,
                        help="flows PER attack class PER RUN (default: 3000)")
    parser.add_argument("--attacks", nargs="+", default=ATTACK_CLASSES,
                        choices=ATTACK_CLASSES, help="attack classes to include")
    parser.add_argument("--runs", type=int, default=1,
                        help="number of temporally ordered runs (default: 1)")
    parser.add_argument("--imbalance", action="store_true",
                        help="make attacks a realistic minority (~5%% of benign)")
    parser.add_argument("--profile", choices=["testbed", "broad"], default="testbed",
                        help="protocol mix: 'testbed' (TLS 1.3 only, matches "
                             "Caddy/tools) or 'broad' (also TLS 1.2 / plain HTTP)")
    parser.add_argument("--schema", choices=["common", "extended"], default="common",
                        help="'common' (default): only the features the REAL Zeek "
                             "pipeline can produce (feature_schema.COMMON) — required "
                             "for real-vs-synthetic experiments. 'extended': all "
                             "synthetic-only features too (NOT applicable to real).")
    parser.add_argument("--seed", type=int, default=42, help="random seed")
    parser.add_argument("--out", default="synthetic_nids_dataset.csv",
                        help="output CSV path")
    args = parser.parse_args()
    if args.runs < 1 or args.benign < 0 or args.attack_each < 0:
        parser.error("--runs must be >=1 and --benign/--attack-each >= 0")

    global L7_MIX                                   # select the protocol profile
    L7_MIX = L7_MIX_BROAD if args.profile == "broad" else L7_MIX_TESTBED

    attack_each = args.attack_each
    if args.imbalance:
        # Realistic base rate: attacks together ~5% of benign [Survey §6.2.1].
        attack_each = max(1, int(args.benign * 0.05 / len(args.attacks)))

    df = build_dataset(args.benign, attack_each, args.attacks,
                       args.seed, runs=args.runs, imbalance=args.imbalance)
    bad = fs.unknown_labels(df["label"])            # enforce the shared vocabulary [audit 8]
    if bad:
        raise SystemExit("ABORT: generator produced unknown label(s) {} not in {} "
                         "[audit 8]".format(bad, sorted(fs.ALLOWED_LABELS)))
    summarize(df)                                   # summary on the FULL feature set
    if args.schema == "common":
        # Keep what the real pipeline now produces (COMMON + flowmeter), + split
        # metadata + label. Flowmeter columns are DERIVED from the sampled flow
        # quantities so the file satisfies the EXTENDED contract the labeler emits.
        import numpy as _np
        df = _add_flowmeter_columns(df, _np.random.default_rng(args.seed + 777))
        keep = ["run_id", "timestamp"] + fs.EXTENDED + ["label"]
        df = df[[c for c in keep if c in df.columns]]
    # The generator must satisfy the SAME COMMON contract as the real pipeline, so a
    # synthetic file can never ship impossible values (fractional counts, inconsistent
    # derived rates) that the merge/validator would later reject [audit 4].
    c_err, c_warn = fs.common_contract_violations(df)
    for w in c_warn:
        print("WARNING (contract):", w)
    if c_err:
        raise SystemExit("ABORT: generated data violates the COMMON contract {} "
                         "[audit 4]".format(c_err))
    df.to_csv(args.out, index=False)
    sha = write_metadata(args.out, args, df)                 # auto provenance [audit 19]
    print("Saved:", args.out, "(schema={})".format(args.schema))
    print("Metadata:", args.out.replace(".csv", "") + ".metadata.json", "(sha256", sha[:12] + "...)")


if __name__ == "__main__":
    main()
