#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
attack_scenarios.py — the shared attack-configuration matrix [audit 5].

Moved out of run_attacks.py so BOTH the orchestrator (which runs a scenario) and
campaign.py (which VALIDATES a manifest's config_id / reserved-test set) read the
SAME source of truth. Each config is a DISTINCT tool setting; the last two are
reserved for the TEST set (unseen configs), so "generalizes to unseen attack
configurations" is demonstrable.
"""

from versions import SCENARIO_VERSION      # ONE source of truth for versions [audit v20.5 §11]

CONFIG_MATRIX = [
    dict(ps_hi=1024, ps_timing="-T3", ps_mode="syn",     bf_tasks=4,  dos_conns=500,  dos_rate=50),
    dict(ps_hi=2048, ps_timing="-T4", ps_mode="connect", bf_tasks=8,  dos_conns=1000, dos_rate=100),
    dict(ps_hi=4096, ps_timing="-T3", ps_mode="syn",     bf_tasks=16, dos_conns=2000, dos_rate=200),
    dict(ps_hi=1024, ps_timing="-T4", ps_mode="connect", bf_tasks=16, dos_conns=1000, dos_rate=50),
    dict(ps_hi=2048, ps_timing="-T3", ps_mode="syn",     bf_tasks=4,  dos_conns=2000, dos_rate=100),
    dict(ps_hi=4096, ps_timing="-T4", ps_mode="connect", bf_tasks=8,  dos_conns=500,  dos_rate=200),
    dict(ps_hi=3072, ps_timing="-T2", ps_mode="syn",     bf_tasks=12, dos_conns=1500, dos_rate=150),
    dict(ps_hi=1500, ps_timing="-T5", ps_mode="connect", bf_tasks=6,  dos_conns=800,  dos_rate=75),
]
# Reserve the last two configs for the TEST set (unseen tool settings) [audit 9].
TEST_RESERVED_CONFIGS = {6, 7}


def expected_annotation_semantics(config_id, attack):
    """The protocol / target_port / tool an annotation MUST declare for `attack` under `config_id`,
    derived from CONFIG_MATRIX and the orchestrator's OWN builders (build_portscan/bruteforce/dos).
    The labeler validates the ground truth against THIS plan, not the annotation's forgeable
    self-claim — so a PortScan that declares range=443 (to fake 100% coverage of the planned
    1-1024 range) or a BruteForce on port 9999 is rejected [audit v20.8 P0-7/P0-8]. Returns a dict
    {protocol, tool, target_port} or None for an unknown attack."""
    cfg = CONFIG_MATRIX[config_id]
    if attack == "PortScan":                                    # nmap over the WHOLE planned range
        return {"protocol": "tcp", "tool": "nmap", "target_port": "1-{}".format(cfg["ps_hi"])}
    if attack == "BruteForce":                                  # hydra against the HTTPS login
        return {"protocol": "tcp", "tool": "hydra", "target_port": "443"}
    if attack == "DoS":                                         # H3 GET flood over QUIC
        return {"protocol": "udp", "tool": "python3", "target_port": "443"}
    return None


def expected_scenario_params(config_id, attack, run_spec):
    """The FULL planned scenario PARAMETERS as the {key: value-string} dict the orchestrator stamps
    into an annotation's `parameters` field, derived from CONFIG_MATRIX (+ run_spec for the per-run
    dos_seconds). The labeler requires the annotation's PARSED `parameters` to EQUAL this, so a
    DoS annotated with conns=1/rate=1/dur=1 while the config plans 500/50/120s, or a PortScan whose
    mode/timing was swapped, is rejected — not just the protocol/port/tool [audit v20.8 P0-8/P0-9].
    The keys/values mirror run_attacks.build_* exactly. Returns a dict of STRINGS, or None."""
    cfg = CONFIG_MATRIX[config_id]
    p = {"config": str(config_id)}
    if attack == "PortScan":
        p.update(mode=str(cfg["ps_mode"]), timing=str(cfg["ps_timing"]),
                 range="1-{}".format(cfg["ps_hi"]))
    elif attack == "BruteForce":
        p.update(tasks=str(cfg["bf_tasks"]), form="wp-login")
    elif attack == "DoS":
        p.update(workers=str(cfg["dos_conns"]), rate=str(cfg["dos_rate"]),
                 dur=str((run_spec or {}).get("dos_seconds")), endpoint="search")
    else:
        return None
    return p


# The exact hydra login-form argv token the orchestrator emits (build_bruteforce), kept here so the
# labeler validates the ACTUAL command against the SAME literal the orchestrator ran [audit v20.9].
BRUTEFORCE_FORM = "/wp-login.php:log=^USER^&pwd=^PASS^:F=Invalid"


def expected_command_argv(config_id, attack, run_spec, target_ip, target_host):
    """The EXACT tool argv the orchestrator's build_* produces for this attack under `config_id` and
    the (already manifest-pinned) target. The labeler compares the recorded `command` argv to this
    ELEMENT-FOR-ELEMENT, so — unlike the earlier "is some correct token present?" check — a command
    with DUPLICATED flags (`-c 500 -c 1`), EXTRA/foreign args (`-u https://evil/`, `-t POST`), a
    CONFLICTING mode/timing, a target the manifest never pinned (`nmap ... 192.0.2.99`), or a wrong
    `-S` host is rejected [audit v20.10 P0]. Returns (argv, wildcard_idx): `wildcard_idx` are the
    positions whose VALUE the labeler cannot know — only the BruteForce `-L`/`-P` wordlist PATHS,
    which just run_attacks can bind; every OTHER position must match exactly. None for an unknown
    attack. Mirrors run_attacks.build_portscan/bruteforce/dos EXACTLY (incl. the `host or ip` host
    precedence for the slow-HTTP URL and the hydra `-S` target)."""
    cfg = CONFIG_MATRIX[config_id]
    host = (str(target_host or "").strip() or str(target_ip or "").strip())   # build_* precedence
    ip = str(target_ip or "").strip()
    if attack == "PortScan":                          # ["nmap", flag, timing, "-p", "1-hi", ip]
        flag = "-sS" if cfg["ps_mode"] == "syn" else "-sT"
        argv = ["nmap", flag, str(cfg["ps_timing"])]
        if cfg["ps_mode"] == "syn":                       # mirror build_portscan: SYN is paced
            argv += ["--max-rate", "300"]
        argv += ["-p", "1-{}".format(cfg["ps_hi"]), ip]
        return (argv, frozenset())
    if attack == "BruteForce":                        # -L/-P paths are the attacker's, hence wild
        return (["hydra", "-L", None, "-P", None, "-t", str(cfg["bf_tasks"]), "-s", "443",
                 "-S", host, "https-post-form", BRUTEFORCE_FORM], frozenset({2, 4}))
    if attack == "DoS":
        return (["python3", None, "--url", "https://{}/?s=load".format(host),
                 "--workers", str(cfg["dos_conns"]),
                 "--seconds", str((run_spec or {}).get("dos_seconds")),
                 "--rate", str(cfg["dos_rate"])], frozenset({1}))
    return None
