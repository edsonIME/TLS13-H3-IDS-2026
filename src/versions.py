#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
versions.py — ONE source of truth for producer/schema versions [audit v20.5 §11/§15].

Before this module the labeler hard-coded the accepted scenario/orchestrator strings and the
status schema id, so the labeler and the downstream consumers could disagree and a semantic
change could ship under an unchanged version. Every version now lives here; the scenario
generator, the attack orchestrator, the labeler and the provenance consumers all import from
this file, so a bump is made in exactly one place.

This module has NO imports on purpose (it is a leaf), so anything may import it without a cycle.
"""

# --- producer versions (the exact strings written into ground truth / status) ---------------
# These four are the CURRENT canonical values; the full per-bump rationale lives in docs/CORRECTIONS.md
# (one section per round) so this file stays a clean single source of truth without stale claims.
SCENARIO_VERSION = "scenarios/v4"   # v4 = DoS over HTTP/3 (QUIC/UDP), honours dos_rate
_SCENARIO_V3_NOTE = "scenarios/v3"          # attack_scenarios.py stamps this on every annotation
ORCHESTRATOR_VERSION = "run_attacks/v9"   # v9 = build_dos invokes h3_flood.py with --rate
_ORCHESTRATOR_V8_NOTE = "run_attacks/v8"    # run_attacks.py stamps this on every annotation; v6 added
                                           # the structured `command_argv` column [audit v20.12 §8]
LABELER_CODE_VERSION = "label_flows/v32"   # v32 = joins flowmeter.log by uid and publishes
                                           # the 74 flowmeter features as fs.EXTENDED; TCP-only
                                           # measures are NaN on non-TCP flows, never 0. A
                                           # behaviour change MUST bump the producer version.
_LABELER_V31_NOTE = "label_flows/v31"   # label_flows.py; v30 = accepts an EXTERNAL --attempt-id and
                                           # records IT as status.attempt_id (was always a fresh uuid) so the
                                           # orchestrator can bind one attempt across all producers [audit
                                           # v20.43 §13 — a behaviour change MUST bump the producer version];
                                           # v29 = campaign PIN of the temporal policy is ENFORCED (CLI must
                                           # match required_min_window_overlap; adopts/tightens
                                           # max_duration_fallback_rate) [audit v20.21/22 §9/§11]
STATUS_SCHEMA_VERSION = "status/v5"        # v5 = the window-matching fields (min_window_overlap /
                                           # overlap_accounting) are REQUIRED and validated, tied to the
                                           # events, with a degenerate-fallback invariant [audit v20.22 §5-9]

# --- the sets the OFFICIAL consumers accept (a status/annotation outside these is not official) -
SUPPORTED_SCENARIO_VERSIONS = frozenset({SCENARIO_VERSION})
SUPPORTED_ORCHESTRATOR_VERSIONS = frozenset({ORCHESTRATOR_VERSION})
SUPPORTED_LABELER_VERSIONS = frozenset({LABELER_CODE_VERSION})
SUPPORTED_STATUS_SCHEMAS = frozenset({STATUS_SCHEMA_VERSION})
