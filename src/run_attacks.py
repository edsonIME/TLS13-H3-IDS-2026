#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_attacks.py  (orchestrator version: ORCHESTRATOR_VERSION in versions.py — robust
fail-closed ground truth)
==================================================================================

Attack ORCHESTRATOR for an isolated NIDS testbed. Runs synthetic attacks ONLY
against your own lab victims and writes a rich ground-truth annotation file. The
version this tool STAMPS on every annotation is the single-source-of-truth
`versions.ORCHESTRATOR_VERSION` — this header restates NO number, so it can never
drift from it [audit v20.15 doc/impl consistency].

KEY GUARANTEES (addressing the audit)
-------------------------------------
  * A missing tool no longer crashes the run: run_capture() catches
    FileNotFoundError / OSError / TimeoutExpired and records status="failed"
    with an error_type [audit 4]. A per-attack --timeout is enforced.
  * The target guard validates BOTH --target-ip and --target-host: the hostname
    is resolved and the IP must match one of the resolved (and allowed) IPs, so
    a mismatched host/ip pair is refused [audit 12].

The match key later used by label_flows is 4-tuple (proto + src IP + dst IP +
dst port) + time window, with the source port wildcard (tools open many
ephemeral source ports). See label_flows.py.

SAFETY: closed lab only. Never point it at systems you do not own.
Requires (attacker VM): nmap, hydra, slowhttptest.
"""

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import shlex
import socket
import subprocess
import sys
import uuid
from datetime import datetime, timezone


ALLOWED_TARGETS = {"10.10.10.11"}                 # EDIT to your lab victim(s)
LAB_SUBNET = ipaddress.ip_network("10.10.10.0/24")

from versions import ORCHESTRATOR_VERSION  # ONE source of truth for versions [audit v20.5 §11]
# Campaign identity is recorded per event so an annotation can be proven to belong
# to the manifest used downstream [audit 17].
# `command_argv` is the STRUCTURED, lossless representation of the exact argv (a JSON list) — the
# primary evidence. `command` (space-joined) stays for humans but is ambiguous for paths with
# spaces, so the labeler compares against command_argv when present [audit v20.11 §11].
ANNOTATION_FIELDS = ["event_id", "run_id", "label", "attacker_ip", "target_ip",
                     "target_hostname", "protocol", "target_port", "start_utc",
                     "end_utc", "tool", "command", "command_argv", "parameters", "return_code",
                     "status", "error_type", "campaign_id", "campaign_sha256",
                     "config_id", "split", "scenario_version", "orchestrator_version"]


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def resolve_host(host):
    """Return all IPv4 addresses a hostname resolves to (via the lab DNS)."""
    infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
    return sorted({ai[4][0] for ai in infos})


def guard(target_ip, target_host):
    """Validate BOTH host and IP; require them consistent and allowed [audit 12]."""
    resolved = []
    if target_host:
        try:
            resolved = resolve_host(target_host)
        except socket.gaierror:
            sys.exit("REFUSED: cannot resolve host {} (is the lab DNS up?)".format(target_host))
        bad = [ip for ip in resolved if ip not in ALLOWED_TARGETS]
        if bad:
            sys.exit("REFUSED: {} resolves to non-allowed IP(s) {}".format(target_host, bad))
    if target_ip:
        if target_ip not in ALLOWED_TARGETS or ipaddress.ip_address(target_ip) not in LAB_SUBNET:
            sys.exit("REFUSED: --target-ip {} is not an allowed lab target.".format(target_ip))
        if resolved and target_ip not in resolved:
            sys.exit("REFUSED: --target-ip {} does not match {} -> {}".format(
                target_ip, target_host, resolved))
        return target_ip
    if not resolved:
        sys.exit("Provide --target-host and/or --target-ip.")
    return resolved[0]


def local_ip(target_ip):
    """The local source IP the OS would use to reach target_ip, or None if it cannot be
    determined (no route). The campaign attacker_ip check treats None as a mismatch, so a host
    that can't even route to the victim never writes ground truth [audit v20.8 P0-10]."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, 9))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def run_capture(cmd, log_path, timeout):
    """Run a command; return (return_code, error_type). Never raises."""
    print("    $", " ".join(str(c) for c in cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return 127, "FileNotFoundError"
    except subprocess.TimeoutExpired:
        with open(log_path, "w", encoding="utf-8") as fh:
            fh.write("TIMEOUT after {}s\nCMD: {}\n".format(timeout, " ".join(cmd)))
        return 124, "TimeoutExpired"
    except OSError as exc:
        return 126, type(exc).__name__
    with open(log_path, "w", encoding="utf-8") as fh:
        fh.write("CMD: {}\n\n--- STDOUT ---\n{}\n--- STDERR ---\n{}\n".format(
            " ".join(cmd), proc.stdout, proc.stderr))
    return proc.returncode, ""


# The scenario matrix lives in a SHARED module so campaign.py validates the same
# config_ids the orchestrator runs [audit 5/9].
from attack_scenarios import CONFIG_MATRIX, TEST_RESERVED_CONFIGS, SCENARIO_VERSION


def _sha256_file(path):
    """SHA-256 of a file, or None if unreadable — used to pin wordlists to the
    campaign so the BruteForce password space matches the plan [audit 10]."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def build_portscan(ip, host, sc):
    hi, timing, mode = sc["ps_hi"], sc["ps_timing"], sc["ps_mode"]
    flag = "-sS" if mode == "syn" else "-sT"          # SYN vs connect scan
    argv = ["nmap", flag, timing]
    if mode == "syn":                                 # pace SYN so the SPAN mirror keeps up
        argv += ["--max-rate", "300"]
    argv += ["-p", "1-{}".format(hi), ip]
    return (argv,
            "TCP", "1-{}".format(hi),
            "config={};mode={};timing={};range=1-{}".format(sc["config_id"], mode, timing, hi))


def build_bruteforce(ip, host, sc, userlist, passlist):
    tasks = sc["bf_tasks"]
    form = "/wp-login.php:log=^USER^&pwd=^PASS^:F=Invalid"
    return (["hydra", "-L", userlist, "-P", passlist, "-t", str(tasks),
             "-s", "443", "-S", host or ip, "https-post-form", form],
            "TCP", "443", "config={};tasks={};form=wp-login".format(sc["config_id"], tasks))


def build_dos(ip, host, sc, seconds, proto="UDP"):
    workers = sc["dos_conns"]
    rate = sc["dos_rate"]
    url = "https://{}/?s=load".format(host or ip)
    
    if proto == "UDP":
        # v2: DoS runs over HTTP/3 (QUIC/UDP) via h3_flood.py, honouring the config's dos_rate
        flooder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "h3_flood.py")
        cmd = ["python3", flooder, "--url", url, "--workers", str(workers),
               "--seconds", str(seconds), "--rate", str(rate)]
    else:  # TCP
        # Utilizando slowhttptest conforme as dependências do ambiente
        cmd = ["slowhttptest", "-c", str(workers), "-r", str(rate), "-l", str(seconds), "-u", url]
        
    return (cmd,
            proto, "443",
            "config={};workers={};dur={};rate={};endpoint=search;proto={}".format(
                sc["config_id"], workers, seconds, rate, proto))


BUILDERS = {
    "PortScan": lambda ip, host, a, sc: build_portscan(ip, host, sc),
    "BruteForce": lambda ip, host, a, sc: build_bruteforce(ip, host, sc, a.userlist, a.passlist),
    "DoS": lambda ip, host, a, sc: build_dos(ip, host, sc, a.dos_seconds, proto="UDP"),
    "DoS_TCP": lambda ip, host, a, sc: build_dos(ip, host, sc, a.dos_seconds, proto="TCP"),
}


def main():
    ap = argparse.ArgumentParser(description="Lab attack orchestrator (robust fail-closed).")
    # These default to None so campaign mode can tell "user did not pass it" (derive
    # from the manifest) apart from "user passed a value" (must equal the plan) [audit 10].
    ap.add_argument("--target-host", default=None, help="default blog.lab, or the "
                    "campaign plan for this run [audit 10]")
    ap.add_argument("--target-ip", default=None)
    ap.add_argument("--attacks", nargs="+", default=None, choices=list(BUILDERS),
                    help="attacks to run (default: all, or the campaign plan) [audit 10]")
    ap.add_argument("--userlist", default="users.txt")
    ap.add_argument("--passlist", default="10k-most-common.txt")
    ap.add_argument("--dos-seconds", type=int, default=None, help="default 120, or the "
                    "campaign plan [audit 10]")
    ap.add_argument("--timeout", type=int, default=None,
                    help="per-attack timeout (s); default 900, or the campaign plan [audit 10]")
    ap.add_argument("--run-id", type=int, default=0)
    ap.add_argument("--config-id", type=int, default=None,
                    help="index into the scenario CONFIG_MATRIX (default: --run-id). "
                         "Each config is a DISTINCT tool setting; {} are reserved for "
                         "the TEST set (unseen configs) [audit 9]".format(
                             sorted(TEST_RESERVED_CONFIGS)))
    ap.add_argument("--list-configs", action="store_true",
                    help="print the scenario matrix and exit [audit 9]")
    ap.add_argument("--campaign", default=None,
                    help="campaign manifest (campaign.py): looks up THIS run's config_id "
                         "and split, so the run/config/split assignment is centralized "
                         "and reserved-test configs never leak into training [audit 11/12]")
    ap.add_argument("--annotations", default=None,
                    help="ground-truth file (default: annotations_run<run-id>.csv, "
                         "so runs never share one file) [audit 2]")
    ap.add_argument("--logdir", default="attack_logs")
    ap.add_argument("--overwrite-annotations", action="store_true",
                    help="truncate the per-run annotations file before writing, so a "
                         "REPEATED run does not keep stale events from a failed attempt "
                         "(which would later match zero flows and abort labeling) [audit 18]")
    ap.add_argument("--append-annotations", action="store_true",
                    help="append to an EXISTING per-run annotations file. By default an "
                         "existing file ABORTS: appending across attempts mixes stale "
                         "events from a different PCAP, so a repeat must be explicit — "
                         "--overwrite-annotations to restart, or this to add [audit 11]")
    ap.add_argument("--allow-partial-attacks", action="store_true",
                    help="exit 0 even if some attacks failed (default: exit 2 if ANY "
                         "requested attack did not succeed) [audit 6]")
    ap.add_argument("--require-reproducible-campaign", action="store_true",
                    help="(now the DEFAULT with --campaign) require a faithful, reproducible "
                         "manifest [audit 11]")
    ap.add_argument("--allow-incomplete-campaign", action="store_true",
                    help="opt OUT of the reproducible-manifest requirement that --campaign now "
                         "enforces by default — dev only [audit v20.6 §9]")
    args = ap.parse_args()
    if args.list_configs:
        for i, sc in enumerate(CONFIG_MATRIX):
            print("config {}{}: {}".format(i, " (TEST-reserved)"
                  if i in TEST_RESERVED_CONFIGS else "", sc))
        return
    if args.run_id < 0:
        sys.exit("ABORT: --run-id must be >= 0.")
    if args.dos_seconds is not None and args.dos_seconds <= 0:
        sys.exit("ABORT: --dos-seconds must be > 0.")
    if args.timeout is not None and args.timeout <= 0:
        sys.exit("ABORT: --timeout must be > 0.")
    # Pick the DETERMINISTIC, distinct scenario for this run [audit 9]. With a
    # campaign the MANIFEST is the source of truth — it OVERRIDES the CLI, and a
    # CLI --config-id may only CONFIRM the manifest value, never change it, so a
    # reserved-test config cannot be forced into a train run [audit 6].
    if args.campaign:
        import campaign as camp
        # --campaign now DEFAULTS to a reproducible manifest [audit v20.6 §9].
        manifest = camp.load(args.campaign,
                             require_reproducible=not args.allow_incomplete_campaign)
        m_cfg = camp.config_of_run(manifest, args.run_id)
        if m_cfg is None:
            sys.exit("ABORT: run_id {} is not in the campaign manifest. [audit 6]".format(args.run_id))
        if args.config_id is not None and args.config_id != m_cfg:
            sys.exit("ABORT: --config-id {} contradicts the campaign (run {} -> config "
                     "{}); the manifest is the source of truth. [audit 6]".format(
                         args.config_id, args.run_id, m_cfg))
        config_id = m_cfg
        campaign_id = manifest.get("campaign_id")
        campaign_split = camp.split_of_run(manifest, args.run_id)
        with open(args.campaign, "rb") as _cf:
            campaign_sha = hashlib.sha256(_cf.read()).hexdigest()
        print("Campaign: run {} -> config {} (split {})".format(
            args.run_id, config_id, campaign_split))
    else:
        config_id = args.config_id if args.config_id is not None else args.run_id
        campaign_id = campaign_split = campaign_sha = ""
    if config_id < 0:
        sys.exit("ABORT: --config-id must be >= 0.")
    if config_id >= len(CONFIG_MATRIX):
        # No silent modulo-wrap in campaign mode: a manifest that declares config 99
        # must NOT run some other physical config [audit 6].
        if args.campaign:
            sys.exit("ABORT: campaign config_id {} is outside the CONFIG_MATRIX (size "
                     "{}); add the scenario — no wrap in campaign mode. [audit 6]".format(
                         config_id, len(CONFIG_MATRIX)))
        print("WARNING: config_id {} >= {} scenarios; it WRAPS and repeats an earlier "
              "config — add scenarios to CONFIG_MATRIX for truly unseen runs. [audit 9]".format(
                  config_id, len(CONFIG_MATRIX)))
    scenario = dict(CONFIG_MATRIX[config_id % len(CONFIG_MATRIX)])
    scenario["config_id"] = config_id

    # --- ATTACK PLAN. In campaign mode the manifest may PIN this run's attacks /
    # target / dos-seconds / timeout and the wordlist digests; the CLI may only
    # CONFIRM those values, and the wordlist files must hash to the declared digests,
    # so a run cannot silently deviate from the planned campaign [audit 10]. Resolved
    # values are written back to `args` so the builders/guard use them unchanged.
    run_spec = ((manifest.get("runs") or {}).get(str(args.run_id), {})
                if args.campaign else {})

    def _plan(field, cli_val, default):
        planned = run_spec.get(field)
        if planned is None:
            return cli_val if cli_val is not None else default
        if cli_val is not None and cli_val != planned:
            sys.exit("ABORT: --{} {!r} contradicts the campaign plan {!r} for run {}; the "
                     "manifest is the source of truth. [audit 10]".format(
                         field.replace("_", "-"), cli_val, planned, args.run_id))
        return planned

    planned_attacks = run_spec.get("attacks")
    if planned_attacks is not None:
        if (not isinstance(planned_attacks, list) or not planned_attacks
                or any(a not in BUILDERS for a in planned_attacks)):
            sys.exit("ABORT: campaign run {} 'attacks' {} is empty or has an unknown "
                     "attack (known: {}). [audit 10]".format(
                         args.run_id, planned_attacks, list(BUILDERS)))
        if args.attacks is not None and sorted(args.attacks) != sorted(planned_attacks):
            sys.exit("ABORT: --attacks {} contradicts the campaign plan {} for run {}. "
                     "[audit 10]".format(sorted(args.attacks), sorted(planned_attacks),
                                         args.run_id))
        args.attacks = list(planned_attacks)
    elif args.attacks is None:
        args.attacks = list(BUILDERS)

    args.target_host = _plan("target_host", args.target_host, "blog.lab")
    args.target_ip = _plan("target_ip", args.target_ip, None)
    args.dos_seconds = _plan("dos_seconds", args.dos_seconds, 120)
    args.timeout = _plan("timeout", args.timeout, 900)
    if args.dos_seconds <= 0 or args.timeout <= 0:
        sys.exit("ABORT: dos-seconds/timeout must be > 0 (check the campaign plan). [audit 10]")

    # Wordlist integrity: if the campaign pins a digest, the ACTUAL file must match, so
    # the BruteForce password space is exactly the one the campaign declared [audit 10].
    for field, path, name in (("userlist_sha256", args.userlist, "userlist"),
                              ("passlist_sha256", args.passlist, "passlist")):
        want = run_spec.get(field)
        if want is not None:
            got = _sha256_file(path)
            if got != want:
                sys.exit("ABORT: {} '{}' sha256 {}... != campaign {}... for run {}; the "
                         "wordlist is not the one the campaign pinned. [audit 10]".format(
                             name, path, str(got)[:12], str(want)[:12], args.run_id))

    # One annotation file PER run so label_flows never sees mixed run_ids [audit 2].
    ann_path = args.annotations or "annotations_run{}.csv".format(args.run_id)
    # A repeated run should start from a CLEAN annotations file [audit 18]. By default an
    # EXISTING file aborts (appending across attempts mixes events from another PCAP);
    # --overwrite-annotations restarts and --append-annotations opts into appending [audit 11].
    if args.overwrite_annotations and os.path.exists(ann_path):
        os.remove(ann_path)
    elif (os.path.exists(ann_path) and os.path.getsize(ann_path) > 0
          and not args.append_annotations):
        sys.exit("ABORT: annotations file '{}' already exists. A repeat run mixing events "
                 "from a different capture is almost never intended: pass "
                 "--overwrite-annotations to restart it, or --append-annotations to add to "
                 "it deliberately. [audit 11]".format(ann_path))
    # Treat an absent OR empty file as new (so we always write the header); a
    # pre-created empty file must not leave the first data row acting as the CSV
    # header downstream [audit 3].
    new_file = (not os.path.exists(ann_path)) or os.path.getsize(ann_path) == 0
    if not new_file:
        with open(ann_path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames != ANNOTATION_FIELDS:      # wrong/edited header [audit 3]
                sys.exit("ABORT: {} has an unexpected header {} (expected {}). Refusing "
                         "to append to a mismatched file. [audit 3]".format(
                             ann_path, reader.fieldnames, ANNOTATION_FIELDS))
            # Existing rows must belong to the SAME run AND the SAME campaign/config/
            # split — otherwise one ground-truth file would mix campaigns [audit 5].
            campaign_fields = (("campaign_id", str(campaign_id or "")),
                               ("campaign_sha256", str(campaign_sha or "")),
                               ("config_id", str(config_id)),
                               ("split", str(campaign_split or "")),
                               ("scenario_version", SCENARIO_VERSION))
            for r in reader:
                if (r.get("run_id") or "").strip() != str(args.run_id):
                    sys.exit("ABORT: {} already has run_id={} != --run-id={}. Use a "
                             "per-run file. [audit 2]".format(
                                 ann_path, r.get("run_id"), args.run_id))
                for fld, cur in campaign_fields:
                    if (r.get(fld) or "").strip() != cur:
                        sys.exit("ABORT: {} already has {}={!r} != current {!r}. Do not "
                                 "mix campaigns/configs/splits in one annotations file "
                                 "(use --overwrite-annotations to restart). [audit 5]".format(
                                     ann_path, fld, r.get(fld), cur))

    ip = guard(args.target_ip, args.target_host)
    hostname = args.target_host or ""
    src = local_ip(ip)
    # In campaign mode the LOCAL source IP must EQUAL the run's planned attacker_ip, so a capture
    # made from the wrong host is refused BEFORE nmap/hydra/slowhttptest run and writes ground
    # truth [audit v20.8 P0-10].
    if args.campaign:
        planned_attacker = str((manifest.get("runs") or {}).get(str(args.run_id), {})
                               .get("attacker_ip") or "")
        if planned_attacker and str(src) != planned_attacker:
            sys.exit("ABORT: local source IP {} != campaign attacker_ip {} for run {} — run this "
                     "from the PLANNED attacker host. [audit v20.8 P0-10]".format(
                         src, planned_attacker, args.run_id))
    os.makedirs(args.logdir, exist_ok=True)
    print("Attacker {} -> {} ({}) | run_id={} | config_id={}{}".format(
        src, ip, hostname, args.run_id, config_id,
        " (TEST-reserved config)" if config_id in TEST_RESERVED_CONFIGS else ""))

    n_requested = n_succeeded = n_failed = 0
    with open(ann_path, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=ANNOTATION_FIELDS)
        if new_file:
            writer.writeheader()
        for name in args.attacks:
            n_requested += 1
            cmd, proto, port, params = BUILDERS[name](ip, hostname, args, scenario)
            event_id = uuid.uuid4().hex[:12]
            log_path = os.path.join(args.logdir, "event_{}.log".format(event_id))

            start = utcnow()
            print("[{}] {} ({}/{}) -> {}".format(start, name, proto, port, ip))
            rc, error_type = run_capture(cmd, log_path, args.timeout)
            end = utcnow()
            # NOTE [audit 13]: status is TOOL-LEVEL only — rc==0 proves the tool RAN.
            # Both traffic_observed and effect_confirmed are rigorously verified downstream
            # (by label_flows and the service_monitor effect gate, respectively).
            status = "success" if rc == 0 and not error_type else "failed"
            n_succeeded += status == "success"
            n_failed += status == "failed"
            
            # Normaliza o nome do ataque removendo sufixos para adequar ao schema
            # Ex: mapeia "DoS_TCP" para a classe "DoS"
            normalized_label = name.split("_")[0]

            writer.writerow({
                "event_id": event_id, "run_id": args.run_id, "label": normalized_label,
                "attacker_ip": src, "target_ip": ip, "target_hostname": hostname,
                "protocol": proto, "target_port": port, "start_utc": start,
                # `command` is DERIVED from the argv via shlex.join, so the human field can never
                # contradict command_argv and a path with spaces is properly quoted [audit v20.12 §12].
                "end_utc": end, "tool": cmd[0], "command": shlex.join(cmd),
                "command_argv": json.dumps(cmd),          # lossless argv evidence [audit v20.11 §11]
                "parameters": params, "return_code": rc, "status": status,
                "error_type": error_type,
                # Campaign identity for provenance [audit 17]:
                "campaign_id": campaign_id, "campaign_sha256": campaign_sha,
                "config_id": config_id, "split": campaign_split,
                "scenario_version": SCENARIO_VERSION,
                "orchestrator_version": ORCHESTRATOR_VERSION,
            })
            fh.flush()
            extra = "" if status == "success" else "  <-- {} (ignored by labeler)".format(
                error_type or "rc!=0")
            print("    rc={} status={}{}".format(rc, status, extra))

    print("Ground truth appended to", ann_path,
          "(labeler uses status=success only)")
    print("Attacks: requested={} succeeded={} failed={}".format(
        n_requested, n_succeeded, n_failed))
    # The PROCESS must not report success when attacks failed — an automation would
    # otherwise treat a run where nmap/hydra/slowhttptest never ran as OK [audit 6].
    if n_failed and not args.allow_partial_attacks:
        sys.exit("ABORT: {}/{} attack(s) FAILED (e.g. tool missing). Fix the tools or "
                 "pass --allow-partial-attacks. [audit 6]".format(n_failed, n_requested))


if __name__ == "__main__":
    main()