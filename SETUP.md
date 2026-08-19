# Setup & Reproduction Guide — TLS13-H3-IDS-2026

This guide explains how to run the generation pipeline, from a no-lab logic
check to a full campaign that regenerates the dataset. It documents the
external tools each host needs, how to provision the internal certificate
authority (which is **not** shipped), and which configuration paths you must
adapt to your environment.

> **Scope.** The released code is the pipeline that produced
> TLS13-H3-IDS-2026. Reproducing the *labelled tables* requires the physical
> testbed described below. Reproducing the *logic* (parsers, hashing, the
> orchestration state machine, the campaign driver) requires only Python and
> can be done on a single machine with `--dry-run`.

---

## 1. Repository layout

```
src/          the pipeline (generation, capture, labelling, sealing, validation)
config/       example campaign configs, per-run configs, Caddyfile,
              docker-compose, and the brute-force wordlists
baselines/    the detection benchmark and the separability diagnostic
tests/        unit / integration tests (run in --dry-run, no lab needed)
DATASHEET.md  dataset documentation (composition, provenance, limitations)
SOURCE_CHECKSUMS.txt  SHA-256 of every released source file
```

The pipeline runs across four hosts. Each source file executes on the host
where its role belongs; see the mapping in the README. `orchestrate_run.py`
drives one run; `orchestrate_campaign.py` drives a multi-run campaign.

---

## 2. Prerequisites

### 2.1 Python

All hosts that run Python code need Python 3.12+ and the packages in
`requirements.txt` (pinned versions in `requirements.lock`):

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2.2 External tools, by host

The pipeline invokes external binaries. Install them on the host that runs
the corresponding role (the `preflight.py` step checks for them and aborts
if any are missing):

| Host | Role | External tools |
|---|---|---|
| NB1 | Victim services | Docker + Docker Compose (Caddy, WordPress, MariaDB), dnsmasq, chrony |
| NB2 | Benign generator | Python with `aioquic`, `httpx`, `requests` |
| NB3 | Attacker | `nmap`, `hydra`, `slowhttptest` |
| NB4 | Capture sensor | `tcpdump`, Zeek **with the Zeek flow-meter (zeek-flowmeter)** |

Zeek must expose the connection, TLS and QUIC logs and the flow-meter log;
`label_flows.py` joins these. If any log is absent the labelling step fails
closed rather than emitting partial features.

### 2.3 Testbed topology

A physically isolated (air-gapped) segment, no default route, wireless
disabled during capture:

| Node | Role | Reference OS | IPv4 |
|---|---|---|---|
| NB1 | Victim + DNS/NTP + internal CA | Linux Mint 22.1 | 10.10.10.11 |
| NB2 | Benign traffic generator | Windows 11 | 10.10.10.20 |
| NB3 | Attack orchestrator | Ubuntu 26.04 | 10.10.10.30 |
| NB4 | Passive capture sensor | Ubuntu 26.04 | link-local capture NIC; mgmt 10.10.10.4 |

The switch must mirror the victim/generator/attacker traffic to the sensor's
capture port. The capture NIC is passive (no routable IP); a separate
management interface is used only for SSH and time sync, and its address is
excluded from capture (`not host <mgmt-ip>`).

---

## 3. The internal certificate authority (you must generate your own)

The testbed serves TLS 1.3 from an **internal CA**. That CA's **private key
is deliberately not distributed** — publishing it would let anyone forge
certificates the testbed's clients trust. Generate your own before the first
run:

```bash
# on NB1 (victim): create an internal CA and issue a server cert for the vhosts
openssl genrsa -out labCA.key 4096
openssl req -x509 -new -nodes -key labCA.key -sha256 -days 3650 \
    -subj "/CN=lab-internal-CA" -out labCA.crt

# server key + CSR for the lab vhosts (blog.lab, shop.lab, ...)
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=blog.lab" -out server.csr
# sign with the SANs listed in config/san.ext
openssl x509 -req -in server.csr -CA labCA.crt -CAkey labCA.key \
    -CAcreateserial -days 825 -sha256 -extfile config/san.ext -out server.crt
```

Then trust `labCA.crt` on the benign generator (NB2) so its clients accept
the lab certificates, and point Caddy (see `config/Caddyfile`) at
`server.crt` / `server.key`. `config/san.ext` lists the subject-alternative
names for the eight lab vhosts.

> Test credentials for the brute-force step are in
> `config/wordlists/` and are small, generic strings (e.g. `password`,
> `admin123`) — safe to publish and required to reproduce the BruteForce
> class.

---

## 4. Configuration you must adapt

The example configs use **placeholders** and **reference paths** that you
replace for your environment.

**Per-run configs (`config/runs/run<N>.json`).** Replace the placeholders:

| Placeholder | Meaning |
|---|---|
| `<user>@<nb1-host>` / `<nb2-host>` / `<nb3-host>` | SSH target `user@ip` for each host |
| `<path-to-ssh-key>` | path to your SSH private key for the lab |
| `<nb2-src-dir>` / `<nb2-campaign-path>` / `<nb2-stage-dir>` | paths on the (Windows) generator host |
| `<python-exe-path>` | the Python executable on the generator host |

**Reference paths.** The configs also contain absolute install paths such as
`/opt/nids/src`, `/opt/nids/campaign.json` and `/opt/nids/wordlists`. These
reflect the reference deployment; change them to wherever you install the
code, campaign manifest and wordlists.

**Campaign manifest.** Copy one of the `config/campaign*.example.json` files
to your own `campaign.json` and set the run parameters (targets, attacker
IP, durations) and — importantly — the **wordlist SHA-256 pins**
(`userlist_sha256` / `passlist_sha256`). The example values are placeholders;
`run_attacks.py` verifies that the pinned hashes match your actual wordlist
files and refuses to run otherwise. The manifest also pre-registers the
integrity thresholds (cross-split duplicate rate, minimum window overlap,
fallback cap, release-quality bars); the CLI may only tighten these.

---

## 5. Running

### Level 1 — Logic check (no lab required)

Verify the orchestration state machine, parsers and hashing without touching
any host:

```bash
# print an example run config to start from
python3 src/orchestrate_run.py --print-example-config > run.json

# stub every step: record the intended actions, touch no host
python3 src/orchestrate_run.py --config run.json --dry-run

# run the test suite (unit / integration, all in dry-run / local servers)
python3 -m pytest tests/ -vv
```

Anyone can run this. It exercises everything except the physical capture and
the real victims/attacks.

### Level 2 — A single real run (needs the testbed)

With the four hosts provisioned, the tools installed (§2.2), the CA generated
(§3) and the configs adapted (§4):

```bash
python3 src/orchestrate_run.py --config config/runs/run0.json
```

This performs the full state machine for one run: preflight → clock
discipline → start capture → benign traffic → attacks → stop capture →
Zeek processing → labelling → finalize (seal + verify). A run that fails any
mandatory gate is aborted rather than sealed.

### Level 3 — A full campaign (regenerates the dataset)

```bash
python3 src/orchestrate_campaign.py \
    --campaign config/campaign.official.example.json \
    --base-dir /data \
    --run-config run.json
```

This drives the configured runs in order (with reserved runs, cooldowns and
resume), then calls `merge_and_split.py`, `validate_dataset.py` and
`evaluate_realism.py` to produce the split, validated dataset.

> The overnight helper `run_overnight_v2.sh` wraps a multi-run campaign with
> practical safeguards (clears orphaned generator processes, lets the lab
> settle before each run, retries a run that seals as *diagnostic* rather
> than *official*). Set the host variables it reads
> (`NB1_HOST`, `NB2_HOST`, `NB3_HOST`, `LAB_SSH_KEY`) for your environment.

---

## 6. Benchmarks

The detection benchmark and the separability diagnostic run on the released
tables (no lab needed):

```bash
# binary attack-vs-benign benchmark with layered feature-occlusion regimes
python3 baselines/baseline_experiments_binary.py \
    --train tls13_h3_ids_2026_train.csv \
    --val   tls13_h3_ids_2026_val.csv \
    --test  tls13_h3_ids_2026_test.csv \
    --label-col label --benign-label BENIGN \
    --models rf mlp cnn \
    --include-ctd --include-protocol-ablation --include-fingerprint-ablation \
    --regimes A1 D1 D2 P F CTD --seeds 42 43 44 45 46

# diagnostic: is separability behavioural or a platform artifact?
python3 baselines/diagnose_separability.py \
    --train tls13_h3_ids_2026_train.csv \
    --test  tls13_h3_ids_2026_test.csv \
    --label-col label --benign-label BENIGN
```

See `DATASHEET.md` (§Uses) for the interpretation of these results.

---

## 7. Verifying integrity

Every released source file is listed with its SHA-256 in
`SOURCE_CHECKSUMS.txt`:

```bash
sha256sum -c SOURCE_CHECKSUMS.txt
```

The dataset's own per-run seals and the whole-campaign validator provide the
provenance chain described in `DATASHEET.md`.
