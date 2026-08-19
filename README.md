# Project — NIDS Dataset for Encrypted Traffic with Synthetic Attacks

Project overview: build an intrusion-detection dataset for **modern encrypted traffic** (HTTPS/TLS 1.3, HTTP/3-QUIC) with synthetic attacks in an **isolated (air-gapped) testbed** composed of four notebooks, following the best practices of four reference papers. Inspired by HIKARI-2021.

> **Scope / ethics:** **academic use** on an **isolated, privately owned network**. Attacks are executed only against laboratory victim hosts — never against third parties.



## Documentation

| File | Purpose |
|---|---|
| `DATASHEET.md` | Dataset documentation (complete after capture) |
| `SECURITY.md` | This file establishes the responsible use guidelines, security restrictions, and ethical boundaries for utilizing the repository's offensive security tools
| `SETUP.md` | A comprehensive guide for setting up the environment, configuring the necessary tools, and executing the generation pipeline to reproduce the TLS13-H3-IDS-2026 dataset.



## Code (Python)

| File | Runs on | Purpose |
|---|---|---|
| `synth_nids_dataset.py` | any PC | Generates a **synthetic** labelled-flow dataset (prototype/augmentation) |
| `seed_content.py` | NB1 victims | Populates WordPress (`wp-cli` via Docker) so benign traffic has content depth |
| `run_attacks.py` | NB3 attacker | Orchestrates attacks + records ground truth **per run** (`annotations_run<N>.csv`) |
| `label_flows.py` | NB4 sensor | Labels flows by **4-tuple** + time window + `quic.log`; produces **3 outputs** (ML, `_split_ready`, `_audit`) + `_run_status.json` (`running` / `failed` / `success`). `--min-window-overlap F` enables **window-overlap-based** labelling (a flow belongs to a window when `overlap/duration >= F`) instead of matching only by flow start time [audit v20.19 §18.4] |
| `validate_dataset.py` | NB4 / any | Smells/pitfalls; **multiclass** baseline with temporal split (Pipeline) |
| `merge_and_split.py` | any | **Temporal** train/test split; **aborts** on temporal leakage |
| `evaluate_realism.py` | any | **TSTR/TRTS + KS/Jensen-Shannon + perturbation** (real vs synthetic) |
| `synthetic_nids_dataset.csv` | — | Ready-to-use sample (**imbalanced ~5%**) for testing the ML pipeline |

> **Versions — canonical sources (not one global file):** **producer/schema** versions (`scenarios/*`, `run_attacks/*`, `label_flows/*`, `status/*`) are defined **only** in `src/versions.py`; the **package** version is defined in `pyproject.toml`; and each **stand-alone tool** (`evaluate_realism.py`, `validate_dataset.py`, `merge_and_split.py`, `synth_nids_dataset.py`) has its own `CODE_VERSION` constant, used in the banner, the `--help` description, and its outputs. The tests `test_version_references_are_consistent` + `test_tool_help_shows_code_version` fail if any README, banner, or `--help` diverges from these sources. For that reason, this README mentions only the current schema (**`status/v5`**) and does not duplicate the remaining version numbers.

## Laboratory Runtime (Ready-to-Use Artifacts)

| File | Where | Purpose |
|---|---|---|
| `docker-compose.yml` | NB1 | Victims: 2× WordPress (`blog.lab` + `shop.lab`) + MariaDB + Caddy |
| `Caddyfile` | NB1 | **Enforces TLS 1.3** + HTTP/3; serves `blog.lab` and `shop.lab` |
| `benign_traffic.py` | NB2 | Real benign browsing (Selenium) on `blog.lab` / `shop.lab` |
| `requirements.txt` | any | Python dependencies (`pip install -r requirements.txt`) |

## Laboratory Automation (Capture / Orchestration) [audit v20.26]

The **automation layer** wraps the analytical pipeline (it does **not** reimplement it — it only invokes it). Everything produces JSON/CSV artifacts and **SHA-256 hashes**, allowing each run to be sealed and re-verified.

| File | Runs on | Purpose |
|---|---|---|
| `preflight.py` | NB1–NB4 | Checks the laboratory **before** each run (tools, disk, DNS, HTTPS, clock, interface, air-gap, **wordlist hashes** vs manifest, manifest loading) → `preflight_run<N>.json`; execution continues only on **PASS** |
| `capture_run.py` | NB4 | Controls `tcpdump`, stores the PID, monitors the PCAP, terminates cleanly, and **seals** capture statistics (received/dropped) + SHA-256 (`--simulate` allows testing without `CAP_NET_RAW`) |
| `process_pcap.py` | NB4 | Runs **Zeek** on the PCAP, verifies `conn/ssl/quic.log` (existence and non-empty), counts records and hashes; `--check-env` validates Zeek/JA3/QUIC support beforehand |
| `service_monitor.py` | NB1 | Samples victim services during the run (availability/latency/HTTP codes + CPU/memory/containers) → CSV/JSON — the **effect evidence** for the DoS class |
| `clock_evidence.py` | NB1–NB4 | Collects clock-synchronisation evidence (`chronyc` / `w32tm` / `timedatectl`) by phase (start/end) |
| `finalize_run.py` | NB4 | Verifies required files, validates status (`status/v5`), inventories + hashes artifacts, packages `run<N>_bundle.tar.gz`; `--verify` detects subsequent modification |
| `orchestrate_run.py` | admin/NB3/NB4 | State machine for **one run** (preflight → clocks → capture → attacks → Zeek → label → finalize) through local/SSH `Runner`; **aborts** on required-step failure; `--dry-run` tests the flow without modifying hosts |
| `orchestrate_campaign.py` | admin | Drives the N runs (ordering, reserved configs, cooldown, **resume**, aborts if an OFFICIAL run fails), then calls `merge_and_split` / `validate_dataset` / `evaluate_realism` |
| `runlib.py` | — | Shared helpers (SHA-256, atomic JSON, guarded run directories, subprocess timeouts, local/SSH `Runner`) |
| `run_overnight_v2.sh` | NB4 |This file is an overnight orchestration script that automates unattended dataset generation runs with robust environment cleanup, error handling, and strict success verification  |


> Automated path: `orchestrate_campaign.py --campaign campaign.official.example.json --base-dir /data --run-config run.json` runs from raw PCAP to the split/validated/evaluated dataset. Physical components (`tcpdump` / Zeek / victim services / SSH) require the real laboratory; the logic (parsers, hashes, state machine, campaign driver) is tested here with `--dry-run` / `--simulate` and local servers.

## End-to-End Workflow

0. **Dependencies** → `pip install -r requirements.txt`.
1. **Seed victim content** → `seed_content.py` (NB1).
2. **Capture** (air-gapped) → `benign_traffic.py` (NB2) + `run_attacks.py` (NB3); `tcpdump` on NB4. Repeat as run 0, 1, 2, ...
3. **Extract features** → `zeek -C -r runN.pcap local` (`conn.log` + `ssl.log` + `quic.log`).
4. **Label** → OFFICIAL: `label_flows.py --annotations annotations_run<N>.csv --campaign campaign.json --require-ip-bytes --require-ssl-log --require-quic-log --min-ssl-join-rate 0.80 --min-quic-join-rate 0.80 --min-port-coverage <cal> --min-window-overlap 0.5`

   The `run_id` is taken from the annotation; this enables all safeguards [audit 7]. **`--min-window-overlap 0.5` is mandatory** because `campaign.official.example.json` pins `required_min_window_overlap:0.5`; omitting it causes the labeller to abort [audit v20.23 §11]. The flags must **match the manifest's `required_labeling_policy`**. Omitting the `--min-*-join-rate` options publishes a status with join rate 0.0, which the labeller **rejects immediately**, and the merge would also refuse [audit v20.4 P0-5/P0-6]. `--campaign` is **mandatory** if the annotation contains campaign identity [audit 5], and it now **requires a reproducible manifest by default** (attacks/target/timeout per run; BruteForce wordlists pinned). Use `--allow-incomplete-campaign` only for development [audit v20.6 §9]. The command produces **3 files** (ML, `_split_ready.csv`, `_audit.csv`) + `_run_status.json` (schema **`status/v5`**) containing `split_ready_sha256` + campaign identity, and executes the **COMMON contract** before publishing [audit 4].
5. **Validate** → sanity checking of one capture is **diagnostic**: `validate_dataset.py --csv labeled_runN_split_ready.csv --allow-single-run-diagnostic`. The **official baseline requires at least two runs**.
6. **Merge + temporal split** → OFFICIAL: `merge_and_split.py <all _split_ready.csv files> --campaign campaign.json --require-status` — `--require-status` **authenticates** every CSV using `_run_status.json` (`SHA-256 == split_ready_sha256`; `campaign_id` / SHA / `config_id` / split must match the manifest), establishing artifact origin [audit 6]. It removes `run_id` / `timestamp` and generates a manifest + `_split_provenance.json` containing campaign and per-run authentication information.
7. **Evaluate realism** (complete campaign) → `evaluate_realism.py --real <ALL _split_ready files by run> --status <corresponding _run_status.json files> --require-status --synth ... --campaign campaign.json --by-class --tstr-balance --domain-distinguishability`. **`--domain-distinguishability` is mandatory** with the official manifest because it pins `release_quality_policy.max_domain_auc`; without the option, `evaluate` aborts [audit v20.23 §11]. **`--status` / `--require-status` are mandatory in official mode** because they authenticate the `--real` artifacts byte-for-byte [audit v20 P0-8]. Without them, use `--allow-unauthenticated-real`, which forces **DIAGNOSTIC ONLY**. The tool prints **INTEGRITY CHECKS PASSED — REALISM NOT ENDORSED** + **REALISM QUALITY** and emits a `VERDICT_JSON` / `--json` structure containing `official` / `diagnostic` / `diagnostic_reasons`.
8. **Document** → complete `DATASHEET.md` and publish the dataset + scripts.

> Shortcut for prototyping the ML pipeline without the lab: run `synth_nids_dataset.py --runs 3` → `validate_dataset.py` → `merge_and_split.py` on the synthetic CSV.

## Tests / CI

The test suite (`tests/test_pipeline.py`) classifies each test into **three tiers** so that no tier must run as one monolithic block [audit residual]. Each test uses its own temporary directory and invokes scripts through the **`_run()`** helper, which launches each subprocess in **its own process group** with a **timeout**. When the timeout expires, `os.killpg(SIGKILL)` terminates the entire process group, preventing grandchildren, thread pools, or open pipes from surviving and hanging the suite.

```bash
python3 tests/test_pipeline.py --only unit          # in-process, no subprocess (fastest)
python3 tests/test_pipeline.py --only integration   # scripts via subprocess, no training
python3 tests/test_pipeline.py --only ml            # baseline/TSTR (trains RandomForest)
python3 tests/test_pipeline.py --list               # list every test and its category
python3 tests/test_pipeline.py --only fast          # shortcut: unit + integration (no ml)
```

In CI, run **three independent jobs** — `unit`, `integration`, and `ml` — each with its own job timeout. For the heavier tiers, use **`--isolated`**: each test runs in a **fresh Python interpreter** (`--run-one` internally), preventing accumulation of BLAS threads, scikit-learn pools, or file descriptors across tests. This is the reliable way to execute an entire tier as a batch [audit v20.2]. `--forked` (POSIX only) is a faster alternative; `--durations N` prints the slowest tests. The tests are plain `test_*` functions without fixtures, so they can also run under `pytest -vv` (or `pytest-forked`).

```bash
python3 tests/test_pipeline.py --only integration --isolated
python3 tests/test_pipeline.py --only ml --isolated
```

## Reference Papers

- **[Ring2019]** *A Survey of Network-based Intrusion Detection Data Sets* (Computers & Security).
- **[Survey]** *Network Intrusion Datasets: A Survey, Limitations, and Recommendations*.
- **[Arp2022]** *Dos and Don'ts of Machine Learning in Computer Security* (USENIX Security).
- **[Smells]** *Bad Design Smells in Benchmark NIDS Datasets* (IEEE).


