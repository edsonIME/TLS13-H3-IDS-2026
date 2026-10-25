# Datasheet — TLS13-H3-IDS-2026

This datasheet follows the framework of Gebru et al., *"Datasheets for
Datasets"* (2021). It documents the motivation, composition, collection
process, preprocessing, recommended uses, and limitations of the
TLS13-H3-IDS-2026 network intrusion-detection dataset.

Every quantity in this document is derived from the released artifacts
(the labelled flow tables, the per-run capture evidence, and the
whole-campaign validation reports). Where a figure is an estimate or
depends on a tool choice, this is stated explicitly.

---

## Motivation

**For what purpose was the dataset created?**
Machine-learning intrusion detection is still evaluated largely on corpora
captured before the standardisation of TLS 1.3, QUIC and HTTP/3. Those
transports change what a passive network sensor can observe: the handshake
is encrypted earlier, the transport moves to UDP, and per-connection
identifiers that older datasets relied upon are no longer visible or no
longer discriminative. TLS13-H3-IDS-2026 was created to provide a labelled
NIDS corpus in which web services are delivered **exclusively** over
TLS 1.3 and HTTP/3, so that detectors can be studied under the encrypted
transports that now dominate the web, and to do so with verifiable ground
truth and a fully released generation pipeline.

**What tasks is it intended to support?**
Binary intrusion detection (attack vs. benign), multiclass attack
classification, feature-occlusion / shortcut-learning studies, and — as the
motivating downstream use — adversarial-robustness evaluation of
encrypted-traffic classifiers. See *Recommended Uses* below.

**Who created the dataset?**
The dataset was produced on an isolated laboratory testbed as part of
doctoral research on adversarial machine learning for network intrusion
detection. Author and affiliation are given in the accompanying manuscript.

---

## Composition

**What do the instances represent?**
Each instance is a **network flow** summarised by 89 features plus a class
label. Flows are derived from packet captures via Zeek (connection, TLS and
QUIC logs) joined with a Zeek-based flow-meter; labels are assigned by
intersecting flow timestamps with externally declared attack windows.

**How many instances are there?**
**153,193 labelled flows** in total (Zeek/merge sessionisation), split into
train (83,972), validation (20,790) and test (48,431).

> **Sessionisation note.** An independent audit that re-sessionised the raw
> packets with a different tool (dpkt) counted 152,017 flows. The ~1,176-flow
> difference reflects the two tools' differing flow-assembly heuristics
> (timeouts, handling of incomplete connections), not missing or duplicated
> data. The released tables use the Zeek/merge count of 153,193 throughout.

**Class distribution (train / val / test):**

| Class | Train | Val | Test | Total | Share |
|---|---|---|---|---|---|
| BENIGN | 65,871 | 16,591 | 32,530 | 114,992 | 75.1 % |
| DoS (HTTP flood) | 9,677 | 2,107 | 11,211 | 22,995 | 15.0 % |
| PortScan | 8,192 | 2,048 | 4,572 | 14,812 | 9.7 % |
| BruteForce | 232 | 44 | 118 | 394 | 0.26 % |

BruteForce is deliberately small: credential brute-forcing against a login
form produces few distinct flows relative to volumetric attacks. This
imbalance is a property of the phenomenon and is reported honestly rather
than resampled away.

**Transport distribution:**

| Class | TCP | QUIC (UDP) | Total |
|---|---:|---:|---:|
| BENIGN | 70,026 | 44,966 | 114,992 |
| PortScan | 14,812 | 0 | 14,812 |
| BruteForce | 394 | 0 | 394 |
| DoS | 0 | 22,995 | 22,995 |
| **Total** | **85,232** | **67,961** | **153,193** |

Per run-disjoint split:

| Split | Runs | BENIGN TCP | BENIGN QUIC | PortScan (TCP) | BruteForce (TCP) | DoS (QUIC) | Total |
|---|---|---:|---:|---:|---:|---:|---:|
| Train | 0-3 | 40,110 | 25,761 | 8,192 | 232 | 9,677 | 83,972 |
| Validation | 4 | 10,084 | 6,507 | 2,048 | 44 | 2,107 | 20,790 |
| Test | 5-6 | 19,832 | 12,698 | 4,572 | 118 | 11,211 | 48,431 |
| All | 0-6 | 70,026 | 44,966 | 14,812 | 394 | 22,995 | 153,193 |

Benign traffic is the only class present on both transports: the aioquic-h3 profile
is HTTP/3 over QUIC/UDP and the httpx/requests profiles are HTTP/1.1 over TLS 1.3/TCP.
Reconnaissance and credential brute-forcing are TCP-only, and the denial-of-service
flood is QUIC/HTTP-3-only. The TCP column therefore mixes TLS 1.3 sessions (benign
HTTP/1.1 and the hydra login attempts on port 443) with scan probes, which are plain
TCP connection attempts (SYN or connect scans) that never complete a TLS handshake.
Consequently each transport poses its own problem (BENIGN/DoS on QUIC;
BENIGN/PortScan/BruteForce on TCP) and, given that a flow is malicious, its transport
determines whether it is the flood or one of the two TCP attacks. Cramér's V for class
against transport, recomputed from the released tables, is 0.5252.


**What features does each instance have?**
89 features plus `label`. Seven of the features are strong or
protocol-identifying attributes — `ja3`, `ja3s`, `dst_port_class`,
`sni_present`, `tls_version`, `alpn`, `transport` — leaving **82 behavioural
features** (packet and byte counts, rates, inter-arrival statistics, TCP
flag counts, subflow and bulk statistics, active/idle timing). The seven
strong-identifier features (`dst_port_class`, `sni_present`, `transport`,
`tls_version`, `alpn`, `ja3`, `ja3s`) are **part of the released 89-feature
representation** and are present in the full regime (A1); the occlusion
regimes remove specific subsets of them to probe shortcut sensitivity (see
*Recommended Uses*). Only the true bookkeeping fields (`run_id`, `timestamp`)
are never model inputs.

**Is any information missing?**
User-agent strings are not recorded as features. The capture NIC observes
mirrored traffic only; application-layer plaintext beyond what the TLS/QUIC
handshakes expose is, by design, encrypted.

**Are there labelling errors or sources of noise?**
Ground truth is derived by intersecting each flow with the declared attack
windows (originator = pinned attacker, responder = victim, window overlap
≥ 0.5 of the flow duration, or a point rule for zero-duration flows). The
rule has three outcomes: (i) a flow matching no candidate window keeps the
BENIGN label; (ii) a flow inside a window that matches its protocol and
destination port takes the window's class (the narrowest port range wins; a
tie between two classes is dropped as ambiguous); (iii) a flow inside a window
that does **not** match its protocol/port is marked ambiguous and excluded from
the released tables rather than guessed. Zero-duration flows use the point
rule and are counted as duration fallbacks; the campaign caps this fallback
rate (maximum per-run value 4.98 %) and the whole-campaign validator aborts if
the cap is exceeded. See *Collection Process*.

> **Attribution re-derivation (completeness of the attack declaration).** The
> labeller cannot detect attacker traffic that falls outside every declared
> window: such flows keep the BENIGN label by outcome (i). The rule was therefore
> re-derived over the sealed `conn.log` and annotations of the seven official
> runs with `t1_outside_window_audit.py` (shipped with the artefacts). Of 38,568
> attacker→victim connection records, 38,201 were attributed to declared events
> (exactly the released attack flows), 43 fell inside a window without matching
> its protocol/port (outcome iii; 2, 2, 3, 3, 2, 28 and 3 per run, equal to the
> labeller's own `ambiguous = 1` counts), and 324 (0.84 %) fell outside every
> window. All 367 non-attributed records are NTP (`udp/123`, 287) and DNS
> (`udp/53`, 80) exchanges with the victim host, which serves both; none is
> addressed to the web service, 314 of the 324 lie more than 60 s from any
> window, and every one was answered (Zeek state `SF`). Their payload was not
> inspected, so this verifies the observable consequence of the assumption (no
> unattributed traffic reached any service other than DNS and NTP), not the
> assumption itself. No class tie occurred.

> **What provenance attribution prevented (window-labelling counterfactual).**
> Benign generation runs for the whole 2,700 s capture, so benign flows fall
> inside every attack window. Re-deriving two window-only rules over the same
> sealed `conn.log` and annotations (`window_counterfactual.py`, shipped): a
> time-only rule would have labelled 8,578 of the 114,667 benign-host→victim
> records as attacks (2,387 DoS, 6,133 PortScan, 58 BruteForce), and a
> time-plus-protocol/port rule 4,710 (906 DoS, 3,762 PortScan, 42 BruteForce) —
> one in five of the resulting PortScan labels and one in ten of the BruteForce
> labels would have been benign, almost all of the scan mislabels (3,666)
> falling inside the 1,231 s slow scan of run 5 (configuration 6, `-T2`). The
> released provenance rule keeps all of them BENIGN; under the same
> time-plus-port rule the attacker's records reproduce the released attack
> counts exactly (22,995 / 14,812 / 394). Per run (time+port rule, benign
> records mislabelled DoS / PortScan / BruteForce): run 0: 140 / 14 / 10;
> run 1: 95 / 0 / 9; run 2: 152 / 57 / 2; run 3: 160 / 0 / 4; run 4: 169 / 25 / 6;
> run 5: 97 / 3,666 / 4; run 6: 93 / 0 / 7. Population: the 114,667 records are
> every `conn.log` record with the benign host as originator and the victim as
> responder. Itemised by originator and responder from the audit tables
> (`benign_population.py`, shipped), the released BENIGN class (114,992 flows)
> consists of exactly these 114,667 records (10.10.10.20 → 10.10.10.11), the 324
> attacker-host records outside every window (10.10.10.30 → 10.10.10.11, kept
> BENIGN by outcome i) and one multicast record from the victim host
> (10.10.10.11 → 224.0.0.251, mDNS, run 3); every attack-labelled flow
> (22,995 DoS, 14,812 PortScan, 394 BruteForce) has the attacker as originator
> and the victim as responder.

**Is the dataset self-contained?**
The released tables are self-contained. The **generation pipeline** is
released as source code; reproducing the corpus additionally requires the
external tools and the internal certificate authority described under
*Collection Process* and *Reproducibility*.

---

## Collection Process

**Testbed.**
A physically isolated (air-gapped) four-host testbed on the 10.10.10.0/24
segment, with no default route and wireless disabled during capture:

| Node | Role | OS | IPv4 |
|---|---|---|---|
| NB1 | Victim services + DNS/NTP | Linux Mint 22.1 | 10.10.10.11 |
| NB2 | Benign traffic generator | Windows 11 Education | 10.10.10.20 |
| NB3 | Attack orchestrator | Ubuntu 26.04 LTS | 10.10.10.30 |
| NB4 | Passive capture sensor | Ubuntu 26.04 LTS | — (see note) |

The NB1 victim serves web applications (Caddy reverse proxy in front of two
WordPress instances backed by MariaDB, in Docker), and provides internal DNS
(dnsmasq), NTP (chrony) and an internal certificate authority.

> **Sensor addressing.** NB4 has two interfaces. The capture NIC is passive
> on the switch mirror-destination port and carries only an auto-assigned
> link-local address (169.254.0.0/16), i.e. no routable IP; a separate
> management interface carries 10.10.10.4/24, used only for time
> synchronisation and administration. Management traffic is excluded from
> every capture (`not host 10.10.10.4`).

**Benign traffic.**
Benign activity is generated by a suite of **concurrent, non-browser Python
clients** (`benign_clients.py`) exercising an aioquic HTTP/3 profile and
httpx / requests profiles over TLS 1.3, driven on the generator host through
a thin wrapper (`benign_traffic.py`). All 113,971 benign sessions in the
released runs are of this non-browser tier; the client identifiers recorded
in the per-run benign logs are `aioquic-h3` (43,958), `httpx-session`
(23,372), `requests-session` (17,232), `httpx` (16,773) and `requests`
(12,636).

> **Deliberate fingerprint collision (anti-leakage design).** The httpx and
> requests benign profiles use the *same* TLS stack as the TCP attack tooling
> (hydra), and the HTTP/3 flooder is built on the same aioquic stack as the
> benign aioquic-h3 profile. As a result the benign JA3 fingerprints
> **overlap by construction** with those of the attacks, so a
> "non-browser fingerprint ⇒ attack" shortcut does not hold. This is an
> intentional property of the dataset and is consistent with the observation
> that removing the JA3/JA3S and transport features leaves the benchmark
> unchanged (see *Recommended Uses*); it does not by itself show that the
> learned representations are attack-specific. Benign flow duration is also
> spread via connection reuse and rate limiting so that the benign class does
> not occupy a trivially separable corner of the feature space.

**Attacks.**
Three attack families, orchestrated from NB3 against NB1 only: network reconnaissance
(nmap, SYN or connect scans over a planned port range, paced to a bounded scan rate),
application-layer credential brute-forcing (hydra against the HTTPS login form on
port 443) and an HTTP GET flood against the WordPress search endpoint delivered over
HTTP/3 on QUIC (`src/h3_flood.py`). The repository also contains the TLS/TCP flood
generator of the pilot campaign (`src/http_flood.py`); it was not used in the seven
official runs, whose DoS flows are QUIC/UDP only.

**Effect-verified ground truth.**
A denial-of-service label is confirmed only against an **independently
measured degradation of service** within the attack windows: a service
monitor on the sensor host probes the targeted service (`blog.lab`) and the
co-hosted, unattacked control service (`shop.lab`) throughout the run, and
finalisation refuses an official seal unless, for at least one probed origin,
the predeclared rule holds over the DoS windows — availability drop ≥ 0.20, or
p95-latency ratio ≥ 2.0, or error-rate increase ≥ 0.20, each relative to the
same origin's probes outside DoS windows. The rule is evaluated per origin and
any confirming origin admits the run; that the confirming origin was the
*target* is an observation of the seven official runs, not a formal condition.
In all seven runs it was: target availability dropped to 4.5–44.7 % during the
flood windows while the control service stayed at 1.00. A slow-rate,
connection-holding attack tried before the campaign did not perturb the
hardened proxy and was not admitted; the corpus therefore contains no DoS
label resting on intent alone and no low-and-slow DoS representative.

**Labelling and quality gates.**
Labels are assigned by `label_flows.py` under a pinned temporal rule
(minimum window overlap 0.5; ambiguous flows dropped). Per-run and
whole-campaign validators enforce capture quality (packet counts, ~0 % drop),
label accounting, the effect check above, run-level temporal partition
integrity, and the declared cross-split duplicate policy; a run that fails any
gate is not sealed as official. Train, validation, and test are disjoint **by
capture run** (runs 0–3 train, run 4 validation, runs 5–6 test, with no run in
more than one partition), although exact EXTENDED feature representations may
recur across partitions — such repetitions are explicitly quantified in the
release provenance (see the cross-split duplicate note under *Preprocessing*) and bounded by
the manifest's `max_cross_split_duplicate_rate`. Each run is sealed with a
manifest and re-verifies against it.

**Campaign identifier.**
The per-run benign logs of the released runs carry the campaign identifier
`nids4d-20260803`. This identifier was **reused** from an earlier pilot; the
released benign traffic is the non-browser client traffic described above,
not the browser-based pilot that first used that identifier. The identifier
is recorded here for transparency and should not be taken to imply the pilot
configuration.

**External dependencies (required to reproduce, by host):**

| Host | Tools |
|---|---|
| NB1 (victim) | Docker (+ Caddy, WordPress, MariaDB, dnsmasq, chrony) |
| NB2 (benign) | Python 3 with aioquic, httpx, requests |
| NB3 (attacker) | nmap, hydra, Python 3 with aioquic (`h3_flood.py`); slowhttptest only for the excluded slow-rate trial |
| NB4 (sensor) | tcpdump, Zeek + Zeek flow-meter |

---

## Preprocessing / Cleaning / Labelling

**What preprocessing was done?**
Packets captured on the sensor were processed offline with Zeek to produce
connection, TLS and QUIC logs and a per-flow flow-meter log; these were
joined and labelled to produce the flow tables, then merged and split into
train/validation/test.

**Post-campaign correction (disclosed).**
During release preparation, an accounting inconsistency in the labeller's
duration-fallback **counter** was detected by the pipeline's own provenance
check. The counter was corrected and the affected runs were re-derived. The
correction affected only the reported fallback statistic, not the labelling
logic: the assigned labels and the feature values are unchanged by the fix.
The released labelling code is the corrected version, and the SHA-256 of each
split-ready output is recorded in its run status.

**Split construction (leakage control).**
Train/validation/test are partitioned by **run** rather than by random
sampling, so that flows from one capture run do not appear across splits.
The merge step is fail-closed on cross-split leakage: it measures, over the
released 89-feature EXTENDED schema, any group of flows whose complete feature
representation recurs in more than one split.

> **Cross-split duplicate note.** Duplication here is defined as an *exact
> match across all 89 features of the EXTENDED schema*, excluding the label
> and the split/bookkeeping metadata (`run_id`, `timestamp`). Raw identifiers
> — source/destination IP and MAC, raw ports, and flow/uid — are **not** part
> of the dataset and therefore play no role in this definition (the schema
> carries only the coarse `dst_port_class`, by design, to avoid a raw-port
> shortcut). Under this behavioural definition the released split provenance
> records 13,377 cross-split duplicate rows (rate 0.087): **12,809 PortScan
> and 568 BENIGN**, with **zero label conflicts** across all groups. The
> PortScan majority are structural collisions of reconnaissance traffic — a
> port scan emits many flows that are physically identical (one packet sent,
> one returned, sub-microsecond duration), so the recurrence is intrinsic to
> the attack. The 568 benign duplicates arise from very short, cache-served
> HTTP responses whose flow features coincide once raw identifiers are
> excluded (two identical small GETs from different clients collapse to the
> same 89-feature vector); they remain consistently labelled BENIGN (no group
> mixes benign and attack). Empirically the duplicates confer no usable
> shortcut: removing **every** cross-split duplicate from the test set leaves
> the binary F1 at 0.9999 and PortScan recall at 1.0 on the unseen remainder,
> so exact memorisation of repeated vectors is not necessary for the result
> (non-identical but host-characteristic vectors may still recur across runs;
> see *Key finding*). The manifest's
> `max_cross_split_duplicate_rate` is set to accommodate this measured rate,
> so the split is released with the duplicates retained and the rate recorded
> in provenance. Users who require strictly flow-disjoint splits should
> deduplicate on the behavioural
> feature vector.

**Artefact identities (SHA-256) behind the transport counts.**
The table below was recomputed by `evidence_digest.py` (shipped with the artefacts)
from the sealed run directories and the release directory. For every run, the
modelling table (`run<N>.csv`), the split-ready table (`run<N>_split_ready.csv`, the
merge input) and the labeller audit table (`run<N>_audit.csv`, unambiguous rows, Zeek
`proto`) give the same label x transport counts; the three released split tables give,
split by split, the rows of the per-split table above, and their union equals the union
of the per-run tables.

| Source | File | Bytes | SHA-256 | Listed in sealed inventory | Digest cited by |
|---|---|---:|---|---|---|
| run 0 | `run0_split_ready.csv` | 13,174,698 | `ae4ec2c14aacb08c81636f49968d5247b14b116458c8d9c266d671345c0e5302` | run0_hashes.json | tls13_h3_ids_2026_split_provenance.json, validation.json |
| run 0 | `run0.csv` | 12,813,981 | `fe1c01ea8a7586ae7e740dd0107846e4b2ee32051475deff498bd218d4e7b42e` | run0_hashes.json | - |
| run 0 | `run0_audit.csv` | 4,698,824 | `4a53b278593d2dc41ec0aacf6b630481d99ca68dc1bba326f0b37783691a5c7d` | run0_hashes.json | - |
| run 0 | `run0_annotations.csv` | 1,942 | `9f734ac8fc950aafb8923d4e2240aa91454dd47a3c89ca0b12390e014caf180f` | run0_hashes.json | - |
| run 0 | `conn.log` | 2,479,156 | `c3619e2b1d4e7cf05f78a9933f7593f06f0437a81e9c08bb0807b047aba580f7` | run0_zeek_hashes.json, run0_hashes.json | - |
| run 1 | `run1_split_ready.csv` | 16,363,373 | `38f45fb477597a88e246915546247658935b71fae79ddde23320f05de236b190` | run1_hashes.json | tls13_h3_ids_2026_split_provenance.json, validation.json |
| run 1 | `run1.csv` | 15,915,616 | `dc78b2f660ac7a77836187e40eb612cbb2566b0b8d277daabeea107401385784` | run1_hashes.json | - |
| run 1 | `run1_audit.csv` | 5,856,691 | `21c596d6685cbb845cb595bf23f033c76090d508cff6c814384797e9ee283400` | run1_hashes.json | - |
| run 1 | `run1_annotations.csv` | 1,912 | `3b1fef73db559847cad24e62b498f598273fa15f4f8794b4580d10988b715d36` | run1_hashes.json | - |
| run 1 | `conn.log` | 3,059,582 | `e98f744d63a31940902f6d95967de4eaf02d73facefade73f4407b7cf5072f53` | run1_hashes.json, run1_zeek_hashes.json | - |
| run 2 | `run2_split_ready.csv` | 17,008,750 | `4a030cda3ca3a66d66d96d7f76ce4d3b9556a57a383c5d0731875fe60b7760ec` | run2_hashes.json | tls13_h3_ids_2026_split_provenance.json, validation.json |
| run 2 | `run2.csv` | 16,526,613 | `41db2ce730c31d574aa2458e0e991ad7590e534edc51108d896a29515eb15f24` | run2_hashes.json | - |
| run 2 | `run2_audit.csv` | 6,068,683 | `17b9b3a0d6eacca0f033bebc9d5aa402e8544310a7a5c625fdb23923ce059337` | run2_hashes.json | - |
| run 2 | `run2_annotations.csv` | 1,951 | `7c4a4784f65636c741560f7dd05a6989641263d444bf1756c16b2d8ebee226ac` | run2_hashes.json | - |
| run 2 | `conn.log` | 3,253,539 | `36f0f081578bd79a36ee54b4c9d3c7c985192e0965086ad4a5e0e93b4b42edc8` | run2_hashes.json, run2_zeek_hashes.json | - |
| run 3 | `run3_split_ready.csv` | 14,321,083 | `6cbdb0151324ef3d3d85957248d08e09447f4aafda42249a41f665d4d80d5db7` | run3_hashes.json | tls13_h3_ids_2026_split_provenance.json, validation.json |
| run 3 | `run3.csv` | 13,932,186 | `414c4eda88dccf515169901abdf4aade1f3a88825e1aaddb3c634bc133ff5d39` | run3_hashes.json | - |
| run 3 | `run3_audit.csv` | 5,122,941 | `937df8de8546215ede507ff6464c75959d0509324a04e2efde53724ff2de2cfc` | run3_hashes.json | - |
| run 3 | `run3_annotations.csv` | 1,912 | `417a004a7bbf0d4ece9a0b394b9fcaba4bcc4fb1909cdb9e4315f0a3b2b3cfd5` | run3_hashes.json | - |
| run 3 | `conn.log` | 2,674,609 | `a95d543ad61d31444fe44abc2eb8165ad307f68e4449a5299fcae08138d2f01a` | run3_hashes.json, run3_zeek_hashes.json | - |
| run 4 | `run4_split_ready.csv` | 15,046,153 | `705d850be3298b3b1a3a48771a226578b06d586adff90d1fce3178bd4e39e2f0` | run4_hashes.json | tls13_h3_ids_2026_split_provenance.json, validation.json |
| run 4 | `run4.csv` | 14,630,336 | `c228de230602c3c7bed8adc02a01d64d5505e422b69c8dc80fad7b335215e1f9` | run4_hashes.json | - |
| run 4 | `run4_audit.csv` | 5,374,466 | `238beb986c1dbb01ad432aaa7180301f33e5051d534e774f9e7b41dc41c08365` | run4_hashes.json | - |
| run 4 | `run4_annotations.csv` | 1,963 | `6b174797cc9ac230bec3e61e5aec1bba0a8a4e053f0d3a5a867bcc220d4296e3` | run4_hashes.json | - |
| run 4 | `conn.log` | 2,838,748 | `05594602bb50c42442f76c1425c98df0d60e3666c3b50cdff36556d4a28f4110` | run4_zeek_hashes.json, run4_hashes.json | - |
| run 5 | `run5_split_ready.csv` | 18,435,565 | `b1ab222b516152989666513a097bcab4bcda9e517fb2e9a63321e2453e1e6afa` | run5_hashes.json | tls13_h3_ids_2026_split_provenance.json, validation.json |
| run 5 | `run5.csv` | 17,925,608 | `d93d8f02efa1f292adc656b9d00862674af662c7c3c85209f4976eb6c02f71c6` | run5_hashes.json | - |
| run 5 | `run5_audit.csv` | 6,648,715 | `bfedb3e714b9d12248aa7bf2ea573539698875984694ca5a1d43c92af24dcdee` | run5_hashes.json | - |
| run 5 | `run5_annotations.csv` | 1,948 | `ec9e11217670dbe0bb6e60b310ce1d0e78e306b957cffbdbc0165eb4146c3cf6` | run5_hashes.json | - |
| run 5 | `conn.log` | 3,467,980 | `4b14ee4e4996a7687ac9370bff7bac04f0f27239aee1567fee3788af78c55d88` | run5_hashes.json, run5_zeek_hashes.json | - |
| run 6 | `run6_split_ready.csv` | 16,893,564 | `4b67e0566058a981fdf27eff484e9297618f5866e986db38fa89bcc511e64eeb` | run6_hashes.json | tls13_h3_ids_2026_split_provenance.json, validation.json |
| run 6 | `run6.csv` | 16,434,867 | `5ee49462487d118256dfa816639edb1d1f484efdee75b29dbd52de87467c0ba3` | run6_hashes.json | - |
| run 6 | `run6_audit.csv` | 6,101,697 | `dc00faaa75b9baea93185033372d69f49eeb21efa270ef0b9efd80914da78325` | run6_hashes.json | - |
| run 6 | `run6_annotations.csv` | 1,903 | `42b1746ceac470ce5c705668867431a63a668c61ee65481d6ac456447f446f35` | run6_hashes.json | - |
| run 6 | `conn.log` | 3,142,489 | `72f659c5af386afd4b01c2562ce174f904b2e5e2fd703248c3946fe3ad6a4258` | run6_zeek_hashes.json, run6_hashes.json | - |
| release | `tls13_h3_ids_2026_train.csv` | 59,100,190 | `2b2f5c6f51355bba5647f5f08e25ff85b416cc41a814c10d3162e28a3be44f58` | - | tls13_h3_ids_2026_split_provenance.json (output); `jisa_benchmark_final/run_provenance.json` (recorded multiclass evaluation), `jisa_dedup_multiclass/dedup_provenance.json` (control C3) and `baselines_binary*/experiment_manifest.json` (binary occlusion study), all as input |
| release | `tls13_h3_ids_2026_val.csv` | 14,609,545 | `0e57ebb99d934ab2f1c9e836e581190ef0dd4eb7c45ae00d9a6c8f47261dfde9` | - | same as above |
| release | `tls13_h3_ids_2026_test.csv` | 34,310,632 | `b9c567cb4fc1e7272913280c1ae27a502f575338a33507a329886513e00d5f99` | - | same as above |
| release | `tls13_h3_ids_2026_split_provenance.json` | 15,163 | `025932ed10df3ff57c6d52a4db4082efb4c49d2f1eea3325bd0fde0a85384bf7` | - | - |
| release | `tls13_h3_ids_2026_split_manifest.csv` | 282 | `bf23b11ce339543e1b69ddc44441000b0ac6929b27e21e7472d925e5187b33a0` | - | tls13_h3_ids_2026_split_provenance.json |
| release | `validation.json` | 11,106 | `5170205a4ea057048ca3fadace6459324b95314383eb9c33293f7983a81b4103` | - | - |

---

## Uses (Recommended)

**Reference benchmark.**
A binary attack-vs-benign benchmark is provided (Random Forest, MLP and a
1-D CNN; five seeds; results as mean ± standard deviation). To test *what*
detection rests on, the benchmark applies a feature-occlusion study adapting
the methodology of Wickramasinghe et al. (SoK, IEEE S&P 2025). Its structure
is **not** a single cumulative chain: A1 (all 89 network features), D1
(A1 minus the strong identifiers / SII, 88 features) and D2 (D1 minus the
SNI-presence indicator, 87 features) form a cumulative sequence; from D2,
three **independent** sensitivity branches each remove one further group —
P (D2 minus the transport indicator, 86 features), F (D2 minus the JA3/JA3S
fingerprints, 85 features) and CTD (D2 minus the four highest-association TCP
window-size features, 83 features). P, F and CTD are parallel ablations of
D2, not successive steps: F retains the transport feature that P removes, and
CTD inherits neither P's nor F's removals.

**Key finding.**
Detection is near-perfect (F1 ≈ 0.999 for all three models) and **invariant
across every regime evaluated** (A1, D1, D2, and the P/F/CTD branches):
neither the cumulative SII/SNI removal nor any of the three independent
branch removals degrades performance. A further probe restricted to eight
operating-system-agnostic volumetric features (flow duration, packet and byte
rates, directional counts, and the down/up ratio) retains F1 = 0.9997.
What this establishes is that the removed fields — the strong identifiers,
the SNI indicator, the transport indicator, the JA3/JA3S fingerprints and the
four highest-association TCP window-size features — are **not necessary** for
binary separation. What it does **not** establish is that the learned
representations are attack-specific: all benign traffic originates on a
Windows host and all attacks on a Linux host, each with its own client
software, and the rate, count and timing statistics that remain can still
encode the generating host and client library. No same-host benign/malicious
cross-over run and no feature-attribution analysis exist in this release, so
the host–label confound is **disclosed, not excluded** (see the confound ledger
in the manuscript).

**Multiclass reference evaluation (recorded; reported in the manuscript).**
Separately from the binary benchmark above, a four-class evaluation was
recorded on the released splits with Random Forest, XGBoost and an MLP (five
seeds, 42–46; hyperparameters selected on the validation split only;
82-feature behavioural view): Macro-F1 0.999913 (RF), 0.999955 (XGBoost, MCC
0.999873) and 0.999507 (MLP) on the test split, with the residual errors
concentrated in BENIGN↔DoS. Three sensitivity controls accompany it: C1
restores the seven strong-identifier attributes (Macro-F1 shifts of −6×10⁻⁶,
+6×10⁻⁶ and +2.1×10⁻⁵); C2 fits and tests within one transport at a time with
the transport indicator withheld (TCP-only Macro-F1 1.000000 for the tree
ensembles and 0.999982 for the MLP; QUIC-only between 0.999731 and 0.999899);
C3 removes every test flow whose complete 82-feature vector recurs in training
or validation (4,471 of 48,431 test flows, 4,305 of them PortScan) and leaves
Macro-F1 unchanged to six decimals (MCC 0.999664, 0.999826 and 0.998101; the
267 non-recurrent PortScan flows are classified with F1 = 1.0 by all three
learners). These controls show that the named mechanisms are not
*necessary* for the result; none shows that the model ignored a mechanism that
was available to it, and none addresses the host–label confound above. Its
provenance record (`jisa_benchmark_final/run_provenance.json`) cites the three
released split tables by SHA-256 (see *Artefact identities*).

**Within-transport control (C2).** The within-transport tasks select rows
by the `transport` column of the released split tables. Because no DoS flow is TCP,
the TCP-only task has three classes and the QUIC-only task two. The raw confusion
matrices released with the recorded evaluation (three learners x five seeds per
regime) carry the following test supports:

| Regime | BENIGN | PortScan | BruteForce | DoS |
|---|---:|---:|---:|---:|
| behavioural (82 features) and with-SII | 32,530 | 4,572 | 118 | 11,211 |
| TCP-only | 19,832 | 4,572 | 118 | - |
| QUIC-only | 12,698 | - | - | 11,211 |
| behavioural after exact-recurrence removal (C3) | 32,364 | 267 | 118 | 11,211 |

**Interpretation.**
Near-perfect *binary* detection is expected for a controlled testbed in
which flooding and scanning are volumetrically distinct from benign HTTP/3
activity; no claim of state-of-the-art detection is made. The value of the
corpus is in its protocol modernity, its effect-verified and re-derivable
provenance, and its suitability for the harder tasks of multiclass
classification and adversarial-robustness evaluation.

**Uses for which the dataset should be used with care.**
Because binary separability is high and largely volumetric, the dataset is
not well suited to claims about detector *difficulty* on binary detection.
Studies seeking difficulty should target multiclass classification, evaluate
robustness to feature normalisation, or use the adversarial-robustness
setting the dataset was designed for. Detectors intended for cross-
environment deployment should not treat lab-controlled volumetric
separability as representative of production traffic.

**Uses for which the dataset should NOT be used.**
The dataset must not be used to justify deploying the released offensive
tooling against systems the user does not own or is not authorised to test
(see *Distribution*). It is not a source of realistic benign *human*
browsing behaviour: benign traffic is programmatic by construction.

---

## Distribution

**How is the dataset distributed, and under what licence?**
The labelled flow tables (and, where size permits, the raw captures) are
distributed via an archival repository with a persistent identifier under a
Creative Commons Attribution licence; the generation code is distributed via
a public source repository under a permissive open-source licence. Exact
identifiers and licence texts accompany the release.

**Offensive tooling and responsible use.**
The pipeline includes network scanning, credential brute-forcing and an
HTTP/3 flooding component, released to enable reproduction. This tooling is
intended **solely** for use within an isolated, air-gapped laboratory
against systems the user owns or is explicitly authorised to test.
Unauthorised use against third-party systems is unlawful in most
jurisdictions and is contrary to the purpose of this release. The repository
includes a responsible-use statement to this effect.

**What is deliberately NOT distributed.**
The internal certificate authority's **private key** is not distributed:
publishing it would let anyone forge certificates trusted by the testbed's
clients. Reproducers must generate their own internal CA (the procedure is
documented in the code repository). Test credentials used by the
brute-forcing wordlists are small, generic strings and are included for
reproducibility.

---

## Maintenance

**Provenance of the released code.**
The released source corresponds to the code **as executed** during the
capture campaign, assembled per host and verified by cryptographic hash:
benign-generation code from the generator host (NB2), attack code from the
attacker host (NB3), and capture/labelling/orchestration code from the
sensor (NB4). The labelling module reflects the post-campaign correction
described above, which affected only the reported fallback statistic. SHA-256
checksums of all released source files are provided in the repository
(`SOURCE_CHECKSUMS.txt`).

**Independent validation summary.**
A whole-campaign audit of the released runs reports no failing checks. Among
its confirmatory findings: QUIC is independently dissected as QUIC in
99.94–99.98 % of UDP records across all seven runs, and TLS 1.3 is directly
evidenced (the `supported_versions` value 0x0304 appears in 276,538
handshake packets). Open observations recorded by the audit, and reflected
in the manuscript's limitations, include: the NTP client reporting
`synchronized=false` despite sub-millisecond measured offset; capture
records exceeding the Ethernet MTU, attributable to receive-offload
(GRO/GSO) in the acquisition stack, which affects size-derived features;
and the cross-split scan-probe duplication noted above.

**Known limitations (summary; see the manuscript for the full treatment).**
Benign traffic is programmatic rather than human browsing. External
ecological realism (comparison against a production capture) is not assessed.
The testbed is single-victim and small-scale by design; the contribution is
methodological, not one of scale.

**Contact and updates.**
Corrections and extensions are handled through the code repository's issue
tracker. Because the generation pipeline is released in full, the dataset can
be regenerated and extended — additional attacks, protocols or endpoints, or
refreshed transport and cipher standards — using the same ground-truth and
integrity machinery.
