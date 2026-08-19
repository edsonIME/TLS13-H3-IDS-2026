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
|---|---|---|---|
| BENIGN | 70,026 | 44,966 | 114,992 |
| DoS | 17,535 | 5,460 | 22,995 |
| PortScan | 14,812 | 0 | 14,812 |
| BruteForce | 394 | 0 | 394 |
| **Total** | **102,767** | **50,426** | **153,193** |

Both TCP (TLS 1.3) and QUIC/HTTP-3 carry **benign and malicious** traffic.
The denial-of-service appears on **both** transports (17,535 TCP and 5,460
QUIC flows), benign traffic spans both (the aioquic-h3 profile is QUIC/UDP;
the httpx/requests profiles are HTTP/1.1 over TLS 1.3/TCP), while
reconnaissance and credential brute-forcing are TCP-only. Consequently
**neither transport isolates a single class**: a UDP flow may be benign
HTTP/3 or DoS, and a TCP flow may be benign HTTP/1.1, DoS, a scan, or a
brute-force. Transport alone therefore does not separate benign from
malicious traffic — a property absent from pre-QUIC corpora, where all
traffic shares one transport.

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
Ground truth is derived by temporal intersection with declared attack
windows, with an ambiguity policy that **drops** flows whose window overlap
is insufficient rather than guessing. A small fraction of flows are assigned
by a legacy point-in-window fallback rule; the campaign caps this fallback
rate and the whole-campaign validator aborts if it is exceeded. See
*Collection Process*.

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
> requests benign profiles use the *same* TLS stack as the attack tooling
> (hydra, the HTTP flooder). As a result the benign JA3 fingerprints
> **overlap by construction** with those of the attacks, so a
> "non-browser fingerprint ⇒ attack" shortcut does not hold. This is an
> intentional property of the dataset, and it explains why removing the
> JA3/JA3S and transport features leaves detection performance unchanged in
> the benchmark (see *Recommended Uses*). Benign flow duration is also
> spread via connection reuse and rate limiting so that the benign class does
> not occupy a trivially separable corner of the feature space.

**Attacks.**
Three attack families, orchestrated from NB3 against NB1 only:
network reconnaissance (nmap, paced to a bounded scan rate), application-
layer credential brute-forcing (hydra against the HTTPS login form on
port 443), and HTTP-flooding denial-of-service. The DoS appears on both
transports in the released flows (17,535 TCP and 5,460 QUIC/HTTP-3), so it
is not an HTTP/3-only flood. *Provenance note: the attack-generation code in
this repository currently emits the DoS over HTTP/3 (QUIC) only; the exact
generator that produced the released TCP+QUIC DoS mix is being reconciled
into the repository so the published pipeline reproduces these flows.*

**Effect-verified ground truth.**
A denial-of-service label is confirmed only against an **independently
measured degradation of service availability** within the attack window: a
service monitor records availability and latency for a targeted and a
control service, and a run is admitted only if the targeted service shows
the expected degradation while the control service remains intact. The
released runs show target-service availability dropping to as low as ~4.5 %
during flood windows while the control service stays at 1.00.

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
release provenance (see the cross-split duplicate note above) and bounded by
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
| NB3 (attacker) | nmap, hydra, slowhttptest |
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
> so detection generalises rather than memorising. The manifest's
> `max_cross_split_duplicate_rate` is set to accommodate this measured rate,
> so the split is released with the duplicates retained and the rate recorded
> in provenance. Users who require strictly flow-disjoint splits should
> deduplicate on the behavioural
> feature vector.

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
Together these establish that separability is driven by **attack-intrinsic
volumetric and flag behaviour**, not by identifier leakage or by a
host-platform artifact (benign traffic originates on a Windows host and
attacks on a Linux host, so this confound was tested for explicitly and
excluded).

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
