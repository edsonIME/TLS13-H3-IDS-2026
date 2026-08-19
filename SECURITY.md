# Responsible Use & Security

## What this repository contains

This repository releases the full generation pipeline for the
TLS13-H3-IDS-2026 dataset. To make the dataset reproducible, that pipeline
**includes offensive security tooling**:

- network reconnaissance driven through `nmap` (`run_attacks.py`,
  `attack_scenarios.py`);
- application-layer credential brute-forcing driven through `hydra`;
- an HTTP/3 flooding denial-of-service component (`h3_flood.py`,
  `http_flood.py`, `h3_get.py`).

This tooling is provided **solely** to enable independent reproduction and
extension of the dataset, and to support defensive research on intrusion
detection for encrypted transports.

## Intended use

Use this tooling **only**:

- within a **physically isolated / air-gapped laboratory**, of the kind
  documented in `SETUP.md` and the accompanying paper; and
- against systems that **you own or are explicitly authorised to test**.

The released configuration restricts attacks to a single lab victim
(`10.10.10.11` in the reference deployment) and assumes no route to any
external network.

## Prohibited use

Do **not** deploy this tooling against systems you do not own or lack written
authorisation to test. Unauthorised scanning, credential attacks, or
denial-of-service against third-party systems is illegal in most
jurisdictions — for example under the Computer Fraud and Abuse Act (US), the
Lei nº 12.737/2012 and the Marco Civil da Internet (Brazil), the Computer
Misuse Act (UK), and equivalent legislation elsewhere — and is contrary to
the purpose of this release.

The HTTP/3 flooding component in particular can disrupt availability. Run it
only against the lab victim, on an isolated segment, never against shared or
production infrastructure.

## What is deliberately withheld

The internal certificate authority's **private key is not distributed**.
Publishing it would allow forging certificates trusted by the testbed's
clients. Reproducers generate their own CA (see `SETUP.md`). The brute-force
wordlists that *are* included contain only generic, non-sensitive test
strings.

## No warranty

This software is provided for research under the terms in `LICENSE`, without
warranty of any kind. The authors accept no liability for misuse.

## Reporting a problem

If you believe a file in this repository inadvertently exposes a secret
(a private key, a real credential, or personal information), please open an
issue **without including the sensitive value itself**, or contact the
maintainer through the address listed in the repository metadata, so it can
be removed from the current tree and history.

By using this repository you agree to use it lawfully and ethically.
