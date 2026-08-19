#!/usr/bin/env python3
"""
configure_nb2.py - provisioner for NB2 (benign traffic, NATIVE Windows 11).

Machine: ASUS TUF Gaming F16 ("LAPTOP-27A6JIHC"), 10.10.10.20.
Role: drives NON-BROWSER Python HTTP clients against blog.lab / shop.lab,
producing benign traffic + the benign-session JSONL evidence. Runs on Windows
NATIVELY.

The generator is `benign_clients.py`, exercising five Python-only profiles:
  * aioquic-h3        HTTP/3 over QUIC (via the h3_get.py subprocess)
  * httpx             one-shot HTTP/1.1 over TLS 1.3/TCP
  * requests          one-shot HTTP/1.1 over TLS 1.3/TCP (a second stack)
  * httpx-session     connection reuse (many requests, one flow)
  * requests-session  connection reuse (a third stack)
The wrapper `benign_traffic.py` translates the orchestrator's interface to
benign_clients.py and restricts it to these profiles. There are NO real
browsers on this path (an earlier Selenium-based generator was replaced; the
seven released runs are entirely non-browser).

ORDER MATTERS: software (winget), the CA and the venv install FIRST (with
internet); the ISOLATED network (static IP, no gateway, DNS -> NB1) + clock sync
apply LAST. Use --no-network to install only.

The benign clients depend on THREE PyPI packages that the project metadata does
not pin: `aioquic`, `httpx`, `requests`. This script installs them explicitly
into the venv WHILE ONLINE (they cannot be fetched after the air-gap). On the
real bench they were installed with `pip install aioquic httpx requests`;
this script does the same into --venv.

--ca and --project are REQUIRED for a real run (the clients must trust the lab
CA, and the project provides benign_clients + benign_traffic). --dry-run
previews without them.

Run from an ELEVATED PowerShell:
    py configure_nb2.py --ca C:\\lab\\labCA.crt --project C:\\nids\\ProjetoDataset --dry-run
    py configure_nb2.py --ca C:\\lab\\labCA.crt --project C:\\nids\\ProjetoDataset
"""

import os
import sys
import lab_common as L

# The three non-browser client dependencies, installed explicitly WHILE ONLINE
# (project metadata does not pin them; they must be present before the air-gap).
BENIGN_CLIENT_PKGS = ["aioquic", "httpx", "requests"]

# Prove the clients can import their stacks (the same guarded imports
# benign_clients.py / h3_get.py do at runtime). Runs in the venv, online.
CLIENTS_IMPORT_CHECK = (
    "import aioquic, httpx, requests;"
    "from aioquic.asyncio.client import connect;"
    "print('benign client stacks OK:', "
    "'aioquic', getattr(aioquic,'__version__','?'), "
    "'httpx', httpx.__version__, 'requests', requests.__version__)"
)


def main() -> int:
    p = L.common_parser(__doc__)
    p.add_argument("--ca", default=None, help="path to labCA.crt (import into Root) — REQUIRED")
    p.add_argument("--skip-ca", action="store_true", help="skip CA import (still VERIFIES it is in Root)")
    p.add_argument("--skip-project", action="store_true",
                   help="skip project install + client deps (advanced; do it another way)")
    p.add_argument("--venv", default=r"C:\nids-experiment\dataset-env", help="native venv location")
    args = p.parse_args()
    ctx = L.make_ctx(args)
    L.require_windows(ctx)
    L.require_admin(ctx)
    # Requirements are enforced on REAL runs only; --dry-run always previews.
    if not ctx.dry_run:
        if not args.ca and not args.skip_ca:
            L.log("--ca <labCA.crt> is REQUIRED (the clients must trust the lab CA). "
                  "Use --skip-ca only if it is already imported.", "FATAL")
            return 1
        if not args.project and not args.skip_project:
            L.log("--project <ProjetoDataset> is REQUIRED (installs benign_clients + benign_traffic). "
                  "Use --skip-project only if done another way.", "FATAL")
            return 1
    if args.skip_project:
        L.log("--skip-project: assumes the project + client deps are ALREADY installed in --venv. "
              "The final checks still verify the project + client stacks, or provisioning fails.", "WARN")
    if not L.confirm(ctx, "Configure THIS machine as NB2 (benign, 10.10.10.20)?"):
        L.log("aborted by user")
        return 1
    nic = L.detect_ethernet(ctx)
    L.log(f"Using Ethernet adapter: {nic}")

    # ===== INSTALL PHASE (needs internet) =====
    L.winget_install("Python.Python.3.12", ctx)
    if args.ca:
        L.step(f"Import lab CA into Root store: {args.ca}")
        L.run(["certutil", "-addstore", "-f", "Root", args.ca], ctx)
    vpy = os.path.join(args.venv, "Scripts", "python.exe")
    if args.project:
        L.step(f"Create venv {args.venv} and install {args.project}")
        L.run(["py", "-3.12", "-m", "venv", args.venv], ctx, check=False)
        L.run([vpy, "-m", "pip", "install", "-e", args.project], ctx, check=False)
        # The benign clients need aioquic/httpx/requests, which the project metadata
        # does NOT pin -> install them explicitly, WHILE ONLINE, into the venv.
        L.step("pip install the benign-client deps (aioquic httpx requests) — WHILE ONLINE")
        L.run([vpy, "-m", "pip", "install", *BENIGN_CLIENT_PKGS], ctx, check=False)

    # ===== VERIFY INSTALLS (fail-closed on the OUTCOMES that matter) =====
    checks = [
        ("Python launcher (py)", ["where", "py"], True),
        # ALWAYS verify the CA is trusted (whether we imported it or --skip-ca claims it):
        ("lab CA in Root store", ["powershell", "-NoProfile", "-Command",
            "if ((certutil -store Root) -match 'Lab Root CA'){exit 0} else {exit 1}"], True),
    ]
    # Verify the project + client stacks whenever --project was requested (confirm the
    # install actually worked, even in --no-network) OR the network will be isolated
    # (they must be present before the air-gap). Only a bare --no-network skips it.
    if args.project or not args.no_network:
        checks.append(("project installed (pip show)", [vpy, "-m", "pip", "show", "nids-encrypted-dataset"], True))
        checks.append(("benign client stacks import (aioquic/httpx/requests, online)",
                       [vpy, "-c", CLIENTS_IMPORT_CHECK], True))
    if not L.final_checks(checks, ctx):
        L.log("PROVISIONING INCOMPLETE — see FAIL above. Network NOT changed.", "FATAL")
        return 1

    # ===== NETWORK PHASE (LAST — cuts internet) =====
    if args.no_network:
        L.log("--no-network: install done, network unchanged. Re-run WITHOUT --no-network to isolate.", "OK")
        return 0
    L.log("Applying the ISOLATED network now — internet will drop. Installs are done.", "WARN")
    L.set_static_ip(nic, L.ROLE_IP["nb2"], ctx)
    L.set_dns(nic, L.SERVER_IP, ctx)
    L.step(f"Sync Windows clock to NB1 ({L.SERVER_IP}) in CLIENT mode (,0x8)")
    L.run(["w32tm", "/config", f"/manualpeerlist:{L.SERVER_IP},0x8",
           "/syncfromflags:manual", "/update"], ctx, check=False)
    L.run(["w32tm", "/resync"], ctx, check=False)

    L.log("NB2 provisioning done.", "OK")
    L.log("For a PUBLICATION, record the installed client versions "
          "(pip freeze | findstr /I \"aioquic httpx requests\") alongside the run provenance.", "WARN")
    print(f"""
Next (guide section 7 / Anexo B.2), in PowerShell:
  {os.path.join(args.venv, 'Scripts', 'Activate.ps1')}
  python src\\benign_traffic.py --minutes 5 --campaign lab\\campaign.official.json `
    --run-id 0 --attempt-id <ID> --log-jsonl out\\run0\\benign.jsonl --headless
  # (benign_traffic.py wraps benign_clients.py and runs the five Python-only profiles)
Acceptance: the clients fetch https://blog.lab WITHOUT a certificate warning
(HTTP/3 via aioquic + HTTP/1.1 via httpx/requests); a benign JSONL is written.
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
