#!/usr/bin/env python3
"""
configure_nb3.py - provisioner for NB3 (attacker) on NATIVE Ubuntu 24.04 LTS.

Machine: Acer Aspire E5-573 ("DESKTOP-HK2BVES", 932 GB), 10.10.10.30.
Role: offensive tools (nmap / hydra / slowhttptest / hping3) via run_attacks.py,
ONLY against the victim 10.10.10.11, in the isolated lab.

ORDER MATTERS: tools/project are installed FIRST (with internet); the ISOLATED
network (static IP, no gateway, DNS -> NB1) is applied LAST. Use --no-network to
install only and apply the network later.

Usage (ON the Ubuntu machine, WITH SUDO; --project is verified before isolating):
    sudo python3 configure_nb3.py --project ~/ProjetoDataset --dry-run
    sudo python3 configure_nb3.py --project ~/ProjetoDataset
    sudo python3 configure_nb3.py --no-network      # install tools only (verify project later)
"""

import sys
import lab_common as L


def main() -> int:
    p = L.common_parser(__doc__)
    p.add_argument("--iface", default=None, help="wired interface (auto-detected if omitted)")
    args = p.parse_args()
    ctx = L.make_ctx(args)
    L.require_linux(ctx)
    L.require_root(ctx)
    if not L.confirm(ctx, "Configure THIS Ubuntu machine as NB3 (attacker, 10.10.10.30)?"):
        L.log("aborted by user")
        return 1
    iface = L.detect_linux_iface(ctx, args.iface)
    L.log(f"Using wired interface: {iface}")

    # ===== INSTALL PHASE (needs internet) =====
    L.linux_apt_install(
        ["nmap", "hydra", "slowhttptest", "hping3",
         "chrony", "python3-venv", "python3-pip", "git"], ctx)
    if args.project:
        L.linux_install_project(args.project, ctx)

    # ===== VERIFY INSTALLS (fail-closed) =====
    checks = [
        ("nmap present", ["bash", "-lc", "command -v nmap"], True),
        ("hydra present", ["bash", "-lc", "command -v hydra"], True),
        ("slowhttptest present", ["bash", "-lc", "command -v slowhttptest"], True),
        ("hping3 present", ["bash", "-lc", "command -v hping3"], True),
        ("chrony present", ["bash", "-lc", "command -v chronyc"], True),
    ]
    # Verify the project (in ~/nids-env) whenever --project was requested OR the network
    # will be isolated. A pre-existing manual install is accepted (the check finds it).
    if args.project or not args.no_network:
        checks.append(("project installed (pip show)", ["bash", "-lc",
            "H=$(getent passwd ${SUDO_USER:-root} | cut -d: -f6); "
            "\"$H/nids-env/bin/pip\" show nids-encrypted-dataset >/dev/null"], True))
    if not L.final_checks(checks, ctx):
        L.log("PROVISIONING INCOMPLETE — a critical check FAILED (see the [FAIL] lines above: "
              "tools and/or the project). Network NOT changed.", "FATAL")
        return 1

    # ===== NETWORK PHASE (LAST — cuts internet) =====
    if args.no_network:
        L.log("--no-network: install done, network unchanged. Re-run WITHOUT --no-network "
              "to isolate.", "OK")
        return 0
    L.log("Applying the ISOLATED network now — internet will drop. Installs are done.", "WARN")
    L.linux_netplan_static(iface, L.ROLE_IP["nb3"], L.SERVER_IP, ctx)  # DNS -> NB1
    L.linux_chrony_client(ctx)

    L.log("NB3 provisioning done.", "OK")
    L.log("Use your REAL wordlists and put their sha256 in the campaign manifest.", "WARN")
    print("""
Next (guide section 8 / Anexo B.3):
  getent hosts blog.lab            # -> 10.10.10.11
  nmap -Pn -p 443 10.10.10.11      # 443 open
  source ~/nids-env/bin/activate && cd <ProjetoDataset>
  python3 src/run_attacks.py --list-configs
  # then, with NB4 already capturing, run the campaign attacks.
Attacks ONLY against 10.10.10.11, inside the isolated lab.
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
