#!/usr/bin/env python3
"""
configure_nb1.py - provisioner for NB1 (victims + infrastructure) on NATIVE
Ubuntu 24.04 LTS.

Machine: Samsung 550XCJ/550XCR ("SAM", 24 GB), 10.10.10.11.
Role: victim stack (2x WordPress + Caddy TLS1.3/HTTP3 + MariaDB) with Docker CE,
plus DNS (dnsmasq) + NTP (chrony) for the lab.

ORDER MATTERS: packages/project are installed FIRST (while the machine still has
internet); the ISOLATED network (static IP, no gateway, DNS -> local dnsmasq) is
applied LAST, because it cuts internet access. Use --no-network to install only
and apply the network later.

What it does NOT do (needs the certificate / campaign): generate the CA + cert
(Anexo A.3.1), `docker compose up` + seed_content.

Usage (ON the Ubuntu machine, WITH SUDO; --project is verified before isolating):
    sudo python3 configure_nb1.py --project ~/ProjetoDataset --dry-run   # preview
    sudo python3 configure_nb1.py --project ~/ProjetoDataset             # install, then isolate
    sudo python3 configure_nb1.py --no-network                           # install only (keep internet)
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
    if not L.confirm(ctx, "Configure THIS Ubuntu machine as NB1 (victims, 10.10.10.11)?"):
        L.log("aborted by user")
        return 1
    iface = L.detect_linux_iface(ctx, args.iface)
    L.log(f"Using wired interface: {iface}")

    # ===== INSTALL PHASE (needs internet) =====
    L.linux_install_docker(ctx)
    # dnsmasq/chrony PACKAGES here (config comes later); python3-venv/pip for --project
    L.linux_apt_install(["dnsmasq", "chrony", "python3-venv", "python3-pip"], ctx)
    if args.project:
        L.linux_install_project(args.project, ctx)

    # ===== VERIFY INSTALLS (fail-closed) =====
    checks = [
        ("docker CLI present", ["bash", "-lc", "command -v docker"], True),
        ("dnsmasq present", ["bash", "-lc", "command -v dnsmasq"], True),
        ("chrony present", ["bash", "-lc", "command -v chronyd || command -v chronyc"], True),
    ]
    # Verify the project (in ~/nids-env) whenever --project was requested OR the network
    # will be isolated. A pre-existing manual install is accepted (the check finds it).
    if args.project or not args.no_network:
        checks.append(("project installed (pip show)", ["bash", "-lc",
            "H=$(getent passwd ${SUDO_USER:-root} | cut -d: -f6); "
            "\"$H/nids-env/bin/pip\" show nids-encrypted-dataset >/dev/null"], True))
    if not L.final_checks(checks, ctx):
        L.log("PROVISIONING INCOMPLETE — a critical check FAILED (see the [FAIL] lines above: "
              "docker/dnsmasq/chrony and/or the project). Network NOT changed.", "FATAL")
        return 1

    # ===== NETWORK PHASE (LAST — cuts internet) =====
    if args.no_network:
        L.log("--no-network: install done, network unchanged. Re-run WITHOUT --no-network "
              "to isolate (installs are idempotent).", "OK")
        return 0
    L.log("Applying the ISOLATED network now — internet will drop. Installs are done.", "WARN")
    L.linux_netplan_static(iface, L.ROLE_IP["nb1"], "127.0.0.1", ctx)  # DNS -> local dnsmasq
    L.linux_dns_server(ctx)        # config only: blog.lab/shop.lab -> 10.10.10.11
    L.linux_chrony_server(ctx)     # config only: serve NTP to 10.10.10.0/24
    L.linux_ufw_allow_lab(ctx)

    if not L.final_checks([
        ("dnsmasq active", ["bash", "-lc", "systemctl is-active dnsmasq"], True),
        ("chrony active", ["bash", "-lc", "systemctl is-active chrony"], True),
    ], ctx):
        L.log("PROVISIONING INCOMPLETE — dnsmasq/chrony not active (see above).", "FATAL")
        return 1
    L.log("NB1 provisioning done.", "OK")
    L.log("Verify DNS from NB2: `nslookup blog.lab` -> 10.10.10.11.", "WARN")
    print("""
Next (guide Anexo A.3 / section 6), from ProjetoDataset/lab:
  1) generate the CA + certificate into lab/certs        (Anexo A.3.1)
  2) docker compose up -d && docker compose ps           (all healthy)
  3) python3 ../src/seed_content.py --url https://blog.lab  --admin-pass '...'  (+ shop.lab)
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
