#!/usr/bin/env python3
"""
configure_nb4.py - provisioner for NB4 (passive sensor) on NATIVE Ubuntu 26.04 LTS.

Machine: Acer ("Secs", 1.35 TB), attached to the switch mirror-destination port.
Role: passive capture of the mirrored span with tcpdump; offline flow extraction
with Zeek + the Zeek flow-meter (zeek-flowmeter) and the ja3 package, all NATIVE
on Ubuntu. There is NO Windows/Npcap and NO WSL2 on this host: the sensor was
re-imaged to native Ubuntu, which is the configuration that produced the released
dataset (capture platform Linux-generic; the Windows time client is not used).

Capture facts:
  * The capture NIC sits on the mirror-destination port and is a SILENT sensor:
    its IPv4/IPv6 is stripped so it never transmits. It carries only an
    auto-assigned link-local (169.254.x.x) address, no routable IP.
  * PCAP timestamps come from the Linux kernel clock on this host, disciplined by
    chrony against NB1 over a SEPARATE management link (the capture port has no
    IP and cannot reach NB1).

ORDER MATTERS: tools/project are installed FIRST (with internet); the management
IP, the clock, and the stripping of the capture NIC are applied LAST. Use
--no-network to install only and apply the rest later.

Flags:
  --capture-nic "<name>"  the mirror NIC: its IPv4/IPv6 is stripped (silent sensor) — REQUIRED
  --project <path>        the ProjetoDataset checkout (e.g. ~/ProjetoDataset) for `pip install -e .`
  --nic "<name>" --mgmt-ip <ip>   optional management link (for time sync; BOTH together)

Usage (ON the Ubuntu machine, WITH SUDO; --dry-run previews; a real run needs --capture-nic):
    sudo python3 configure_nb4.py --capture-nic enp2s0 --project ~/ProjetoDataset --dry-run
    sudo python3 configure_nb4.py --capture-nic enp2s0 --project ~/ProjetoDataset
    # with a separate management link (time sync): add  --nic <mgmt-iface> --mgmt-ip 10.10.10.4
    sudo python3 configure_nb4.py --no-network      # install tools only (verify project later)
"""

import sys
import lab_common as L


def main() -> int:
    p = L.common_parser(__doc__)
    p.add_argument("--mgmt-ip", default=None,
                   help="management IPv4 on a SEPARATE NIC (needs --nic), used only for time sync")
    p.add_argument("--capture-nic", default=None,
                   help="mirror NIC name to strip of IPv4/IPv6 — REQUIRED on a real run")
    args = p.parse_args()
    ctx = L.make_ctx(args)
    L.require_linux(ctx)
    L.require_root(ctx)

    # flag-combo guards (valid to fire even in dry-run):
    if args.mgmt_ip and not args.nic:
        L.log("--mgmt-ip requires an explicit --nic (so the capture port is never touched).", "FATAL")
        return 1
    if args.nic and args.capture_nic and args.nic.strip().lower() == args.capture_nic.strip().lower():
        L.log("--nic (management) must DIFFER from --capture-nic (the mirror port stays IP-less).", "FATAL")
        return 1
    # missing-required is enforced on REAL runs only; --dry-run always previews:
    if not ctx.dry_run and not args.no_network and not args.capture_nic:
        L.log("--capture-nic \"<mirror NIC>\" is required (to strip its IPv4/IPv6). "
              "Use --no-network to install only.", "FATAL")
        return 1
    if not ctx.dry_run and not args.project:
        L.log("Sem --project: o projeto precisa JA estar instalado (~/nids-env) — a "
              "verificacao final confere e FALHA se nao estiver. Passe --project <path>.", "WARN")
    if not L.confirm(ctx, "Configure THIS Ubuntu machine as NB4 (passive sensor, native tcpdump/Zeek)?"):
        L.log("aborted by user")
        return 1

    # ===== INSTALL PHASE (needs internet) =====
    # Native capture + offline processing toolchain (no Npcap, no WSL):
    #   tcpdump   -> live capture of the mirrored span
    #   chrony    -> discipline the kernel clock (which stamps the PCAP) against NB1
    #   Zeek      -> offline flow extraction from the PCAP (installed below from the OBS repo)
    L.linux_apt_install(
        ["tcpdump", "chrony", "python3-venv", "python3-pip", "git", "curl", "gnupg"], ctx)
    L.linux_install_zeek(ctx)          # Zeek + zkg + zeek-flowmeter from the official OBS repo
    L.step("zkg: configure + install the ja3 package (JA3/JA3S TLS evidence)")
    L.run(["bash", "-lc",
           "PATH=/opt/zeek/bin:$PATH; export PATH; zkg autoconfig || true; "
           "zkg install --force ja3 || true"], ctx, check=False)
    if args.project:
        L.linux_install_project(args.project, ctx)

    # ===== VERIFY INSTALLS (fail-closed on the essentials) =====
    checks = [
        ("tcpdump present", ["bash", "-lc", "command -v tcpdump"], True),
        ("Zeek present", ["bash", "-lc", "command -v zeek || test -x /opt/zeek/bin/zeek"], True),
        ("chrony present", ["bash", "-lc", "command -v chronyc"], True),
        ("ja3 package installed (zkg)", ["bash", "-lc",
            "PATH=/opt/zeek/bin:$PATH; export PATH; zkg list 2>/dev/null | grep -qi ja3"], True),
    ]
    # Verify the project (in ~/nids-env) whenever --project was requested OR the network
    # will be isolated. A pre-existing manual install is accepted (the check finds it).
    if args.project or not args.no_network:
        checks.append(("project installed (pip show)", ["bash", "-lc",
            "H=$(getent passwd ${SUDO_USER:-root} | cut -d: -f6); "
            "\"$H/nids-env/bin/pip\" show nids-encrypted-dataset >/dev/null"], True))
    if not L.final_checks(checks, ctx):
        L.log("PROVISIONING INCOMPLETE — a critical check FAILED (see the [FAIL] lines above: "
              "tcpdump/Zeek/chrony/ja3 and/or the project). Network NOT changed.", "FATAL")
        return 1

    # ===== NETWORK / TIME PHASE (last) =====
    if args.no_network:
        L.log("--no-network: install done, capture NIC / clock unchanged.", "OK")
        return 0

    # Silence the mirror port FIRST (strip IPv4/IPv6 so the sensor never transmits).
    L.linux_strip_nic_ip(args.capture_nic, ctx)
    if not L.final_checks([
        ("capture NIC has no routable IPv4", ["bash", "-lc",
            f"ip -4 addr show dev {args.capture_nic} 2>/dev/null | grep -q 'inet ' "
            f"&& ! ip -4 addr show dev {args.capture_nic} | grep -q '169.254.' && exit 1 || exit 0"], True)],
            ctx):
        L.log("Capture NIC still has a routable IPv4 — fix and re-run.", "FATAL")
        return 1

    # Management link + clock (only if a separate management NIC was given).
    if args.mgmt_ip:
        L.set_static_ip(args.nic, args.mgmt_ip, ctx)   # management IP on the SEPARATE NIC
        L.linux_chrony_client(ctx)                      # discipline the kernel clock against NB1
    else:
        L.log("No --mgmt-ip: NB4 has no live path to NB1 for time. The kernel clock (which "
              "stamps the PCAP) must be PRE-SYNCED to NB1 and then confirmed in the preflight. "
              "See guide section 11.", "WARN")

    L.log("NB4 provisioning done.", "OK")
    cap = args.capture_nic or "<mirror NIC>"
    run_dir = "/mnt/nids-captures/run0"
    if args.project:
        proc = f"source ~/nids-env/bin/activate && cd {args.project}"
    else:
        proc = "# install the project first (or re-run with --project), then activate its venv"
    print(f"""
Next (guide section 9 / Anexo B.4):
  # CAPTURE (native) — tcpdump writes the PCAP directly from the mirror NIC:
  sudo mkdir -p {run_dir}
  sudo tcpdump -i {cap} -w {run_dir}/run0.pcap    # start BEFORE the run; Ctrl-C after
  # PROCESS — activate the venv and cd to the project first:
  {proc}
  python3 src/process_pcap.py --run-dir {run_dir} --run-id 0 --attempt-id <ID> --zeek
  python3 src/verify_switch_mirroring.py --conn {run_dir}/zeek/conn.log \\
    --client-ip 10.10.10.20 --victim-ip 10.10.10.11 --tcp-port 443 --udp-port 443
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
