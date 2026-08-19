# Automated Provisioning for the NIDS Testbed

One Python provisioning script is provided for each notebook to automate the manual setup of networking, DNS, Docker, packages, clock synchronisation, and project dependencies. The single source of truth for addressing is `lab_common.py`.

| Script | Machine | Role | Operating System | IP Address |
|---|---|---|---|---|
| `configure_nb1.py` | Samsung "SAM" | Victim services + DNS/NTP | **Linux Mint 22.1 (native)** | 10.10.10.11 |
| `configure_nb2.py` | ASUS TUF "LAPTOP-27A6JIHC" | Benign traffic generator | Windows 11 (native) | 10.10.10.20 |
| `configure_nb3.py` | Acer "DESKTOP-HK2BVES" (932 GB) | Attacker | **Ubuntu 26.04 (native)** | 10.10.10.30 |
| `configure_nb4.py` | Acer "Secs" (1.35 TB) | Sensor / capture host | **Ubuntu 26.04 (native)** | mirrored port, no routable IP |

> **NB4 note.** The sensor was **reinstalled with native Ubuntu** and uses native `tcpdump` and Zeek. This is the configuration that produced the published dataset and corresponds to a generic Linux capture platform. The Windows time client is not used on this host. An earlier version of the provisioner treated NB4 as Windows + Npcap/dumpcap with Zeek running under WSL2; that path has been superseded by native capture and is no longer supported here.

> **Operating-system note.** NB1 runs Linux Mint 22.1 (Ubuntu 22.04 base) and NB3 runs Ubuntu 26.04. Both use the same native Linux provisioning path based on netplan, `apt`, and `chrony`. The scripts detect the operating-system version where required; for example, the Zeek repository is derived from the machine's `VERSION_ID`.

## Prerequisites

Complete these steps once on each machine.

1. **Python**
   - **Windows (NB2):**
     ```powershell
     winget install -e --id Python.Python.3.12
     ```
   - **Linux (NB1, NB3, NB4):** `python3` is expected to be already installed.

2. Copy the following files to each machine:
   - `lab_common.py`
   - the corresponding `configure_nbX.py`

   Keep both files in the **same directory**, because each provisioning script imports `lab_common`.

3. Perform the provisioning **while Internet access is still available and before the testbed is isolated (air-gapped)**.

## Usage

### NB1, NB3, and NB4 — native Linux

Run the scripts **on the corresponding Linux host with `sudo`**.

```bash
# NB1 — victim services + DNS/NTP (Linux Mint 22.1)
sudo python3 configure_nb1.py --project ~/ProjetoDataset --dry-run
sudo python3 configure_nb1.py --project ~/ProjetoDataset
# Add --yes to skip the interactive confirmation.

# NB3 — attacker (Ubuntu 26.04)
sudo python3 configure_nb3.py --project ~/ProjetoDataset

# NB4 — sensor (Ubuntu 26.04)
# Always provide --capture-nic. The mirrored capture interface will have its IP removed.
sudo python3 configure_nb4.py --capture-nic enp2s0 --project ~/ProjetoDataset --dry-run
sudo python3 configure_nb4.py --capture-nic enp2s0 --project ~/ProjetoDataset

# If a separate management interface is available for clock synchronisation with NB1:
#   add --nic <management-interface> --mgmt-ip 10.10.10.4
```

### NB2 — Windows

Open **PowerShell as Administrator** in the directory containing the scripts.

```powershell
# NB2 — always provide --ca and --project.
# First review the planned changes with --dry-run, then execute without it.
py configure_nb2.py --ca C:\lab\labCA.crt --project C:\nids\ProjetoDataset --dry-run
py configure_nb2.py --ca C:\lab\labCA.crt --project C:\nids\ProjetoDataset
```

## Provisioning Order

The provisioning workflow is intentionally ordered so that software and project dependencies are installed **before** the isolated network configuration is applied.

The scripts therefore:

1. install packages and project dependencies while Internet access is available;
2. perform the required checks;
3. apply the isolated network configuration without a default gateway **last**.

Use `--no-network` if you want to install the software first and apply the network configuration separately later.

Final checks are **fail-closed for critical requirements**, including packages, tools, and services such as Docker, `dnsmasq`, `chrony`, `nmap`, `hydra`, Zeek, `tcpdump`, and JA3 support. If a critical requirement fails, the script exits with an error instead of reporting successful provisioning.

Only checks that depend on the rest of the laboratory already being online remain **best-effort**. For example, NTP resynchronisation may not succeed while NB1 is still being provisioned.

## Common Command-Line Options

Common options:

```text
--dry-run
--yes
--no-network
--project <path>
```

Linux-specific option:

```text
--iface enp3s0
```

The interface is auto-detected if omitted.

Windows-specific option:

```text
--nic "Ethernet 2"
```

NB2-specific options:

```text
--ca <labCA.crt>
--venv
```

NB4-specific options:

```text
--capture-nic "<interface>"
--nic "<management-interface>" --mgmt-ip <ip>
```

`--capture-nic` removes the routable IP configuration from the capture interface.

`--nic` together with `--mgmt-ip` configures a **separate management interface**, used for administration and clock synchronisation.

## Recommended Provisioning Sequence

Provision the machines in the following order:

1. **NB1** — victim services + DNS/NTP
2. **NB2** — benign traffic generator
3. **NB3** — attacker
4. **NB4** — sensor

This sequence ensures that the victim-side infrastructure, DNS, and time services are available before the remaining hosts are finalised.

## What the Provisioning Scripts Do

The scripts configure:

- static IP addressing;
- DNS and NTP;
- Docker CE on NB1;
- operating-system packages through `apt` or `winget`;
- native Zeek from the official repository on NB4;
- clock synchronisation with `chrony` on Linux and `w32tm` on Windows;
- project installation through `pip install -e .` when `--project` is provided.

On Linux, network configuration is performed with netplan. On Windows, the scripts use `netsh`.

## What the Provisioning Scripts Do Not Do

The following tasks require campaign-specific coordination, certificates, or runtime orchestration and are therefore intentionally left outside the provisioning scripts:

- generating the internal certificate authority;
- starting and seeding the victim application stack on NB1 with `docker compose up`;
- launching attacks from NB3;
- capturing, labelling, validating, and sealing the dataset on NB4.

At the end of provisioning, each script prints the exact commands required for the relevant next steps.

## Operational Notes and Limitations

- **Hardware validation.** The provisioning scripts have not been validated on the final physical hardware through a complete provisioning run. They were checked using `--dry-run` and syntax validation of the generated shell commands. Review the `--dry-run` output carefully and provision one machine at a time.
- **NB1 DNS configuration.** The script disables `systemd-resolved` and assigns port 53 to `dnsmasq`, which is the intended configuration for the air-gapped DNS host. Validate name resolution from NB2 with `nslookup blog.lab`. On Linux Mint or Ubuntu Desktop, confirm that NetworkManager does not overwrite `/etc/resolv.conf`.
- **NB1 Docker access.** The provisioning process adds the user to the `docker` group. Log out and back in, or run `newgrp docker`, before using Docker without `sudo`.
- **NB4 native capture.** Packet capture is performed natively: `tcpdump` reads directly from the mirrored interface and Zeek processes the PCAP locally. Npcap and WSL are not used.
- **NB4 capture interface.** The capture NIC has **no routable IP address**. It may retain only an automatically assigned link-local address in `169.254.0.0/16`. `configure_nb4.py --capture-nic` applies this configuration.
- **NB4 clock discipline.** The kernel clock that timestamps the PCAP should remain synchronised with NB1. This can be achieved through the separate management interface configured with `--mgmt-ip`, or through prior synchronisation followed by verification during preflight.
- **NB2 certificate trust.** The command `certutil -addstore Root` installs a certificate authority in the machine-wide Windows trusted root store. Use this only with the laboratory CA.
- **Privileges.** Run the Linux provisioners (NB1, NB3, NB4) with `sudo`. Run the Windows provisioner (NB2) from an elevated PowerShell session.
