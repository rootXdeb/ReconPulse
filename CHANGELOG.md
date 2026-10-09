# Changelog

## Unreleased

- **Much more reliable host discovery.** Added an unprivileged datagram-ICMP
  path (detects ping-responsive hosts without root) and a neighbor-cache
  catch-all that reads the OS ARP table to find silent/firewalled devices that
  answer ARP but drop every ping and SYN. ARP requests are now retransmitted.
- **Fixed a discovery false-positive under concurrency**: ICMP replies are now
  matched by source address, so one live host no longer makes every host in a
  parallel sweep report as alive.
- Web dashboard is now network-sweep-focused: removed the scan-type selector
  (always TCP connect) and the target field is a CIDR network range; restyled
  the inputs and the primary action button.
- Renamed the project to **Reconpulse** (binary is now `reconpulse`).
- Redesigned the web dashboard as a dark, monospace terminal-style operations
  console (JetBrains Mono, high-contrast brutalist layout).
- Added `setup.sh` — a Linux installer that provisions the build toolchain via
  the system package manager, compiles the tool, and can grant `CAP_NET_RAW`.

## 0.1.0

- Initial release: multi-threaded TCP connect/SYN/UDP port scanning, ICMP/TCP-probe host discovery, banner-based service fingerprinting.
- 19 vulnerability-check modules covering FTP, SSH, Telnet, SMTP, RPC/NFS, SMB, r-services, Java RMI, an ingreslock backdoor, MySQL, distccd, PostgreSQL, VNC, X11, IRC, and Tomcat.
- CLI, JSON, and standalone HTML report output.
- Cross-platform core (Linux, macOS, Windows via MinGW/Npcap); raw-socket SYN scan and ARP discovery are Linux-only and degrade gracefully elsewhere.
