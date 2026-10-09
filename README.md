# Reconpulse

Reconpulse is a lightweight, dependency-free network reconnaissance and vulnerability
verification scanner written in C. It discovers live hosts, enumerates open
TCP/UDP services, fingerprints them, and actively verifies a curated set of
high-impact vulnerabilities rather than just inferring them from a version
string.

Unlike general-purpose network mappers, Reconpulse trades broad protocol coverage
for **depth and proof**: each vulnerability module either confirms
exploitability directly against the live target (e.g. triggering a known
backdoor and executing a command) or is explicitly marked as a lower-confidence,
banner-based match when active verification isn't safe or feasible. Every
finding is reported with severity, confidence, evidence, and remediation
guidance.

## Features

- Multi-threaded TCP connect scanning; raw-socket half-open (SYN) scanning on
  Linux; UDP scanning via connected-socket ICMP-error detection (no root
  required).
- Host discovery layered in four stages for reliability, so a live host has to
  evade all of them to be missed:
  1. **Active ARP** request/reply (Linux raw AF_PACKET / Windows `SendARP`),
     retransmitted to survive a dropped packet — works below IP-level
     filtering, so it finds firewalled local hosts.
  2. **ICMP echo** over an *unprivileged* datagram socket first (works without
     root on macOS, and on Linux where `ping_group_range` allows), falling back
     to a raw socket. Replies are matched by source address, so a busy subnet
     can't make one host's reply look like everyone's.
  3. **Broad TCP connect probe** across ~30 common ports — catches routed hosts
     ARP can't reach and any host with a reachable port.
  4. **Neighbor-cache catch-all** — after the probes above have forced layer-2
     resolution, the OS ARP/neighbor table is read (`/proc/net/arp` on Linux,
     the routing socket on macOS/BSD). This finds the "silent" devices — phones,
     printers, IoT and fully-firewalled machines — that answer ARP but drop
     every ping and SYN. Off-subnet targets never enter the local table, so this
     never false-positives a routed range.
- Banner grabbing and service/version fingerprinting.
- 19 vulnerability-check modules (see below), each independently dispatched
  based on the service actually found open.
- CLI, JSON, and standalone styled HTML report output.
- Built-in authorization gate — the tool refuses to run without an explicit
  `--authorize` flag.

## Vulnerability modules

| Port | Service | Check | Confidence |
|---|---|---|---|
| 21 | vsftpd | CVE-2011-2523 backdoor — verifies remote shell on port 6200 | Confirmed |
| 21/2121 | FTP | Default/weak credential login | Confirmed |
| 2121 | ProFTPD | CVE-2010-4221 version match | Likely |
| 22 | SSH | Outdated OpenSSH version match | Likely |
| 23 | Telnet | Default/weak credential login | Confirmed |
| 25 | SMTP | VRFY username enumeration | Confirmed |
| 111 | RPC/NFS | mountd reachability via portmapper | Confirmed |
| 139/445 | Samba | CVE-2007-2447 (usermap_script) version match | Likely |
| 513 | rlogin | Passwordless trust-based root login | Confirmed |
| 1099 | Java RMI | Unauthenticated registry exposure | Confirmed |
| 1524 | ingreslock | Unauthenticated bound root shell | Confirmed |
| 3306 | MySQL | Empty-password root login | Confirmed |
| 3632 | distccd | CVE-2004-2687 exposure (unauthenticated RCE service) | Confirmed |
| 5432 | PostgreSQL | Default/trust authentication | Confirmed |
| 5900 | VNC | No-authentication / password-only detection | Confirmed / Likely |
| 6000 | X11 | Open access control check | Confirmed |
| 6667 | UnrealIRCd | CVE-2010-2075 backdoor — verifies remote command execution | Confirmed |
| 8180 | Tomcat | Manager default credential login | Confirmed |

"Confirmed" means the module actively proved the condition against the live
target (e.g. executed `id` through a backdoor and parsed the output).
"Likely" means the finding is based on version/banner matching, used where
active verification would require capabilities out of scope for a
dependency-free scanner (SSH's cryptographic handshake, full SMB session
setup, VNC's DES challenge-response) or would risk crashing the service
(ProFTPD's overflow). These gaps are documented, not hidden — see Roadmap.

## Setup (Linux)

The fastest path on Linux is the bundled setup script. It detects your package
manager (apt, dnf/yum, pacman, zypper, apk), installs a C11 toolchain and
`make`, compiles the scanner, and can grant the raw-socket capability used by
SYN scanning and ICMP discovery.

```
./setup.sh              # install build deps, then compile
./setup.sh --caps       # also grant CAP_NET_RAW so SYN/ICMP work without sudo
./setup.sh --no-install # skip package install, just compile
./setup.sh --help
```

After it finishes you'll have a `./reconpulse` binary in the project root.

## Build

If you'd rather build by hand, Reconpulse needs only a C11 compiler and `make`
— no third-party libraries.

```
make        # builds ./reconpulse (or reconpulse.exe under MinGW on Windows)
```

- **Linux**: full functionality, including raw-socket SYN scanning and ICMP
  ping (both need root/`CAP_NET_RAW` — see `setup.sh --caps`).
- **macOS / other POSIX**: everything except SYN scanning, which transparently
  falls back to a TCP connect scan.
- **Windows**: build with MinGW-w64 (posix-threads variant, for pthread
  support) and link against `ws2_32`/`iphlpapi` (handled automatically by the
  Makefile). ICMP discovery uses `IcmpSendEcho` and needs no elevated
  privileges. SYN scanning is not implemented on Windows (raw TCP send is
  blocked by the OS since XP SP2); a future revision can add it via Npcap.

## Usage

### CLI

```
./reconpulse -t 192.168.56.101 --authorize
./reconpulse -t 192.168.56.0/24 -p 1-9000 --threads 100 --authorize
./reconpulse -t 192.168.56.101 --scan-type syn --format html -o report.html --authorize
```

Run `./reconpulse --help` for the full option list.

### Web dashboard

```
./reconpulse --serve --web-port 8888 --authorize
```

Then open `http://localhost:8888`. The dashboard is a dark, monospace
terminal-style operations console served directly by the binary itself — the
page you see is compiled in (`web/index.html` is embedded as a byte array at
build time, so there's no separate web server, framework, or file to ship
alongside the executable).

From the dashboard you configure and launch a network sweep — CIDR range, port
range, threads, timeout, vulnerability checks on/off — watch it run, and review
live/past results (open ports, service versions, and findings with severity,
confidence, evidence, and remediation) without touching a terminal. It always
uses the TCP-connect scan (the most reliable, no-privilege method); if you need
SYN or UDP, use the CLI's `--scan-type`. A history panel keeps every scan run in
the current session for quick recall.

The dashboard talks to the same engine as the CLI over a small local JSON
API:

- `POST /api/scan` — submit a scan (`target`, `port_start`, `port_end`,
  `scan_type`, `threads`, `timeout_ms`, `vuln_checks`), returns `{ "job_id" }`
- `GET /api/scan/<id>` — poll a job's status; returns full results once done
- `GET /api/jobs` — list all scans run this session

`--authorize` at launch applies to every scan submitted through the
dashboard for that session — the same ethical gate as the CLI, not a
separate opt-in per request.

## Legal and ethical use

Reconpulse performs active exploitation-verification (backdoor triggers, default
credential logins) against the target. **Only scan systems you own or have
explicit written authorization to test.** The `--authorize` flag is a
deliberate friction point, not a formality — treat it the same way you would
a pentest rules-of-engagement sign-off. This project was built and validated
against Metasploitable2, an intentionally vulnerable virtual machine designed
for exactly this kind of testing.

## Architecture

```
include/reconpulse/     public headers
src/net/            cross-platform socket helpers, thread pool
src/discovery/      host liveness (ARP, then ICMP, then TCP fallback)
src/portscan/       TCP connect / SYN / UDP scanners
src/service/        banner grabbing, fingerprinting
src/vulns/          one file per vulnerability module + dispatch registry
src/report/         CLI, JSON, HTML output (shared JSON builder used by both the file report and the dashboard API)
src/scan_engine.c   shared scan orchestration used by both the CLI and the dashboard's scan jobs
src/web/            embedded HTTP server + dashboard API + generated HTML asset
web/index.html      dashboard source (edit this, then `make embed` to regenerate the embedded copy)
```

Each vulnerability module is registered against the port(s) it applies to in
`src/vulns/vuln_registry.c` and only runs if that port was found open — the
same dispatch pattern used by plugin-based scanners (Nmap's NSE, Nessus'
NASL), implemented here as a plain C function-pointer table with no scripting
runtime.

## Roadmap

- Full SMB session-setup implementation to actively trigger CVE-2007-2447
  rather than version-match it.
- DES implementation for active VNC password verification.
- Npcap-based SYN scanning on Windows.
