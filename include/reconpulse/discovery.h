#ifndef RECONPULSE_DISCOVERY_H
#define RECONPULSE_DISCOVERY_H

/* Best-effort liveness check, in order of preference:
 *   1. ARP (Linux: raw AF_PACKET request/reply; Windows: SendARP) — works
 *      below IP-level filtering, so it reliably finds live hosts on the
 *      local subnet even when they're firewalled against everything else.
 *   2. ICMP echo (raw socket on POSIX / IcmpSendEcho on Windows).
 *   3. TCP connect probe against a broad set of commonly-open ports —
 *      the last resort for hosts that are routed (not on the local
 *      subnet, so ARP doesn't apply) and have ICMP blocked.
 * Needs no privileges to fall back correctly: each stage that requires
 * elevated access degrades to "inconclusive" rather than "dead" when it
 * can't run, so a lower-privileged run still falls through to the next
 * stage instead of wrongly declaring a live host unreachable. */
int host_is_alive(const char *ip, int timeout_ms);

/* Returns 1 if an ARP reply was received for ip, 0 if none arrived within
 * timeout_ms, or -1 if ARP isn't applicable/available here (not on the
 * local subnet, no raw-socket privilege, or unsupported platform). */
int arp_probe(const char *ip, int timeout_ms);

/* Returns 1 if the OS ARP/neighbor cache holds a complete (MAC-resolved)
 * entry for ip — i.e. the host answered ARP and is live on the local
 * subnet — 0 if there's no complete entry, or -1 if the cache can't be
 * read on this platform. Needs no privileges. */
int neighbor_is_reachable(const char *ip);

#endif
