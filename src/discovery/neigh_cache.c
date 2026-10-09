/* Reads the operating system's ARP / neighbor cache to decide whether a
 * local-subnet host is alive.
 *
 * This is the catch-all that finds "silent" devices: phones, printers, IoT
 * gadgets and firewalled hosts that never answer an ICMP echo and drop every
 * TCP SYN, yet must still answer ARP to exist on the LAN at all (ARP lives
 * below IP-level filtering). Once anything on this machine has tried to send
 * a packet to such a host — an ICMP echo, a TCP connect — the kernel resolves
 * its MAC at layer 2 and records it here, even when the host ignores the
 * packet itself. Reading the cache needs no elevated privileges.
 *
 * A routed (non-local) target never appears in the local neighbor table — the
 * kernel only stores the gateway's MAC for it — so this never false-positives
 * an off-subnet address. */

#include <string.h>
#include <stdio.h>
#include "reconpulse/discovery.h"

#if defined(__linux__)

/* /proc/net/arp columns:
 *   IP address   HW type   Flags   HW address   Mask   Device
 * Flags bit 0x2 (ATF_COM) means the entry is complete (MAC known). */
int neighbor_is_reachable(const char *ip)
{
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) return -1;

    char line[256];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; } /* header */

    int result = 0;
    while (fgets(line, sizeof(line), f)) {
        char entry_ip[64], hw_type[32], flags[32], mac[64], mask[32], dev[64];
        if (sscanf(line, "%63s %31s %31s %63s %31s %63s",
                   entry_ip, hw_type, flags, mac, mask, dev) < 4)
            continue;
        if (strcmp(entry_ip, ip) != 0) continue;

        unsigned f_val = 0;
        sscanf(flags, "%x", &f_val);
        if ((f_val & 0x2) && strcmp(mac, "00:00:00:00:00:00") != 0) {
            result = 1;
            break;
        }
    }
    fclose(f);
    return result;
}

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

/* Dumps the kernel ARP table via the routing socket (the same mechanism
 * `arp -a` uses) and looks for a complete link-layer entry for `ip`. */
int neighbor_is_reachable(const char *ip)
{
    struct in_addr want;
    if (inet_pton(AF_INET, ip, &want) != 1) return -1;

    int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO };
    size_t needed = 0;
    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0 || needed == 0) return -1;

    char *buf = malloc(needed);
    if (!buf) return -1;
    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) { free(buf); return -1; }

    /* Route-message sockaddrs are padded to 4-byte (uint32_t) boundaries on
     * the BSD/macOS routing socket — not machine-word boundaries. Rounding
     * to sizeof(long) here misaligns the sockaddr_dl and reads a garbage
     * MAC length, which is what made every incomplete entry look complete. */
    #define RP_SA_RNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

    int result = 0;
    char *lim = buf + needed;
    for (char *next = buf; next < lim; ) {
        struct rt_msghdr *rtm = (struct rt_msghdr *)next;
        struct sockaddr_in *sin = (struct sockaddr_in *)(rtm + 1);
        size_t sa_len = sin->sin_len ? sin->sin_len : sizeof(struct sockaddr_in);
        struct sockaddr_dl *sdl = (struct sockaddr_dl *)((char *)sin + RP_SA_RNDUP(sa_len));

        if (sin->sin_addr.s_addr == want.s_addr) {
            if (sdl->sdl_alen == 6) result = 1; /* has a resolved Ethernet MAC */
            break;
        }
        next += rtm->rtm_msglen;
    }
    #undef RP_SA_RNDUP
    free(buf);
    return result;
}

#else

int neighbor_is_reachable(const char *ip)
{
    (void)ip;
    return -1;
}

#endif
