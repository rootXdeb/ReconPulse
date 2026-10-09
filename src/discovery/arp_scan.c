#include <stdio.h>
#include <string.h>
#include "reconpulse/discovery.h"

#if defined(_WIN32)

#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#pragma comment(lib, "iphlpapi.lib")

int arp_probe(const char *ip, int timeout_ms)
{
    (void)timeout_ms; /* SendARP manages its own internal retry/timeout */
    IPAddr dest = inet_addr(ip);
    if (dest == INADDR_NONE) return -1;

    ULONG mac[2];
    ULONG mac_len = 6;
    return SendARP(dest, 0, mac, &mac_len) == NO_ERROR ? 1 : 0;
}

#elif defined(__linux__)

/* Raw AF_PACKET ARP request/reply. Requires root/CAP_NET_RAW, and only
 * finds hosts on the same local (L2) subnet as this machine — ARP never
 * crosses a router, so a routed target correctly falls through to the
 * ICMP/TCP-probe stages in host_is_alive() instead. */

#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

static int ipv4_to_u32(const char *ip, uint32_t *out)
{
    struct in_addr a;
    if (inet_pton(AF_INET, ip, &a) != 1) return -1;
    *out = a.s_addr; /* network byte order */
    return 0;
}

/* Finds the non-loopback, up, AF_INET interface whose subnet contains
 * target_ip, returning its name, ifindex, local IPv4, and MAC. */
static int find_local_interface(uint32_t target_ip, char *ifname_out, size_t ifname_len,
                                 int *ifindex_out, uint32_t *local_ip_out, uint8_t mac_out[6])
{
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) != 0) return -1;

    int found = -1;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK)) continue;
        if (!ifa->ifa_netmask) continue;

        uint32_t local = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
        uint32_t mask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;

        if ((local & mask) != (target_ip & mask)) continue;

        snprintf(ifname_out, ifname_len, "%s", ifa->ifa_name);
        *local_ip_out = local;
        found = 0;
        break;
    }
    freeifaddrs(ifaddr);
    if (found != 0) return -1;

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname_out);

    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) { close(s); return -1; }
    *ifindex_out = ifr.ifr_ifindex;

    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) { close(s); return -1; }
    memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);

    close(s);
    return 0;
}

int arp_probe(const char *ip, int timeout_ms)
{
    uint32_t target_ip;
    if (ipv4_to_u32(ip, &target_ip) != 0) return -1;

    char ifname[IFNAMSIZ];
    int ifindex;
    uint32_t local_ip;
    uint8_t local_mac[6];
    if (find_local_interface(target_ip, ifname, sizeof(ifname), &ifindex, &local_ip, local_mac) != 0)
        return -1; /* target isn't on any local subnet we have an interface for */

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) return -1; /* no privileges — caller falls back to ICMP/TCP */

    uint8_t frame[42];
    memset(frame, 0xFF, 6);                       /* Ethernet dest: broadcast */
    memcpy(frame + 6, local_mac, 6);               /* Ethernet src */
    frame[12] = 0x08; frame[13] = 0x06;            /* ethertype: ARP */

    uint8_t *arp = frame + 14;
    arp[0] = 0x00; arp[1] = 0x01;                  /* htype: Ethernet */
    arp[2] = 0x08; arp[3] = 0x00;                  /* ptype: IPv4 */
    arp[4] = 6;                                    /* hlen */
    arp[5] = 4;                                    /* plen */
    arp[6] = 0x00; arp[7] = 0x01;                  /* oper: request */
    memcpy(arp + 8, local_mac, 6);                 /* sender MAC */
    memcpy(arp + 14, &local_ip, 4);                /* sender IP */
    memset(arp + 18, 0x00, 6);                     /* target MAC: unknown */
    memcpy(arp + 24, &target_ip, 4);               /* target IP */

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_halen = 6;
    sll.sll_protocol = htons(ETH_P_ARP);
    memset(sll.sll_addr, 0xFF, 6);

    /* Retransmit a few times: a single ARP request can be dropped under
     * load or on a busy switch, and one lost packet must not make a live
     * host look dead. The timeout budget is split across the attempts. */
    const int attempts = 3;
    int per_attempt = timeout_ms / attempts;
    if (per_attempt < 120) per_attempt = 120;

    int result = 0;
    for (int a = 0; a < attempts && !result; a++) {
        if (sendto(sock, frame, sizeof(frame), 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            close(sock);
            return -1;
        }

        /* Fresh timeout each iteration — select() decrements tv on Linux,
         * so it must be reset or later waits collapse to zero. */
        struct timeval tv = { per_attempt / 1000, (per_attempt % 1000) * 1000 };
        for (;;) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sock, &rfds);

            int rc = select(sock + 1, &rfds, NULL, NULL, &tv);
            if (rc <= 0) break; /* timed out for this attempt — retransmit */

            uint8_t buf[128];
            int n = (int)recv(sock, buf, sizeof(buf), 0);
            if (n < 42) continue;
            if (buf[12] != 0x08 || buf[13] != 0x06) continue; /* not ARP */

            const uint8_t *rarp = buf + 14;
            int oper = (rarp[6] << 8) | rarp[7];
            if (oper != 2) continue; /* not a reply */

            uint32_t sender_ip;
            memcpy(&sender_ip, rarp + 14, 4);
            if (sender_ip == target_ip) { result = 1; break; }
        }
    }

    close(sock);
    return result;
}

#else /* macOS/BSD: no portable raw-ARP path here — degrade gracefully */

int arp_probe(const char *ip, int timeout_ms)
{
    (void)ip; (void)timeout_ms;
    return -1;
}

#endif
