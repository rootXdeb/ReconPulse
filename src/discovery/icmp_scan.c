#include <string.h>
#include <stdlib.h>
#include "reconpulse/discovery.h"
#include "reconpulse/netutils.h"

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#pragma comment(lib, "iphlpapi.lib")

static int icmp_ping(const char *ip, int timeout_ms)
{
    HANDLE h = IcmpCreateFile();
    if (h == INVALID_HANDLE_VALUE) return 0;

    IPAddr dest;
    dest = inet_addr(ip);

    char send_data[] = "reconpulse-ping";
    char reply_buf[sizeof(ICMP_ECHO_REPLY) + sizeof(send_data) + 8];

    DWORD ret = IcmpSendEcho(h, dest, send_data, sizeof(send_data),
                              NULL, reply_buf, sizeof(reply_buf), (DWORD)timeout_ms);
    IcmpCloseHandle(h);
    return ret != 0;
}

#else /* POSIX */

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>

/* Built as a raw byte buffer at fixed offsets (type/code/checksum/id/seq,
 * per RFC 792) rather than cast onto the system's `struct icmp` — that
 * BSD-derived struct name is declared inconsistently across libcs and
 * feature-test-macro settings, and the wire layout here is simple and
 * fixed enough not to need it. Same rationale as the SYN scanner. */
#define ICMP_ECHO_REQUEST 8
#define ICMP_HDR_LEN 8

static uint16_t icmp_checksum(const void *buf, int len)
{
    const uint16_t *word = buf;
    uint32_t sum = 0;
    for (; len > 1; len -= 2) sum += *word++;
    if (len == 1) sum += *(const uint8_t *)word;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

static int icmp_ping(const char *ip, int timeout_ms)
{
    /* Prefer the unprivileged datagram-ICMP socket: on macOS any user may
     * open it, and on Linux it works whenever the caller's group falls in
     * net.ipv4.ping_group_range (the common default). Fall back to a raw
     * socket (needs root/CAP_NET_RAW) only if the datagram one is refused.
     * This is what lets a non-root run still detect ICMP-responsive hosts
     * instead of dropping straight to the TCP probe. */
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock < 0) sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) return -1; /* neither permitted — caller falls back */

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(sock);
        return -1;
    }

    uint8_t pkt[ICMP_HDR_LEN + 16];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = ICMP_ECHO_REQUEST; /* type */
    pkt[1] = 0;                 /* code */
    pkt[2] = 0; pkt[3] = 0;     /* checksum, filled below */
    uint16_t id = (uint16_t)getpid();
    pkt[4] = (uint8_t)(id >> 8); pkt[5] = (uint8_t)(id & 0xFF);
    pkt[6] = 0; pkt[7] = 1;      /* sequence = 1 */
    memcpy(pkt + ICMP_HDR_LEN, "reconpulse-ping-icmp", 16);

    /* icmp_checksum reads 16-bit words in the host's native order, not
     * forced big-endian — that's what makes the one's-complement result
     * self-consistent. Store it with a raw memcpy, not a manual byte split. */
    uint16_t cksum = icmp_checksum(pkt, sizeof(pkt));
    memcpy(pkt + 2, &cksum, 2);

    if (sendto(sock, pkt, sizeof(pkt), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    /* Wait for an echo reply *from this target*. Raw ICMP sockets receive a
     * copy of every ICMP packet on the host, and even datagram ICMP sockets
     * can hand back a reply belonging to a different probe when many run at
     * once — so we must verify the source address, or one live host makes
     * every concurrent probe report "alive". Keep reading until the deadline
     * rather than giving up on the first (possibly foreign) packet. */
    struct timeval start, now;
    gettimeofday(&start, NULL);

    for (;;) {
        gettimeofday(&now, NULL);
        long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
        long remain = timeout_ms - elapsed_ms;
        if (remain <= 0) { close(sock); return 0; }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        struct timeval tv = { remain / 1000, (remain % 1000) * 1000 };

        int rc = select(sock + 1, &rfds, NULL, NULL, &tv);
        if (rc <= 0) { close(sock); return 0; }

        uint8_t buf[512];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int n = (int)recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len);
        if (n <= 0) { close(sock); return 0; }

        /* Only accept a reply whose source is the host we probed. */
        if (from.sin_addr.s_addr != addr.sin_addr.s_addr) continue;

        /* A datagram ICMP socket hands back the ICMP message with no IP
         * header; a raw socket prepends the IP header. Locate the ICMP type
         * in either case and only count an actual echo reply (type 0). */
        int icmp_type = -1;
        if ((buf[0] >> 4) == 4) {              /* looks like an IPv4 header */
            int ihl = (buf[0] & 0x0F) * 4;
            if (n > ihl) icmp_type = buf[ihl];
        } else {
            icmp_type = buf[0];
        }
        if (icmp_type == 0) { close(sock); return 1; }  /* echo reply from target */
        /* some other ICMP message from the target (e.g. an error) — keep waiting */
    }
}

#endif

static int tcp_probe_alive(const char *ip, int timeout_ms)
{
    /* Broad enough to catch most real hosts regardless of OS or role —
     * Windows (135/139/445/3389), Linux/Unix (22/111), mail (25/110/143/
     * 993/995), web (80/443/8080/8443), databases (3306/5432/1433),
     * VNC/remote-admin (5900/5985), and a few common IoT/embedded/legacy
     * ports (23/53/161/1723/9100). timeout_ms is split across all of
     * them, so a wider list doesn't blow up total worst-case scan time. */
    static const int common_ports[] = {
        21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 161, 389, 443,
        445, 465, 587, 993, 995, 1433, 1723, 2049, 3306, 3389, 5432, 5900,
        5985, 8080, 8443, 9100
    };
    int n = (int)(sizeof(common_ports) / sizeof(common_ports[0]));

    for (int i = 0; i < n; i++) {
        socket_t s = net_tcp_connect(ip, common_ports[i], timeout_ms / n + 50);
        if (s != INVALID_SOCKET) {
            net_close(s);
            return 1;
        }
    }
    return 0;
}

int host_is_alive(const char *ip, int timeout_ms)
{
    /* Discovery needs a little breathing room even when the user picks a
     * tight per-port timeout for the port scan, or slower devices get
     * wrongly declared dead. */
    int disc_to = timeout_ms < 500 ? 500 : timeout_ms;

    /* Stage 1 — active raw ARP (Linux/Windows). Works below IP-level
     * filtering, so on the local subnet it's the single most reliable
     * signal. A 0/-1 result doesn't prove the host is dead (it may be
     * routed, or we may lack the privilege to send raw ARP), so we fall
     * through rather than trusting a negative result. */
    if (arp_probe(ip, disc_to) == 1) return 1;

    /* Stage 2 — ICMP echo (unprivileged datagram socket first, raw as a
     * fallback). Catches hosts that answer ping even when firewalled at
     * the TCP layer. Sending it also primes the kernel ARP cache. */
    if (icmp_ping(ip, disc_to) == 1) return 1;

    /* Stage 3 — broad TCP connect probe. Catches routed hosts (where ARP
     * never applies) and any host with at least one reachable port. Each
     * connect attempt also forces layer-2 ARP resolution of a local host,
     * priming the cache for stage 4 even when every port is filtered. */
    if (tcp_probe_alive(ip, timeout_ms) == 1) return 1;

    /* Stage 4 — neighbor-cache catch-all. Stages 2 and 3 have by now sent
     * packets toward the target; if it is a live host on our subnet it has
     * answered ARP (which no host firewall can suppress) and the kernel has
     * recorded its MAC, even though it never replied to a ping or a SYN.
     * This is what finds the "silent" devices — phones, printers, IoT and
     * fully-firewalled machines — that the earlier stages miss. Off-subnet
     * targets never land in the local table, so this won't false-positive
     * a routed range. */
    if (neighbor_is_reachable(ip) == 1) return 1;

    return 0;
}
