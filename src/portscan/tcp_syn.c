#include "reconpulse/portscan.h"

#if defined(__linux__)

/* Raw-socket half-open (SYN) scan. Requires root / CAP_NET_RAW.
 *
 * The IP and TCP headers are built as plain byte buffers at fixed offsets
 * rather than cast onto the system's `struct iphdr`/`struct tcphdr`.
 * Those structs are defined differently (and sometimes only partially,
 * depending on feature-test macros) across glibc, musl, and BSD libcs —
 * exactly the kind of portability landmine not worth stepping on when the
 * on-wire layout is simple, fixed, and well documented (RFC 791 / RFC
 * 793). This also matches the hand-rolled-protocol style already used
 * for MySQL/RPC/etc. elsewhere in this codebase.
 *
 * Known caveat: once the SYN-ACK arrives, the Linux kernel's own TCP stack
 * (which knows nothing about our raw socket) will usually reply with an
 * unsolicited RST because it has no matching connection for that source
 * port. That RST does not affect scan accuracy — we've already classified
 * the port by the time it's sent — but on a real engagement you would
 * typically add a local firewall rule (e.g. `iptables -A OUTPUT -p tcp
 * --tcp-flags RST RST -j DROP`) to keep the kernel from tipping off the
 * target with a stray reset. Documented here rather than applied
 * automatically, since silently mutating firewall rules is not something
 * a scanner should do on its own.
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define IP_HDR_LEN  20
#define TCP_HDR_LEN 20

static uint16_t checksum16(const void *data, int len)
{
    uint32_t sum = 0;
    const uint16_t *p = data;
    for (; len > 1; len -= 2) sum += *p++;
    if (len == 1) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static void put_be16(uint8_t *buf, int off, uint16_t v)
{
    buf[off] = (uint8_t)(v >> 8);
    buf[off + 1] = (uint8_t)(v & 0xFF);
}

static void put_be32(uint8_t *buf, int off, uint32_t v)
{
    buf[off] = (uint8_t)(v >> 24);
    buf[off + 1] = (uint8_t)(v >> 16);
    buf[off + 2] = (uint8_t)(v >> 8);
    buf[off + 3] = (uint8_t)(v & 0xFF);
}

static uint16_t get_be16(const uint8_t *buf, int off)
{
    return (uint16_t)((buf[off] << 8) | buf[off + 1]);
}

static int get_local_ip(const char *dst_ip, char *out, size_t out_len)
{
    /* Connect a UDP socket to discover which local interface routes to
     * the target, without sending any actual traffic. */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, dst_ip, &addr.sin_addr);

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(s);
        return -1;
    }

    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    if (getsockname(s, (struct sockaddr *)&local, &len) < 0) {
        close(s);
        return -1;
    }
    inet_ntop(AF_INET, &local.sin_addr, out, (socklen_t)out_len);
    close(s);
    return 0;
}

port_state_t tcp_syn_scan_port(const char *ip, int port, int timeout_ms)
{
    char local_ip[INET_ADDRSTRLEN];
    if (get_local_ip(ip, local_ip, sizeof(local_ip)) != 0)
        return PORT_FILTERED;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return PORT_FILTERED; /* no privileges — caller should fall back */

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    uint16_t src_port = (uint16_t)(30000 + (getpid() % 20000));

    uint32_t src_addr, dst_addr;
    inet_pton(AF_INET, local_ip, &src_addr);
    inet_pton(AF_INET, ip, &dst_addr);

    uint8_t packet[IP_HDR_LEN + TCP_HDR_LEN];
    memset(packet, 0, sizeof(packet));

    /* --- IP header --- */
    packet[0] = 0x45; /* version 4, IHL 5 (20 bytes, no options) */
    packet[1] = 0x00; /* TOS */
    put_be16(packet, 2, (uint16_t)sizeof(packet));            /* total length */
    put_be16(packet, 4, (uint16_t)(getpid() & 0xFFFF));       /* identification */
    put_be16(packet, 6, 0);                                   /* flags + fragment offset */
    packet[8] = 64;                                           /* TTL */
    packet[9] = IPPROTO_TCP;                                  /* protocol */
    put_be16(packet, 10, 0);                                  /* checksum, filled below */
    memcpy(packet + 12, &src_addr, 4);
    memcpy(packet + 16, &dst_addr, 4);
    /* checksum16 reads/writes 16-bit words in the host's native order, not
     * forced big-endian — that's what makes the one's-complement result
     * self-consistent. Store it with a raw memcpy, not put_be16. */
    uint16_t ip_cksum = checksum16(packet, IP_HDR_LEN);
    memcpy(packet + 10, &ip_cksum, 2);

    /* --- TCP header --- */
    uint8_t *tcp = packet + IP_HDR_LEN;
    put_be16(tcp, 0, src_port);
    put_be16(tcp, 2, (uint16_t)port);
    put_be32(tcp, 4, 0x1000);   /* sequence number */
    put_be32(tcp, 8, 0);        /* ack number */
    tcp[12] = 0x50;             /* data offset = 5 words, reserved = 0 */
    tcp[13] = 0x02;             /* flags: SYN */
    put_be16(tcp, 14, 65535);   /* window */
    put_be16(tcp, 16, 0);       /* checksum, filled below */
    put_be16(tcp, 18, 0);       /* urgent pointer */

    struct {
        uint8_t src[4], dst[4], zero, proto, tcp_len[2];
        uint8_t tcp_hdr[TCP_HDR_LEN];
    } pseudo;
    memcpy(pseudo.src, &src_addr, 4);
    memcpy(pseudo.dst, &dst_addr, 4);
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_TCP;
    put_be16(pseudo.tcp_len, 0, TCP_HDR_LEN);
    memcpy(pseudo.tcp_hdr, tcp, TCP_HDR_LEN);
    uint16_t tcp_cksum = checksum16(&pseudo, (int)sizeof(pseudo));
    memcpy(tcp + 16, &tcp_cksum, 2);

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons((uint16_t)port);
    dst.sin_addr.s_addr = dst_addr;

    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        close(sock);
        return PORT_FILTERED;
    }

    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    port_state_t result = PORT_FILTERED;
    struct timeval deadline;
    gettimeofday(&deadline, NULL);
    deadline.tv_sec += tv.tv_sec;
    deadline.tv_usec += tv.tv_usec;

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);

        struct timeval now, remaining;
        gettimeofday(&now, NULL);
        remaining.tv_sec = deadline.tv_sec - now.tv_sec;
        remaining.tv_usec = deadline.tv_usec - now.tv_usec;
        if (remaining.tv_usec < 0) { remaining.tv_usec += 1000000; remaining.tv_sec--; }
        if (remaining.tv_sec < 0) break;

        int rc = select(sock + 1, &rfds, NULL, NULL, &remaining);
        if (rc <= 0) break;

        uint8_t buf[65535];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int n = (int)recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len);
        if (n < IP_HDR_LEN) continue;

        int ip_hlen = (buf[0] & 0x0F) * 4;
        if (n < ip_hlen + TCP_HDR_LEN) continue;

        uint32_t resp_saddr;
        memcpy(&resp_saddr, buf + 12, 4);
        if (resp_saddr != dst_addr) continue;

        const uint8_t *rtcp = buf + ip_hlen;
        uint16_t resp_src_port = get_be16(rtcp, 0);
        uint16_t resp_dst_port = get_be16(rtcp, 2);
        if (resp_src_port != (uint16_t)port || resp_dst_port != src_port) continue;

        uint8_t flags = rtcp[13];
        if ((flags & 0x02) && (flags & 0x10)) { result = PORT_OPEN; break; }   /* SYN+ACK */
        if (flags & 0x04) { result = PORT_CLOSED; break; }                     /* RST */
    }

    close(sock);
    return result;
}

#else /* non-Linux: raw SYN crafting isn't portable here — degrade gracefully */

#include "reconpulse/portscan.h"

port_state_t tcp_syn_scan_port(const char *ip, int port, int timeout_ms)
{
    return tcp_connect_scan_port(ip, port, timeout_ms);
}

#endif
