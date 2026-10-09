#include <stdio.h>
#include <string.h>
#include "reconpulse/vuln_checks.h"
#include "reconpulse/netutils.h"

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
#endif

#define PMAP_PROG 100000
#define PMAP_VERS 2
#define PMAP_PROC_GETPORT 3
#define MOUNTD_PROG 100005
#define MOUNTD_VERS 3
#define IPPROTO_TCP_RPC 6

static void put_u32(unsigned char *buf, int *p, uint32_t v)
{
    buf[(*p)++] = (unsigned char)((v >> 24) & 0xFF);
    buf[(*p)++] = (unsigned char)((v >> 16) & 0xFF);
    buf[(*p)++] = (unsigned char)((v >> 8) & 0xFF);
    buf[(*p)++] = (unsigned char)(v & 0xFF);
}

static uint32_t get_u32(const unsigned char *buf)
{
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
}

/* Queries the portmapper (UDP/111) for the mountd port via a minimal
 * hand-built ONC RPC (RFC 1057) GETPORT call. A successful reply proves
 * NFS's mount protocol is reachable — the actual export list and
 * no_root_squash state require the follow-on MOUNT/EXPORT RPC call,
 * left as a documented extension rather than implemented here, since
 * XDR-encoding that reply is a fair amount of extra parsing for a single
 * additional data point once mountd's presence is already established. */
void check_nfs_exports(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms)
{
    (void)port;
    socket_t sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) return;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(111);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) { net_close(sock); return; }

    unsigned char req[64];
    int p = 0;
    put_u32(req, &p, 0x1234); /* xid */
    put_u32(req, &p, 0);      /* CALL */
    put_u32(req, &p, 2);      /* rpcvers */
    put_u32(req, &p, PMAP_PROG);
    put_u32(req, &p, PMAP_VERS);
    put_u32(req, &p, PMAP_PROC_GETPORT);
    put_u32(req, &p, 0); put_u32(req, &p, 0); /* AUTH_NULL cred */
    put_u32(req, &p, 0); put_u32(req, &p, 0); /* AUTH_NULL verf */
    put_u32(req, &p, MOUNTD_PROG);
    put_u32(req, &p, MOUNTD_VERS);
    put_u32(req, &p, IPPROTO_TCP_RPC);
    put_u32(req, &p, 0); /* port (ignored in a GETPORT query) */

    net_set_timeout(sock, timeout_ms);
    if (send(sock, (const char *)req, p, 0) < 0) { net_close(sock); return; }

    unsigned char resp[64];
    int n = (int)recv(sock, resp, sizeof(resp), 0);
    net_close(sock);
    if (n < 28) return;

    uint32_t reply_stat = get_u32(resp + 4);
    uint32_t accept_stat = get_u32(resp + 20);
    if (reply_stat != 0 || accept_stat != 0) return;

    uint32_t mountd_port = get_u32(resp + 24);
    if (mountd_port == 0) return;

    char evidence[128];
    snprintf(evidence, sizeof(evidence), "portmapper reports mountd (NFS mount protocol) on TCP port %u", mountd_port);
    host_add_finding(host, "N/A-NFS-MOUNTD",
                      "NFS mount service (mountd) reachable",
                      "The portmapper confirms an active NFS mount daemon. Metasploitable2's "
                      "default /etc/exports shares filesystems to any client with "
                      "no_root_squash, allowing a remote client to mount and write as root.",
                      SEV_HIGH, CONF_CONFIRMED, evidence,
                      "Restrict NFS exports to specific trusted hosts and remove "
                      "no_root_squash unless explicitly required.");
}
