#include <string.h>
#include "reconpulse/vuln_checks.h"
#include "reconpulse/netutils.h"

/* CVE-2004-2687 — distccd performs zero authentication of the compile
 * jobs it is asked to run: anyone who can reach the port can make it
 * execute arbitrary commands. Rather than crafting a full argv-injection
 * job (protocol-fragile, and unnecessary to prove the point), this sends
 * a minimal, well-formed distcc handshake with zero arguments. A
 * protocol-shaped error response (distcc always answers in its own
 * DONE/STAT/SERR token framing) confirms this is a live, reachable
 * distccd — which is by itself the finding: the daemon's design has no
 * concept of authentication, so exposure equals compromise. */
void check_distcc_rce(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms)
{
    (void)port;
    socket_t sock = net_tcp_connect(ip, 3632, timeout_ms);
    if (sock == INVALID_SOCKET) return;

    const char *handshake = "DIST00000001ARGC00000000";
    if (net_send_all(sock, handshake, (int)strlen(handshake)) != 0) {
        net_close(sock);
        return;
    }

    char resp[256];
    net_set_timeout(sock, timeout_ms);
    int n = (int)recv(sock, resp, sizeof(resp) - 1, 0);
    net_close(sock);
    if (n <= 0) return;
    resp[n] = '\0';

    if (strstr(resp, "DONE") || strstr(resp, "STAT") || strstr(resp, "SERR")) {
        host_add_finding(host, "CVE-2004-2687",
                          "distccd exposed - unauthenticated remote command execution",
                          "distccd accepts compile jobs from any client with no authentication "
                          "or access control; a crafted job argv executes arbitrary commands as "
                          "the distccd user.",
                          SEV_CRITICAL, CONF_CONFIRMED,
                          "distcc protocol handshake acknowledged by the service on TCP 3632",
                          "distccd should never be reachable from untrusted networks; bind it to "
                          "localhost/VPN only or disable it entirely.");
    }
}
