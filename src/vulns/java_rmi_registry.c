#include <string.h>
#include "reconpulse/vuln_checks.h"
#include "reconpulse/netutils.h"

/* Java RMI registry has no authentication of its own; anyone who can
 * reach it can look up bound remote objects and, depending on what's
 * bound, trigger deserialization of attacker-controlled data (the basis
 * of numerous Java RMI RCE chains). We only verify the registry is
 * actually speaking the RMI wire protocol rather than attempting a full
 * exploit chain, which is target-specific. */
void check_java_rmi_registry(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms)
{
    (void)port;
    socket_t sock = net_tcp_connect(ip, 1099, timeout_ms);
    if (sock == INVALID_SOCKET) return;

    unsigned char hello[] = { 'J', 'R', 'M', 'I', 0x00, 0x02, 0x4b };
    if (net_send_all(sock, hello, sizeof(hello)) != 0) { net_close(sock); return; }

    unsigned char resp[64];
    net_set_timeout(sock, timeout_ms);
    int n = (int)recv(sock, resp, sizeof(resp), 0);
    net_close(sock);

    if (n >= 1 && resp[0] == 0x4e) {
        host_add_finding(host, "N/A-JAVA-RMI",
                          "Java RMI registry exposed with no authentication",
                          "The RMI registry acknowledged the RMI wire protocol handshake. RMI "
                          "registries have no built-in access control; exposure to untrusted "
                          "networks is a common vector for Java deserialization RCE.",
                          SEV_HIGH, CONF_CONFIRMED,
                          "RMI ProtocolAck (0x4e) received in response to a JRMI handshake",
                          "Bind the RMI registry to localhost or a management-only interface, "
                          "and require an RMI SSL socket factory with authentication.");
    }
}
