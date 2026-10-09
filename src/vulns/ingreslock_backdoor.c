#include <stdio.h>
#include <string.h>
#include "reconpulse/vuln_checks.h"
#include "reconpulse/netutils.h"

/* Metasploitable2 has a root shell bound directly to TCP 1524 (the
 * conventional "ingreslock" port), left over from a previous compromise
 * baked into the image. Any connection gets a shell with no auth. */
void check_ingreslock_backdoor(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms)
{
    (void)port;
    socket_t sock = net_tcp_connect(ip, 1524, timeout_ms);
    if (sock == INVALID_SOCKET) return;

    const char *cmd = "id\n";
    net_send_all(sock, cmd, (int)strlen(cmd));
    char resp[256];
    net_recv_line(sock, resp, sizeof(resp), timeout_ms);
    net_close(sock);

    if (strstr(resp, "uid=")) {
        char evidence[300];
        snprintf(evidence, sizeof(evidence), "port 1524 responded to 'id' with: %.200s", resp);
        host_add_finding(host, "N/A-INGRESLOCK",
                          "Unauthenticated root shell on TCP 1524 (ingreslock backdoor)",
                          "A pre-existing shell is bound to port 1524 with no authentication, "
                          "granting immediate command execution to any connecting client.",
                          SEV_CRITICAL, CONF_CONFIRMED, evidence,
                          "Rebuild the host from a known-clean image; a bound shell like this "
                          "indicates prior compromise, not a patchable misconfiguration.");
    }
}
