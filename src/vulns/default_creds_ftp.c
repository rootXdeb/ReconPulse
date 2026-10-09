#include <stdio.h>
#include <string.h>
#include "reconpulse/vuln_checks.h"
#include "reconpulse/netutils.h"
#include "reconpulse/cred_list.h"

void check_ftp_default_creds(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms)
{
    int target_port = port->port;

    for (int i = 0; i < RECONPULSE_DEFAULT_CREDS_COUNT; i++) {
        socket_t sock = net_tcp_connect(ip, target_port, timeout_ms);
        if (sock == INVALID_SOCKET) continue;

        char banner[256];
        net_recv_line(sock, banner, sizeof(banner), timeout_ms);

        char cmd[128];
        snprintf(cmd, sizeof(cmd), "USER %s\r\n", RECONPULSE_DEFAULT_CREDS[i].user);
        net_send_all(sock, cmd, (int)strlen(cmd));
        char resp[256];
        net_recv_line(sock, resp, sizeof(resp), timeout_ms);

        snprintf(cmd, sizeof(cmd), "PASS %s\r\n", RECONPULSE_DEFAULT_CREDS[i].pass);
        net_send_all(sock, cmd, (int)strlen(cmd));
        net_recv_line(sock, resp, sizeof(resp), timeout_ms);
        net_close(sock);

        if (strncmp(resp, "230", 3) == 0) {
            char title[128], evidence[256];
            snprintf(title, sizeof(title), "FTP accepts default credentials (%s:%s)",
                     RECONPULSE_DEFAULT_CREDS[i].user, RECONPULSE_DEFAULT_CREDS[i].pass);
            snprintf(evidence, sizeof(evidence), "USER/PASS %s:%s -> %.100s",
                     RECONPULSE_DEFAULT_CREDS[i].user, RECONPULSE_DEFAULT_CREDS[i].pass, resp);
            host_add_finding(host, "N/A-FTP-CREDS", title,
                              "The FTP service authenticated successfully using a well-known "
                              "default or intentionally weak credential pair.",
                              SEV_HIGH, CONF_CONFIRMED, evidence,
                              "Remove or change the password on this account; disable password "
                              "auth in favor of key-based access where possible.");
            return;
        }
    }
}
