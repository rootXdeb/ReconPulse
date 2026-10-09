#include <stdio.h>
#include <string.h>
#include "reconpulse/vuln_checks.h"
#include "reconpulse/netutils.h"
#include "reconpulse/cred_list.h"

/* Accumulates incoming bytes (ignoring telnet IAC negotiation is
 * unnecessary here — the login/password prompts are always parseable
 * plain text regardless of what negotiation noise surrounds them) until
 * `needle` appears or timeout_ms elapses. */
static int expect_text(socket_t sock, const char *needle, char *buf, int buf_len, int timeout_ms)
{
    int total = 0;
    buf[0] = '\0';
    net_set_timeout(sock, timeout_ms);

    while (total < buf_len - 1) {
        int n = (int)recv(sock, buf + total, buf_len - 1 - total, 0);
        if (n <= 0) break;
        total += n;
        buf[total] = '\0';
        if (strstr(buf, needle)) return 1;
    }
    return 0;
}

void check_telnet_default_creds(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms)
{
    (void)port;
    for (int i = 0; i < RECONPULSE_DEFAULT_CREDS_COUNT; i++) {
        socket_t sock = net_tcp_connect(ip, 23, timeout_ms);
        if (sock == INVALID_SOCKET) continue;

        char buf[1024];
        if (!expect_text(sock, "ogin:", buf, sizeof(buf), timeout_ms)) {
            net_close(sock);
            continue;
        }

        char line[128];
        snprintf(line, sizeof(line), "%s\r\n", RECONPULSE_DEFAULT_CREDS[i].user);
        net_send_all(sock, line, (int)strlen(line));

        if (!expect_text(sock, "assword:", buf, sizeof(buf), timeout_ms)) {
            net_close(sock);
            continue;
        }

        snprintf(line, sizeof(line), "%s\r\n", RECONPULSE_DEFAULT_CREDS[i].pass);
        net_send_all(sock, line, (int)strlen(line));

        char result[1024];
        int got_prompt = expect_text(sock, "$", result, sizeof(result), 3000);
        int denied = strstr(result, "ncorrect") != NULL || strstr(result, "failed") != NULL;
        net_close(sock);

        if (got_prompt && !denied) {
            char title[128], evidence[300];
            snprintf(title, sizeof(title), "Telnet accepts default credentials (%s:%s)",
                     RECONPULSE_DEFAULT_CREDS[i].user, RECONPULSE_DEFAULT_CREDS[i].pass);
            snprintf(evidence, sizeof(evidence), "login/password %s:%s reached a shell prompt: %.*s",
                     RECONPULSE_DEFAULT_CREDS[i].user, RECONPULSE_DEFAULT_CREDS[i].pass, 150, result);
            host_add_finding(host, "N/A-TELNET-CREDS", title,
                              "Telnet transmits credentials in cleartext and authenticated "
                              "successfully with a well-known default account.",
                              SEV_HIGH, CONF_CONFIRMED, evidence,
                              "Disable telnetd in favor of SSH; change or remove this account's "
                              "password.");
            return;
        }
    }
}
