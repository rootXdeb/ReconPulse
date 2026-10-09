#include <string.h>
#include <stdio.h>
#include "reconpulse/vuln_checks.h"
#include "reconpulse/netutils.h"
#include "reconpulse/cred_list.h"

static void base64_encode(const char *in, char *out)
{
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t len = strlen(in);
    size_t o = 0;
    size_t i = 0;
    for (; i + 2 < len; i += 3) {
        uint32_t n = ((unsigned char)in[i] << 16) | ((unsigned char)in[i+1] << 8) | (unsigned char)in[i+2];
        out[o++] = tbl[(n >> 18) & 0x3F];
        out[o++] = tbl[(n >> 12) & 0x3F];
        out[o++] = tbl[(n >> 6) & 0x3F];
        out[o++] = tbl[n & 0x3F];
    }
    size_t rem = len - i;
    if (rem == 1) {
        uint32_t n = (unsigned char)in[i] << 16;
        out[o++] = tbl[(n >> 18) & 0x3F];
        out[o++] = tbl[(n >> 12) & 0x3F];
        out[o++] = '=';
        out[o++] = '=';
    } else if (rem == 2) {
        uint32_t n = ((unsigned char)in[i] << 16) | ((unsigned char)in[i+1] << 8);
        out[o++] = tbl[(n >> 18) & 0x3F];
        out[o++] = tbl[(n >> 12) & 0x3F];
        out[o++] = tbl[(n >> 6) & 0x3F];
        out[o++] = '=';
    }
    out[o] = '\0';
}

/* Tomcat's Manager application (needed to deploy a WAR and get full
 * remote code execution) is itself gated behind HTTP Basic auth. Default
 * installs — including Metasploitable2's — ship it with a well-known
 * credential pair. */
void check_tomcat_default_creds(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms)
{
    int target_port = port->port;

    for (int i = 0; i < RECONPULSE_DEFAULT_CREDS_COUNT; i++) {
        char userpass[128];
        snprintf(userpass, sizeof(userpass), "%s:%s", RECONPULSE_DEFAULT_CREDS[i].user, RECONPULSE_DEFAULT_CREDS[i].pass);
        char b64[256];
        base64_encode(userpass, b64);

        socket_t sock = net_tcp_connect(ip, target_port, timeout_ms);
        if (sock == INVALID_SOCKET) continue;

        char req[512];
        snprintf(req, sizeof(req),
                 "GET /manager/html HTTP/1.0\r\nHost: %s\r\nAuthorization: Basic %s\r\n\r\n",
                 ip, b64);
        net_send_all(sock, req, (int)strlen(req));

        char resp[256];
        net_set_timeout(sock, timeout_ms);
        int n = (int)recv(sock, resp, sizeof(resp) - 1, 0);
        net_close(sock);
        if (n <= 0) continue;
        resp[n] = '\0';

        if (strncmp(resp, "HTTP/1.0 200", 12) == 0 || strncmp(resp, "HTTP/1.1 200", 12) == 0) {
            char title[128], evidence[256];
            snprintf(title, sizeof(title), "Tomcat Manager accepts default credentials (%s:%s)",
                     RECONPULSE_DEFAULT_CREDS[i].user, RECONPULSE_DEFAULT_CREDS[i].pass);
            snprintf(evidence, sizeof(evidence),
                     "GET /manager/html with Basic auth %s:%s returned HTTP 200",
                     RECONPULSE_DEFAULT_CREDS[i].user, RECONPULSE_DEFAULT_CREDS[i].pass);
            host_add_finding(host, "N/A-TOMCAT-CREDS", title,
                              "Access to the Tomcat Manager application allows deploying an "
                              "arbitrary WAR file, which is equivalent to full remote code "
                              "execution as the Tomcat service user.",
                              SEV_CRITICAL, CONF_CONFIRMED, evidence,
                              "Remove default manager accounts and restrict /manager to trusted "
                              "hosts only.");
            return;
        }
    }
}
