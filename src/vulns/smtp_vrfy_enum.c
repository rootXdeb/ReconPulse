#include <stdio.h>
#include <string.h>
#include "reconpulse/vuln_checks.h"
#include "reconpulse/netutils.h"

/* CVE-1999-0531-class issue: SMTP VRFY lets a remote, unauthenticated
 * client enumerate valid local usernames. Confirmed by contrasting the
 * response to a known-valid account ("root") against an almost-certainly
 * invalid one. */
void check_smtp_vrfy_enum(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms)
{
    (void)port;
    socket_t sock = net_tcp_connect(ip, 25, timeout_ms);
    if (sock == INVALID_SOCKET) return;

    char banner[256];
    net_recv_line(sock, banner, sizeof(banner), timeout_ms);

    const char *v1 = "VRFY root\r\n";
    net_send_all(sock, v1, (int)strlen(v1));
    char r1[256];
    net_recv_line(sock, r1, sizeof(r1), timeout_ms);

    const char *v2 = "VRFY zzz_not_a_real_user_9f3\r\n";
    net_send_all(sock, v2, (int)strlen(v2));
    char r2[256];
    net_recv_line(sock, r2, sizeof(r2), timeout_ms);

    net_close(sock);

    int valid_ok = (strncmp(r1, "250", 3) == 0 || strncmp(r1, "252", 3) == 0);
    int invalid_rejected = (strncmp(r2, "550", 3) == 0 || strncmp(r2, "551", 3) == 0);

    if (valid_ok && invalid_rejected) {
        char evidence[300];
        snprintf(evidence, sizeof(evidence), "VRFY root -> %.100s | VRFY <bogus> -> %.100s", r1, r2);
        host_add_finding(host, "CVE-1999-0531",
                          "SMTP VRFY user enumeration enabled",
                          "The mail server responds differently to VRFY requests for valid vs. "
                          "invalid usernames, allowing remote account enumeration.",
                          SEV_LOW, CONF_CONFIRMED, evidence,
                          "Disable the VRFY command (disable_vrfy_command = yes in Postfix) or "
                          "have it return a uniform response.");
    }
}
