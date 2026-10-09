#include <string.h>
#include "reconpulse/vuln_checks.h"
#include "reconpulse/netutils.h"

/* RFB (VNC) handshake: read the server's protocol version line, echo it
 * back, then inspect the security types it offers. Type 1 (None) means
 * no authentication at all — confirmed directly from the protocol.
 * Type 2 (VNC Authentication) uses a DES challenge-response; verifying a
 * guessed password against it would mean hand-rolling DES, which is a
 * lot of code for one additional check, so that case is reported as
 * "password-protected, not attempted" rather than faked. */
void check_vnc_auth(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms)
{
    (void)port;
    socket_t sock = net_tcp_connect(ip, 5900, timeout_ms);
    if (sock == INVALID_SOCKET) return;

    char version[13] = {0};
    net_set_timeout(sock, timeout_ms);
    if (recv(sock, version, 12, 0) != 12) { net_close(sock); return; }
    net_send_all(sock, version, 12);

    int uses_none = 0, uses_vnc_auth = 0;

    if (strncmp(version, "RFB 003.003", 11) == 0) {
        unsigned char sec[4];
        if (recv(sock, sec, 4, 0) == 4) {
            uint32_t type = ((uint32_t)sec[0] << 24) | ((uint32_t)sec[1] << 16) |
                             ((uint32_t)sec[2] << 8) | sec[3];
            if (type == 1) uses_none = 1;
            else if (type == 2) uses_vnc_auth = 1;
        }
    } else {
        unsigned char count;
        if (recv(sock, &count, 1, 0) == 1 && count > 0 && count < 16) {
            unsigned char types[16];
            int n = (int)recv(sock, types, count, 0);
            for (int i = 0; i < n; i++) {
                if (types[i] == 1) uses_none = 1;
                if (types[i] == 2) uses_vnc_auth = 1;
            }
        }
    }
    net_close(sock);

    if (uses_none) {
        host_add_finding(host, "N/A-VNC-NOAUTH",
                          "VNC server requires no authentication",
                          "The RFB handshake offered security type 'None' — any client can "
                          "obtain a full remote desktop session with no credentials.",
                          SEV_CRITICAL, CONF_CONFIRMED,
                          "RFB security-type negotiation offered type 1 (None)",
                          "Enable VNC authentication with a strong password, or tunnel VNC over "
                          "SSH and disable direct exposure.");
    } else if (uses_vnc_auth) {
        host_add_finding(host, "N/A-VNC-WEAKAUTH",
                          "VNC server reachable, password-based auth only (not brute-forced)",
                          "The server requires VNC Authentication (DES challenge-response). This "
                          "scan does not attempt password recovery against it; Metasploitable2's "
                          "documented default VNC password is 'password'.",
                          SEV_MEDIUM, CONF_LIKELY,
                          "RFB security-type negotiation offered type 2 (VNC Authentication)",
                          "Set a strong, unique VNC password or disable direct VNC exposure in "
                          "favor of SSH tunneling.");
    }
}
