#include <string.h>
#include "reconpulse/vuln_checks.h"
#include "reconpulse/netutils.h"

/* X11 connection setup (little-endian ordering, no auth attempted). If the
 * server has been opened up with `xhost +` (Metasploitable2's default),
 * it accepts the connection with reply code 1 (Success) despite us
 * presenting zero authorization data. */
void check_x11_open_access(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms)
{
    (void)port;
    socket_t sock = net_tcp_connect(ip, 6000, timeout_ms);
    if (sock == INVALID_SOCKET) return;

    unsigned char setup[12] = {
        0x6c, 0x00,             /* byte order: 'l' = LSB first */
        0x0b, 0x00,             /* protocol-major-version = 11 */
        0x00, 0x00,             /* protocol-minor-version = 0 */
        0x00, 0x00,             /* auth-protocol-name length = 0 */
        0x00, 0x00,             /* auth-protocol-data length = 0 */
        0x00, 0x00              /* unused pad */
    };
    if (net_send_all(sock, setup, sizeof(setup)) != 0) {
        net_close(sock);
        return;
    }

    unsigned char reply[8];
    net_set_timeout(sock, timeout_ms);
    int n = (int)recv(sock, reply, sizeof(reply), 0);
    net_close(sock);

    if (n >= 1 && reply[0] == 1) {
        host_add_finding(host, "N/A-X11-OPEN",
                          "X11 server accepts connections with no access control",
                          "The X server on TCP 6000 accepted a connection setup request with "
                          "zero authorization data, meaning any client on the network can "
                          "capture keystrokes, screen contents, or inject input events.",
                          SEV_HIGH, CONF_CONFIRMED,
                          "X11 connection-setup handshake returned Success (code 1) with no auth data",
                          "Run `xhost -` to require authorization, and restrict X11 to "
                          "localhost/SSH X-forwarding only.");
    }
}
