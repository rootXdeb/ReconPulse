#include <string.h>
#include "reconpulse/portscan.h"
#include "reconpulse/common.h"
#include "reconpulse/netutils.h"

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <unistd.h>
  #include <errno.h>
  #include <sys/select.h>
  #include <arpa/inet.h>
#endif

/* Uses a connected UDP socket rather than a raw ICMP listener: on both
 * Linux/BSD and Windows, the kernel delivers an ICMP "port unreachable"
 * for a connected UDP socket back to the application as a socket error
 * (ECONNREFUSED / WSAECONNRESET) on the next send/recv — no raw socket
 * or root privileges required. A genuine reply means the port is open;
 * silence within the timeout is the classic UDP ambiguous case (the
 * datagram or the ICMP error may simply have been dropped by a
 * firewall), reported here as filtered. */
port_state_t udp_scan_port(const char *ip, int port, int timeout_ms)
{
    socket_t sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) return PORT_FILTERED;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        net_close(sock);
        return PORT_FILTERED;
    }

    char probe[4] = { 0, 0, 0, 0 };
    send(sock, probe, sizeof(probe), 0);

    net_set_timeout(sock, timeout_ms);

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };

    int rc = select((int)sock + 1, &rfds, NULL, NULL, &tv);
    if (rc <= 0) {
        net_close(sock);
        return PORT_FILTERED; /* open|filtered — no definitive answer */
    }

    char buf[512];
    int n = (int)recv(sock, buf, sizeof(buf), 0);
    net_close(sock);
    return n > 0 ? PORT_OPEN : PORT_CLOSED;
}
