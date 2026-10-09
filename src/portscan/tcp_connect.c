#include "reconpulse/portscan.h"
#include "reconpulse/netutils.h"

port_state_t tcp_connect_scan_port(const char *ip, int port, int timeout_ms)
{
    socket_t sock = net_tcp_connect(ip, port, timeout_ms);
    if (sock == INVALID_SOCKET) return PORT_CLOSED;
    net_close(sock);
    return PORT_OPEN;
}
