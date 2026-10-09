#include <string.h>
#include "reconpulse/service_probe.h"
#include "reconpulse/netutils.h"

void grab_banner(const char *ip, int port, int timeout_ms, char *banner, int banner_len)
{
    banner[0] = '\0';

    socket_t sock = net_tcp_connect(ip, port, timeout_ms);
    if (sock == INVALID_SOCKET) return;

    net_recv_line(sock, banner, banner_len, timeout_ms);
    net_close(sock);

    /* strip trailing CR/LF */
    int len = (int)strlen(banner);
    while (len > 0 && (banner[len - 1] == '\n' || banner[len - 1] == '\r'))
        banner[--len] = '\0';
}
