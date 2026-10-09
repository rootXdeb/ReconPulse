#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "reconpulse/netutils.h"

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #pragma comment(lib, "ws2_32.lib")
#else
  #include <unistd.h>
  #include <fcntl.h>
  #include <time.h>
  #include <sys/select.h>
  #include <arpa/inet.h>
  #include <netinet/in.h>
#endif

int net_global_init(void)
{
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0 ? 0 : -1;
#else
    return 0;
#endif
}

void net_global_cleanup(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

static void set_nonblocking(socket_t sock, int enable)
{
#ifdef _WIN32
    u_long mode = enable ? 1 : 0;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (enable) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    else fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
#endif
}

void net_set_timeout(socket_t sock, int timeout_ms)
{
#ifdef _WIN32
    DWORD tv = (DWORD)timeout_ms;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

socket_t net_tcp_connect(const char *ip, int port, int timeout_ms)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) return INVALID_SOCKET;

    socket_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;

    set_nonblocking(sock, 1);
    int rc = connect(sock, (struct sockaddr *)&addr, sizeof(addr));

#ifdef _WIN32
    if (rc == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
        net_close(sock);
        return INVALID_SOCKET;
    }
#else
    if (rc < 0 && errno != EINPROGRESS) {
        net_close(sock);
        return INVALID_SOCKET;
    }
#endif

    if (rc != 0) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        rc = select((int)sock + 1, NULL, &wfds, NULL, &tv);
        if (rc <= 0) {
            net_close(sock);
            return INVALID_SOCKET;
        }

        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
        if (err != 0) {
            net_close(sock);
            return INVALID_SOCKET;
        }
    }

    set_nonblocking(sock, 0);
    net_set_timeout(sock, timeout_ms);
    return sock;
}

int net_recv_line(socket_t sock, char *buf, int buf_len, int timeout_ms)
{
    net_set_timeout(sock, timeout_ms);
    int total = 0;
    while (total < buf_len - 1) {
        char c;
        int n = (int)recv(sock, &c, 1, 0);
        if (n <= 0) break;
        buf[total++] = c;
        if (c == '\n') break;
    }
    buf[total] = '\0';
    return total;
}

int net_send_all(socket_t sock, const void *data, int len)
{
    const char *p = (const char *)data;
    int sent = 0;
    while (sent < len) {
        int n = (int)send(sock, p + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

void net_close(socket_t sock)
{
    CLOSESOCK(sock);
}

void net_sleep_ms(int ms)
{
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

int cidr_expand(const char *cidr, char hosts[][MAX_IP_LEN], int max_hosts)
{
    char base[MAX_IP_LEN];
    int prefix = 32;

    const char *slash = strchr(cidr, '/');
    if (slash) {
        size_t base_len = (size_t)(slash - cidr);
        if (base_len >= sizeof(base)) return 0;
        memcpy(base, cidr, base_len);
        base[base_len] = '\0';
        prefix = atoi(slash + 1);
    } else {
        snprintf(base, sizeof(base), "%s", cidr);
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, base, &addr) != 1) return 0;

    if (prefix < 0 || prefix > 32) prefix = 32;
    uint32_t host_bits = (prefix >= 32) ? 0 : (32u - (uint32_t)prefix);
    uint32_t count = (host_bits == 0) ? 1u : (1u << host_bits);
    uint32_t network = ntohl(addr.s_addr) & (host_bits == 32 ? 0u : (~0u << host_bits));

    int written = 0;
    uint32_t first = (count > 2) ? 1 : 0;
    uint32_t last = (count > 2) ? count - 2 : count - 1;

    for (uint32_t i = first; i <= last && written < max_hosts; i++) {
        uint32_t ip = network + i;
        struct in_addr out;
        out.s_addr = htonl(ip);
        inet_ntop(AF_INET, &out, hosts[written], MAX_IP_LEN);
        written++;
    }
    return written;
}
