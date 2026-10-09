#ifndef RECONPULSE_NETUTILS_H
#define RECONPULSE_NETUTILS_H

#include "reconpulse/common.h"

int net_global_init(void);
void net_global_cleanup(void);

/* Opens a TCP connection to ip:port, aborting after timeout_ms. Returns
 * INVALID_SOCKET on failure. */
socket_t net_tcp_connect(const char *ip, int port, int timeout_ms);

/* Sets send/recv timeouts (ms) on an already-open socket. */
void net_set_timeout(socket_t sock, int timeout_ms);

/* Reads up to buf_len-1 bytes into buf (NUL-terminated), returns bytes read
 * or -1 on error/timeout. */
int net_recv_line(socket_t sock, char *buf, int buf_len, int timeout_ms);

/* Sends the full buffer, retrying on partial writes. Returns 0 on success. */
int net_send_all(socket_t sock, const void *data, int len);

void net_close(socket_t sock);

void net_sleep_ms(int ms);

/* Expands a CIDR (e.g. "192.168.1.0/24") into a list of dotted IPs.
 * Returns the number of hosts written (capped at max_hosts). */
int cidr_expand(const char *cidr, char hosts[][MAX_IP_LEN], int max_hosts);

#endif
