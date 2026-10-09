#ifndef RECONPULSE_PORTSCAN_H
#define RECONPULSE_PORTSCAN_H

#include "reconpulse/common.h"

/* Probes a single TCP port with a full connect(). Portable, no privileges
 * required. Returns the resulting state. */
port_state_t tcp_connect_scan_port(const char *ip, int port, int timeout_ms);

/* Raw-socket half-open SYN scan. Linux only (needs CAP_NET_RAW/root); on
 * other platforms this transparently falls back to tcp_connect_scan_port. */
port_state_t tcp_syn_scan_port(const char *ip, int port, int timeout_ms);

/* UDP probe: sends an empty datagram and classifies the port based on
 * whether an ICMP port-unreachable came back. */
port_state_t udp_scan_port(const char *ip, int port, int timeout_ms);

#endif
