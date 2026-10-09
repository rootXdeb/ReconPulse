#ifndef RECONPULSE_WEBSERVER_H
#define RECONPULSE_WEBSERVER_H

#include "reconpulse/common.h"

/* Starts the dashboard HTTP server on the given port and blocks forever.
 * base_cfg supplies defaults (threads/timeout/etc.) for scans submitted
 * through the dashboard; per-request fields (target, ports, scan type,
 * vuln-checks toggle) are taken from each POST /api/scan body. */
void webserver_run(const scan_config_t *base_cfg, int port);

#endif
