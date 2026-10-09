#ifndef RECONPULSE_SCAN_ENGINE_H
#define RECONPULSE_SCAN_ENGINE_H

#include "reconpulse/common.h"

/* Expands cfg->target_cidr, scans every host concurrently (thread pool
 * sized by cfg->thread_count), and runs vulnerability checks per host if
 * cfg->run_vuln_checks is set. Allocates *results (caller must free) and
 * sets *host_count. */
void run_scan(const scan_config_t *cfg, host_result_t **results, int *host_count);

#endif
