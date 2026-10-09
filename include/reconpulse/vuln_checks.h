#ifndef RECONPULSE_VULN_CHECKS_H
#define RECONPULSE_VULN_CHECKS_H

#include "reconpulse/common.h"

typedef void (*vuln_check_fn)(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms);

typedef struct {
    int port;               /* port this check applies to */
    const char *name;       /* module name, for -v logging */
    vuln_check_fn fn;
} vuln_check_entry_t;

/* Returns the built-in check table and its length. */
const vuln_check_entry_t *vuln_registry_get(int *count);

/* Runs every registered check whose port matches an open port on host. */
void run_vuln_checks(const char *ip, host_result_t *host, int timeout_ms);

#endif
