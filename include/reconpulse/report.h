#ifndef RECONPULSE_REPORT_H
#define RECONPULSE_REPORT_H

#include "reconpulse/common.h"
#include "reconpulse/strbuf.h"

void report_print_cli(const host_result_t *hosts, int host_count);
void report_write_json(const host_result_t *hosts, int host_count, const char *path);
void report_write_html(const host_result_t *hosts, int host_count, const char *path);

/* Appends the hosts/ports/findings JSON body (no outer wrapper) into sb.
 * Shared by the file-based JSON report and the web dashboard API so the
 * schema only lives in one place. */
void build_hosts_json(strbuf_t *sb, const host_result_t *hosts, int host_count);

#endif
