#include <stdio.h>
#include "reconpulse/report.h"

#define CLR_RESET   "\x1b[0m"
#define CLR_RED     "\x1b[31m"
#define CLR_YELLOW  "\x1b[33m"
#define CLR_GREEN   "\x1b[32m"
#define CLR_CYAN    "\x1b[36m"
#define CLR_BOLD    "\x1b[1m"

static const char *severity_color(severity_t s)
{
    switch (s) {
        case SEV_CRITICAL: return CLR_RED;
        case SEV_HIGH:      return CLR_RED;
        case SEV_MEDIUM:    return CLR_YELLOW;
        case SEV_LOW:       return CLR_CYAN;
        default:            return CLR_RESET;
    }
}

void report_print_cli(const host_result_t *hosts, int host_count)
{
    for (int h = 0; h < host_count; h++) {
        const host_result_t *host = &hosts[h];
        if (!host->is_alive) continue;

        printf("\n" CLR_BOLD "Host: %s" CLR_RESET "\n", host->ip);
        printf("%-8s %-8s %-14s %-30s\n", "PORT", "STATE", "SERVICE", "VERSION/BANNER");
        printf("--------------------------------------------------------------------\n");

        for (int i = 0; i < host->port_count; i++) {
            const port_result_t *p = &host->ports[i];
            if (p->state != PORT_OPEN) continue;
            printf("%-8d %-8s %-14s %-30s\n", p->port, "open", p->service,
                   p->version[0] ? p->version : p->banner);
        }

        if (host->finding_count > 0) {
            printf("\n" CLR_BOLD "Findings:" CLR_RESET "\n");
            for (int i = 0; i < host->finding_count; i++) {
                const finding_t *f = &host->findings[i];
                printf("  %s[%s]%s %s(%s)%s %s\n",
                       severity_color(f->severity), severity_to_str(f->severity), CLR_RESET,
                       CLR_BOLD, confidence_to_str(f->confidence), CLR_RESET, f->title);
                printf("      %s\n", f->id);
                printf("      Evidence: %s\n", f->evidence);
                printf("      Fix: %s\n", f->remediation);
            }
        }
    }
    printf("\n");
}
