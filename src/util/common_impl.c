#include <stdio.h>
#include <string.h>
#include "reconpulse/common.h"

int host_add_finding(host_result_t *host, const char *id, const char *title,
                      const char *description, severity_t severity,
                      confidence_t confidence, const char *evidence,
                      const char *remediation)
{
    if (host->finding_count >= MAX_FINDINGS_PER_HOST) return -1;

    finding_t *f = &host->findings[host->finding_count++];
    memset(f, 0, sizeof(*f));
    snprintf(f->id, sizeof(f->id), "%s", id ? id : "N/A");
    snprintf(f->title, sizeof(f->title), "%s", title ? title : "");
    snprintf(f->description, sizeof(f->description), "%s", description ? description : "");
    f->severity = severity;
    f->confidence = confidence;
    snprintf(f->evidence, sizeof(f->evidence), "%s", evidence ? evidence : "");
    snprintf(f->remediation, sizeof(f->remediation), "%s", remediation ? remediation : "");
    return 0;
}

const char *severity_to_str(severity_t s)
{
    switch (s) {
        case SEV_CRITICAL: return "CRITICAL";
        case SEV_HIGH:      return "HIGH";
        case SEV_MEDIUM:    return "MEDIUM";
        case SEV_LOW:       return "LOW";
        default:            return "INFO";
    }
}

const char *confidence_to_str(confidence_t c)
{
    return c == CONF_CONFIRMED ? "CONFIRMED" : "LIKELY";
}
