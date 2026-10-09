#include <stdio.h>
#include <time.h>
#include "reconpulse/report.h"

static void html_escape_print(FILE *f, const char *s)
{
    for (; *s; s++) {
        switch (*s) {
            case '<': fputs("&lt;", f); break;
            case '>': fputs("&gt;", f); break;
            case '&': fputs("&amp;", f); break;
            case '"': fputs("&quot;", f); break;
            default:  fputc(*s, f);
        }
    }
}

static const char *severity_class(severity_t s)
{
    switch (s) {
        case SEV_CRITICAL: return "crit";
        case SEV_HIGH:      return "high";
        case SEV_MEDIUM:    return "med";
        case SEV_LOW:       return "low";
        default:            return "info";
    }
}

void report_write_html(const host_result_t *hosts, int host_count, const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) return;

    time_t now = time(NULL);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(f,
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Reconpulse Scan Report</title><style>"
        "body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0f1117;color:#e6e6e6;margin:0;padding:2rem}"
        "h1{color:#fff} .meta{color:#9aa0a6;margin-bottom:2rem}"
        ".host{background:#161923;border:1px solid #262b3a;border-radius:8px;padding:1.5rem;margin-bottom:1.5rem}"
        "table{width:100%%;border-collapse:collapse;margin:1rem 0}"
        "th,td{text-align:left;padding:.5rem;border-bottom:1px solid #262b3a;font-size:.9rem}"
        ".badge{display:inline-block;padding:.15rem .6rem;border-radius:4px;font-size:.75rem;font-weight:600;color:#fff}"
        ".crit{background:#7f1d1d}.high{background:#b91c1c}.med{background:#a16207}.low{background:#0369a1}.info{background:#374151}"
        ".finding{border-left:3px solid #444;padding:.75rem 1rem;margin:.75rem 0;background:#10131c}"
        ".finding.crit,.finding.high{border-left-color:#dc2626}.finding.med{border-left-color:#eab308}.finding.low{border-left-color:#0ea5e9}"
        ".conf{color:#9aa0a6;font-size:.8rem}"
        "</style></head><body>");

    fprintf(f, "<h1>Reconpulse Network Security Scan Report</h1>");
    fprintf(f, "<div class='meta'>Generated %s</div>", timestr);

    for (int h = 0; h < host_count; h++) {
        const host_result_t *host = &hosts[h];
        if (!host->is_alive) continue;

        fprintf(f, "<div class='host'><h2>%s</h2>", host->ip);
        fprintf(f, "<table><tr><th>Port</th><th>Service</th><th>Version / Banner</th></tr>");
        for (int i = 0; i < host->port_count; i++) {
            const port_result_t *p = &host->ports[i];
            if (p->state != PORT_OPEN) continue;
            fprintf(f, "<tr><td>%d</td><td>", p->port);
            html_escape_print(f, p->service);
            fprintf(f, "</td><td>");
            html_escape_print(f, p->version[0] ? p->version : p->banner);
            fprintf(f, "</td></tr>");
        }
        fprintf(f, "</table>");

        if (host->finding_count > 0) {
            fprintf(f, "<h3>Findings (%d)</h3>", host->finding_count);
            for (int i = 0; i < host->finding_count; i++) {
                const finding_t *fnd = &host->findings[i];
                const char *cls = severity_class(fnd->severity);
                fprintf(f, "<div class='finding %s'>", cls);
                fprintf(f, "<span class='badge %s'>%s</span> <b>", cls, severity_to_str(fnd->severity));
                html_escape_print(f, fnd->title);
                fprintf(f, "</b> <span class='conf'>[%s, %s]</span><br>",
                        fnd->id, confidence_to_str(fnd->confidence));
                fprintf(f, "<p>"); html_escape_print(f, fnd->description); fprintf(f, "</p>");
                fprintf(f, "<p><b>Evidence:</b> "); html_escape_print(f, fnd->evidence); fprintf(f, "</p>");
                fprintf(f, "<p><b>Remediation:</b> "); html_escape_print(f, fnd->remediation); fprintf(f, "</p>");
                fprintf(f, "</div>");
            }
        } else {
            fprintf(f, "<p style='color:#9aa0a6'>No findings on this host.</p>");
        }
        fprintf(f, "</div>");
    }

    fprintf(f, "</body></html>");
    fclose(f);
}
