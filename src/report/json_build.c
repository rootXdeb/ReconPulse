#include "reconpulse/report.h"

/* Emits `"hosts": [ ... ]` (the key/value only, no surrounding braces) so
 * callers can embed it inside their own JSON object — a standalone report
 * file wraps it in `{ }` as-is, while the dashboard API merges it
 * alongside job status fields. */
void build_hosts_json(strbuf_t *sb, const host_result_t *hosts, int host_count)
{
    strbuf_append(sb, "\"hosts\": [\n");
    int first_host = 1;

    for (int h = 0; h < host_count; h++) {
        const host_result_t *host = &hosts[h];
        if (!host->is_alive) continue;

        if (!first_host) strbuf_append(sb, ",\n");
        first_host = 0;

        strbuf_appendf(sb, "    {\n      \"ip\": \"%s\",\n      \"ports\": [\n", host->ip);

        int first_port = 1;
        for (int i = 0; i < host->port_count; i++) {
            const port_result_t *p = &host->ports[i];
            if (p->state != PORT_OPEN) continue;
            if (!first_port) strbuf_append(sb, ",\n");
            first_port = 0;

            strbuf_appendf(sb, "        { \"port\": %d, \"service\": \"", p->port);
            strbuf_append_json_escaped(sb, p->service);
            strbuf_append(sb, "\", \"version\": \"");
            strbuf_append_json_escaped(sb, p->version[0] ? p->version : p->banner);
            strbuf_append(sb, "\" }");
        }
        strbuf_append(sb, "\n      ],\n      \"findings\": [\n");

        for (int i = 0; i < host->finding_count; i++) {
            const finding_t *f = &host->findings[i];
            if (i > 0) strbuf_append(sb, ",\n");
            strbuf_append(sb, "        {\n");
            strbuf_appendf(sb, "          \"id\": \"%s\",\n", f->id);
            strbuf_append(sb, "          \"title\": \""); strbuf_append_json_escaped(sb, f->title); strbuf_append(sb, "\",\n");
            strbuf_appendf(sb, "          \"severity\": \"%s\",\n", severity_to_str(f->severity));
            strbuf_appendf(sb, "          \"confidence\": \"%s\",\n", confidence_to_str(f->confidence));
            strbuf_append(sb, "          \"description\": \""); strbuf_append_json_escaped(sb, f->description); strbuf_append(sb, "\",\n");
            strbuf_append(sb, "          \"evidence\": \""); strbuf_append_json_escaped(sb, f->evidence); strbuf_append(sb, "\",\n");
            strbuf_append(sb, "          \"remediation\": \""); strbuf_append_json_escaped(sb, f->remediation); strbuf_append(sb, "\"\n");
            strbuf_append(sb, "        }");
        }
        strbuf_append(sb, "\n      ]\n    }");
    }
    strbuf_append(sb, "\n  ]");
}
