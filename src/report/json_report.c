#include <stdio.h>
#include "reconpulse/report.h"

void report_write_json(const host_result_t *hosts, int host_count, const char *path)
{
    strbuf_t sb;
    strbuf_init(&sb);
    strbuf_append(&sb, "{\n  ");
    build_hosts_json(&sb, hosts, host_count);
    strbuf_append(&sb, "\n}\n");

    FILE *f = fopen(path, "w");
    if (f) {
        fputs(sb.data, f);
        fclose(f);
    }
    strbuf_free(&sb);
}
