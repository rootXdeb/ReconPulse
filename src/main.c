#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "reconpulse/common.h"
#include "reconpulse/netutils.h"
#include "reconpulse/scan_engine.h"
#include "reconpulse/report.h"
#include "reconpulse/webserver.h"
#include "reconpulse/log.h"

static void print_usage(const char *prog)
{
    printf("Reconpulse %s — network reconnaissance and vulnerability verification scanner\n\n", RECONPULSE_VERSION);
    printf("Usage: %s -t <target> --authorize [options]\n", prog);
    printf("       %s --serve --authorize [--web-port 8888]\n\n", prog);
    printf("Required:\n");
    printf("  -t, --target <ip|cidr>   Target host or CIDR range (e.g. 192.168.56.101 or 192.168.56.0/24)\n");
    printf("      --authorize          Explicit confirmation you are authorized to scan the target\n\n");
    printf("Options:\n");
    printf("  -p, --ports <a-b>        Port range (default 1-1024)\n");
    printf("      --scan-type <t>      connect | syn | udp (default connect)\n");
    printf("      --threads <n>        Worker threads (default 50)\n");
    printf("      --timeout <ms>       Per-probe timeout in ms (default 800)\n");
    printf("      --no-vuln            Skip vulnerability checks (port/service scan only)\n");
    printf("  -f, --format <fmt>       cli | json | html (default cli)\n");
    printf("  -o, --output <path>      Output file (required for json/html)\n");
    printf("      --serve              Launch the web dashboard instead of a one-shot scan\n");
    printf("      --web-port <n>       Dashboard HTTP port (default 8888)\n");
    printf("  -h, --help               Show this help\n");
}

int main(int argc, char **argv)
{
    scan_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.port_start = 1;
    cfg.port_end = 1024;
    cfg.thread_count = 50;
    cfg.timeout_ms = 800;
    cfg.scan_type = SCAN_CONNECT;
    cfg.run_vuln_checks = 1;
    snprintf(cfg.output_format, sizeof(cfg.output_format), "cli");

    int serve_mode = 0;
    int web_port = 8888;

    for (int i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-t") || !strcmp(argv[i], "--target")) && i + 1 < argc) {
            snprintf(cfg.target_cidr, sizeof(cfg.target_cidr), "%s", argv[++i]);
        } else if ((!strcmp(argv[i], "-p") || !strcmp(argv[i], "--ports")) && i + 1 < argc) {
            sscanf(argv[++i], "%d-%d", &cfg.port_start, &cfg.port_end);
        } else if (!strcmp(argv[i], "--scan-type") && i + 1 < argc) {
            i++;
            if (!strcmp(argv[i], "syn")) cfg.scan_type = SCAN_SYN;
            else if (!strcmp(argv[i], "udp")) cfg.scan_type = SCAN_UDP;
            else cfg.scan_type = SCAN_CONNECT;
        } else if (!strcmp(argv[i], "--threads") && i + 1 < argc) {
            cfg.thread_count = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--timeout") && i + 1 < argc) {
            cfg.timeout_ms = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--no-vuln")) {
            cfg.run_vuln_checks = 0;
        } else if ((!strcmp(argv[i], "-f") || !strcmp(argv[i], "--format")) && i + 1 < argc) {
            snprintf(cfg.output_format, sizeof(cfg.output_format), "%s", argv[++i]);
        } else if ((!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output")) && i + 1 < argc) {
            snprintf(cfg.output_file, sizeof(cfg.output_file), "%s", argv[++i]);
        } else if (!strcmp(argv[i], "--authorize")) {
            cfg.authorized = 1;
        } else if (!strcmp(argv[i], "--serve")) {
            serve_mode = 1;
        } else if (!strcmp(argv[i], "--web-port") && i + 1 < argc) {
            web_port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!serve_mode && cfg.target_cidr[0] == '\0') {
        fprintf(stderr, "Error: --target is required (or use --serve for the dashboard).\n\n");
        print_usage(argv[0]);
        return 1;
    }
    if (!cfg.authorized) {
        fprintf(stderr,
            "Refusing to start: --authorize was not supplied.\n"
            "Only run this tool against systems you own or have explicit written\n"
            "authorization to test. Pass --authorize to confirm and proceed.\n");
        return 1;
    }

    if (net_global_init() != 0) {
        fprintf(stderr, "Failed to initialize networking.\n");
        return 1;
    }

    if (serve_mode) {
        webserver_run(&cfg, web_port);
        net_global_cleanup();
        return 0;
    }

    log_msg(LOG_INFO, "Scanning target %s, ports %d-%d, scan-type=%d, threads=%d",
            cfg.target_cidr, cfg.port_start, cfg.port_end, cfg.scan_type, cfg.thread_count);

    host_result_t *results = NULL;
    int host_count = 0;
    run_scan(&cfg, &results, &host_count);

    if (!strcmp(cfg.output_format, "json") && cfg.output_file[0])
        report_write_json(results, host_count, cfg.output_file);
    else if (!strcmp(cfg.output_format, "html") && cfg.output_file[0])
        report_write_html(results, host_count, cfg.output_file);
    else
        report_print_cli(results, host_count);

    free(results);
    net_global_cleanup();
    return 0;
}
