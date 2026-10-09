#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "reconpulse/webserver.h"
#include "reconpulse/netutils.h"
#include "reconpulse/scan_engine.h"
#include "reconpulse/report.h"
#include "reconpulse/strbuf.h"
#include "reconpulse/log.h"

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <unistd.h>
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
#endif

extern unsigned char index_html[];
extern unsigned int index_html_len;

#define MAX_JOBS 256
#define REQ_BUF_SIZE 8192
#define BODY_BUF_SIZE 4096

typedef enum { JOB_PENDING, JOB_RUNNING, JOB_DONE } job_status_t;

typedef struct {
    int id;
    int used;
    volatile job_status_t status;
    scan_config_t cfg;
    host_result_t *results;
    int host_count;
    time_t started;
} scan_job_t;

static scan_job_t g_jobs[MAX_JOBS];
static int g_next_id = 1;
static pthread_mutex_t g_jobs_lock = PTHREAD_MUTEX_INITIALIZER;

/* --- tiny flat-JSON helpers: this server only ever parses request bodies
 * it generated the schema for (target/port_start/port_end/scan_type/
 * threads/timeout_ms/vuln_checks), so a substring-based extractor is
 * sufficient — no nested objects/arrays to worry about. */
static int json_get_string(const char *body, const char *key, char *out, size_t out_len)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(body, needle);
    if (!p) return 0;
    p = strchr(p + strlen(needle), ':');
    if (!p) return 0;
    p = strchr(p, '"');
    if (!p) return 0;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < out_len - 1) out[i++] = *p++;
    out[i] = '\0';
    return 1;
}

static int json_get_int(const char *body, const char *key, int def)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(body, needle);
    if (!p) return def;
    p = strchr(p + strlen(needle), ':');
    if (!p) return def;
    return atoi(p + 1);
}

static int json_get_bool(const char *body, const char *key, int def)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(body, needle);
    if (!p) return def;
    p = strchr(p + strlen(needle), ':');
    if (!p) return def;
    p++;
    while (*p == ' ') p++;
    return strncmp(p, "true", 4) == 0;
}

static void send_response(socket_t sock, int status, const char *status_text,
                           const char *content_type, const char *body, size_t body_len)
{
    char header[256];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
        status, status_text, content_type, body_len);
    net_send_all(sock, header, hlen);
    if (body_len > 0) net_send_all(sock, body, (int)body_len);
}

static void *job_thread_fn(void *arg)
{
    scan_job_t *job = (scan_job_t *)arg;
    job->status = JOB_RUNNING;
    run_scan(&job->cfg, &job->results, &job->host_count);
    job->status = JOB_DONE;
    return NULL;
}

static scan_job_t *create_job(const scan_config_t *cfg)
{
    pthread_mutex_lock(&g_jobs_lock);
    scan_job_t *job = NULL;
    for (int i = 0; i < MAX_JOBS; i++) {
        if (!g_jobs[i].used) { job = &g_jobs[i]; break; }
    }
    if (job) {
        memset(job, 0, sizeof(*job));
        job->used = 1;
        job->id = g_next_id++;
        job->status = JOB_PENDING;
        job->cfg = *cfg;
        job->started = time(NULL);
    }
    pthread_mutex_unlock(&g_jobs_lock);

    if (job) {
        pthread_t t;
        pthread_create(&t, NULL, job_thread_fn, job);
        pthread_detach(t);
    }
    return job;
}

static scan_job_t *find_job(int id)
{
    for (int i = 0; i < MAX_JOBS; i++)
        if (g_jobs[i].used && g_jobs[i].id == id) return &g_jobs[i];
    return NULL;
}

static void handle_post_scan(socket_t sock, const char *body, const scan_config_t *base_cfg)
{
    scan_config_t cfg = *base_cfg;
    json_get_string(body, "target", cfg.target_cidr, sizeof(cfg.target_cidr));
    cfg.port_start = json_get_int(body, "port_start", 1);
    cfg.port_end = json_get_int(body, "port_end", 1024);
    cfg.run_vuln_checks = json_get_bool(body, "vuln_checks", 1);
    cfg.authorized = 1; /* server-level --authorize already gated startup */

    int threads = json_get_int(body, "threads", base_cfg->thread_count);
    if (threads > 0 && threads <= 500) cfg.thread_count = threads;

    int timeout = json_get_int(body, "timeout_ms", base_cfg->timeout_ms);
    if (timeout > 0 && timeout <= 20000) cfg.timeout_ms = timeout;

    char scan_type[16] = {0};
    json_get_string(body, "scan_type", scan_type, sizeof(scan_type));
    if (!strcmp(scan_type, "syn")) cfg.scan_type = SCAN_SYN;
    else if (!strcmp(scan_type, "udp")) cfg.scan_type = SCAN_UDP;
    else cfg.scan_type = SCAN_CONNECT;

    if (cfg.target_cidr[0] == '\0') {
        const char *err = "{\"error\":\"missing target\"}";
        send_response(sock, 400, "Bad Request", "application/json", err, strlen(err));
        return;
    }

    scan_job_t *job = create_job(&cfg);
    if (!job) {
        const char *err = "{\"error\":\"job queue full\"}";
        send_response(sock, 503, "Service Unavailable", "application/json", err, strlen(err));
        return;
    }

    char resp[64];
    int n = snprintf(resp, sizeof(resp), "{\"job_id\": %d}", job->id);
    send_response(sock, 200, "OK", "application/json", resp, (size_t)n);
}

static void handle_get_job(socket_t sock, int id)
{
    scan_job_t *job = find_job(id);
    if (!job) {
        const char *err = "{\"error\":\"not found\"}";
        send_response(sock, 404, "Not Found", "application/json", err, strlen(err));
        return;
    }

    strbuf_t sb;
    strbuf_init(&sb);

    if (job->status != JOB_DONE) {
        strbuf_appendf(&sb, "{ \"status\": \"%s\", \"target\": \"%s\" }",
                       job->status == JOB_RUNNING ? "running" : "pending", job->cfg.target_cidr);
    } else {
        strbuf_appendf(&sb, "{ \"status\": \"done\", \"target\": \"%s\", ", job->cfg.target_cidr);
        build_hosts_json(&sb, job->results, job->host_count);
        strbuf_append(&sb, " }");
    }

    send_response(sock, 200, "OK", "application/json", sb.data, sb.len);
    strbuf_free(&sb);
}

static void handle_get_jobs(socket_t sock)
{
    strbuf_t sb;
    strbuf_init(&sb);
    strbuf_append(&sb, "[");
    int first = 1;
    for (int i = 0; i < MAX_JOBS; i++) {
        if (!g_jobs[i].used) continue;
        if (!first) strbuf_append(&sb, ",");
        first = 0;
        strbuf_appendf(&sb, "{\"id\":%d,\"target\":\"%s\",\"status\":\"%s\"}",
                       g_jobs[i].id, g_jobs[i].cfg.target_cidr,
                       g_jobs[i].status == JOB_DONE ? "done" : g_jobs[i].status == JOB_RUNNING ? "running" : "pending");
    }
    strbuf_append(&sb, "]");
    send_response(sock, 200, "OK", "application/json", sb.data, sb.len);
    strbuf_free(&sb);
}

typedef struct {
    socket_t sock;
    const scan_config_t *base_cfg;
} client_ctx_t;

static void *handle_client(void *arg)
{
    client_ctx_t *ctx = (client_ctx_t *)arg;
    socket_t sock = ctx->sock;
    const scan_config_t *base_cfg = ctx->base_cfg;
    free(ctx);

    char req[REQ_BUF_SIZE];
    int total = 0, header_end = -1;
    net_set_timeout(sock, 10000);

    while (total < (int)sizeof(req) - 1) {
        int n = (int)recv(sock, req + total, sizeof(req) - 1 - total, 0);
        if (n <= 0) break;
        total += n;
        req[total] = '\0';
        char *pos = strstr(req, "\r\n\r\n");
        if (pos) { header_end = (int)(pos - req) + 4; break; }
    }

    if (header_end < 0) { net_close(sock); return NULL; }

    char method[8] = {0}, path[256] = {0};
    sscanf(req, "%7s %255s", method, path);

    char body[BODY_BUF_SIZE];
    int content_length = 0;
    char *cl = strstr(req, "Content-Length:");
    if (cl) content_length = atoi(cl + strlen("Content-Length:"));
    if (content_length >= (int)sizeof(body)) content_length = (int)sizeof(body) - 1;

    int have = total - header_end;
    if (have < 0) have = 0;
    if (have > content_length) have = content_length;
    if (have > 0) memcpy(body, req + header_end, (size_t)have);
    while (have < content_length) {
        int n = (int)recv(sock, body + have, content_length - have, 0);
        if (n <= 0) break;
        have += n;
    }
    body[have] = '\0';

    if (!strcmp(method, "GET") && !strcmp(path, "/")) {
        send_response(sock, 200, "OK", "text/html", (const char *)index_html, index_html_len);
    } else if (!strcmp(method, "POST") && !strcmp(path, "/api/scan")) {
        handle_post_scan(sock, body, base_cfg);
    } else if (!strcmp(method, "GET") && !strncmp(path, "/api/scan/", 10)) {
        handle_get_job(sock, atoi(path + 10));
    } else if (!strcmp(method, "GET") && !strcmp(path, "/api/jobs")) {
        handle_get_jobs(sock);
    } else {
        const char *msg = "not found";
        send_response(sock, 404, "Not Found", "text/plain", msg, strlen(msg));
    }

    net_close(sock);
    return NULL;
}

void webserver_run(const scan_config_t *base_cfg, int port)
{
    socket_t listener = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "Failed to bind port %d\n", port);
        return;
    }
    listen(listener, 32);

    log_msg(LOG_INFO, "Reconpulse dashboard listening on http://localhost:%d", port);

    for (;;) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        socket_t client = accept(listener, (struct sockaddr *)&client_addr, &len);
        if (client == INVALID_SOCKET) continue;

        client_ctx_t *ctx = malloc(sizeof(client_ctx_t));
        ctx->sock = client;
        ctx->base_cfg = base_cfg;

        pthread_t t;
        pthread_create(&t, NULL, handle_client, ctx);
        pthread_detach(t);
    }
}
