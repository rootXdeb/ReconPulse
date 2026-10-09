#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "reconpulse/scan_engine.h"
#include "reconpulse/netutils.h"
#include "reconpulse/threadpool.h"
#include "reconpulse/discovery.h"
#include "reconpulse/portscan.h"
#include "reconpulse/service_probe.h"
#include "reconpulse/vuln_checks.h"

/* Three-phase pipeline so the thread pool is shared across hosts AND
 * ports, rather than one thread being pinned to a single host for its
 * entire port range:
 *   1. discovery  - one task per host
 *   2. port scan  - one task per (alive host, port) pair, flattened into
 *                   a single queue every worker thread pulls from
 *   3. vuln checks - one task per alive host (each check internally only
 *                    touches that host's own open ports)
 * This means --threads is equally meaningful whether you scan one host
 * with a wide port range or a whole subnet — the pool never leaves idle
 * threads waiting on one slow host while work sits queued elsewhere. */

typedef struct {
    char ip[MAX_IP_LEN];
    const scan_config_t *cfg;
    host_result_t *result;
} discover_task_t;

static void discover_task_fn(void *arg)
{
    discover_task_t *t = (discover_task_t *)arg;
    memset(t->result, 0, sizeof(*t->result));
    snprintf(t->result->ip, sizeof(t->result->ip), "%s", t->ip);
    t->result->is_alive = host_is_alive(t->ip, t->cfg->timeout_ms);
}

typedef struct {
    const char *ip;
    int port;
    const scan_config_t *cfg;
    host_result_t *host;
    pthread_mutex_t *lock;
} port_task_t;

static void port_scan_task(void *arg)
{
    port_task_t *t = (port_task_t *)arg;

    port_state_t state;
    switch (t->cfg->scan_type) {
        case SCAN_SYN: state = tcp_syn_scan_port(t->ip, t->port, t->cfg->timeout_ms); break;
        case SCAN_UDP: state = udp_scan_port(t->ip, t->port, t->cfg->timeout_ms); break;
        default:       state = tcp_connect_scan_port(t->ip, t->port, t->cfg->timeout_ms); break;
    }
    if (state != PORT_OPEN) return;

    /* Reserve a slot under the lock, then do the slow banner-grab I/O
     * outside it so concurrent port tasks for the same host never block
     * on each other. */
    pthread_mutex_lock(t->lock);
    int idx = (t->host->port_count < MAX_PORTS_PER_HOST) ? t->host->port_count++ : -1;
    pthread_mutex_unlock(t->lock);
    if (idx < 0) return;

    port_result_t *p = &t->host->ports[idx];
    memset(p, 0, sizeof(*p));
    p->port = t->port;
    p->state = state;
    snprintf(p->protocol, sizeof(p->protocol), "%s", t->cfg->scan_type == SCAN_UDP ? "udp" : "tcp");

    grab_banner(t->ip, t->port, t->cfg->timeout_ms, p->banner, sizeof(p->banner));
    identify_service(t->port, p->banner, p->service, sizeof(p->service), p->version, sizeof(p->version));
}

typedef struct {
    char ip[MAX_IP_LEN];
    host_result_t *host;
    int timeout_ms;
} vuln_task_t;

static void vuln_task_fn(void *arg)
{
    vuln_task_t *t = (vuln_task_t *)arg;
    run_vuln_checks(t->ip, t->host, t->timeout_ms);
}

void run_scan(const scan_config_t *cfg, host_result_t **results, int *host_count)
{
    char (*hosts)[MAX_IP_LEN] = malloc((size_t)MAX_HOSTS * MAX_IP_LEN);
    int count = cidr_expand(cfg->target_cidr, hosts, MAX_HOSTS);

    *results = calloc((size_t)(count > 0 ? count : 1), sizeof(host_result_t));
    *host_count = count;
    if (count == 0) { free(hosts); return; }

    threadpool_t *pool = threadpool_create(cfg->thread_count);

    /* Phase 1: discovery */
    discover_task_t *dtasks = calloc((size_t)count, sizeof(discover_task_t));
    for (int i = 0; i < count; i++) {
        snprintf(dtasks[i].ip, sizeof(dtasks[i].ip), "%s", hosts[i]);
        dtasks[i].cfg = cfg;
        dtasks[i].result = &(*results)[i];
        threadpool_submit(pool, discover_task_fn, &dtasks[i]);
    }
    threadpool_wait(pool);

    /* Phase 2: port scan, flattened across every alive host */
    pthread_mutex_t *locks = calloc((size_t)count, sizeof(pthread_mutex_t));
    for (int i = 0; i < count; i++) pthread_mutex_init(&locks[i], NULL);

    int port_range = cfg->port_end - cfg->port_start + 1;
    if (port_range < 0) port_range = 0;
    size_t max_tasks = (size_t)count * (size_t)port_range;
    port_task_t *ptasks = malloc((max_tasks > 0 ? max_tasks : 1) * sizeof(port_task_t));
    size_t pt_idx = 0;

    for (int i = 0; i < count; i++) {
        if (!(*results)[i].is_alive) continue;
        for (int port = cfg->port_start; port <= cfg->port_end; port++) {
            port_task_t *t = &ptasks[pt_idx++];
            t->ip = dtasks[i].ip;
            t->port = port;
            t->cfg = cfg;
            t->host = &(*results)[i];
            t->lock = &locks[i];
            threadpool_submit(pool, port_scan_task, t);
        }
    }
    threadpool_wait(pool);

    for (int i = 0; i < count; i++) pthread_mutex_destroy(&locks[i]);
    free(locks);

    /* Phase 3: vulnerability checks per alive host */
    vuln_task_t *vtasks = calloc((size_t)count, sizeof(vuln_task_t));
    if (cfg->run_vuln_checks) {
        for (int i = 0; i < count; i++) {
            if (!(*results)[i].is_alive) continue;
            snprintf(vtasks[i].ip, sizeof(vtasks[i].ip), "%s", hosts[i]);
            vtasks[i].host = &(*results)[i];
            vtasks[i].timeout_ms = cfg->timeout_ms;
            threadpool_submit(pool, vuln_task_fn, &vtasks[i]);
        }
        threadpool_wait(pool);
    }

    threadpool_destroy(pool);
    free(vtasks);
    free(ptasks);
    free(dtasks);
    free(hosts);
}
