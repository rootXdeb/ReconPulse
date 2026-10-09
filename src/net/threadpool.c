/* Portable pthread-based pool. On Windows this requires MinGW-w64 built
 * with the posix threading model (winpthreads) — see README build notes. */
#include <stdlib.h>
#include <pthread.h>
#include "reconpulse/threadpool.h"

typedef struct task_node {
    task_fn_t fn;
    void *arg;
    struct task_node *next;
} task_node_t;

struct threadpool {
    pthread_t *workers;
    int thread_count;

    task_node_t *head, *tail;
    pthread_mutex_t queue_lock;
    pthread_cond_t queue_cond;

    int pending;              /* queued + in-flight tasks */
    pthread_cond_t done_cond;

    int shutdown;
};

static void *worker_loop(void *arg)
{
    threadpool_t *pool = (threadpool_t *)arg;

    for (;;) {
        pthread_mutex_lock(&pool->queue_lock);
        while (!pool->head && !pool->shutdown)
            pthread_cond_wait(&pool->queue_cond, &pool->queue_lock);

        if (pool->shutdown && !pool->head) {
            pthread_mutex_unlock(&pool->queue_lock);
            break;
        }

        task_node_t *node = pool->head;
        pool->head = node->next;
        if (!pool->head) pool->tail = NULL;
        pthread_mutex_unlock(&pool->queue_lock);

        node->fn(node->arg);
        free(node);

        pthread_mutex_lock(&pool->queue_lock);
        pool->pending--;
        if (pool->pending == 0)
            pthread_cond_broadcast(&pool->done_cond);
        pthread_mutex_unlock(&pool->queue_lock);
    }
    return NULL;
}

threadpool_t *threadpool_create(int thread_count)
{
    if (thread_count < 1) thread_count = 1;

    threadpool_t *pool = calloc(1, sizeof(threadpool_t));
    if (!pool) return NULL;

    pool->thread_count = thread_count;
    pool->workers = calloc((size_t)thread_count, sizeof(pthread_t));
    pthread_mutex_init(&pool->queue_lock, NULL);
    pthread_cond_init(&pool->queue_cond, NULL);
    pthread_cond_init(&pool->done_cond, NULL);

    for (int i = 0; i < thread_count; i++)
        pthread_create(&pool->workers[i], NULL, worker_loop, pool);

    return pool;
}

int threadpool_submit(threadpool_t *pool, task_fn_t fn, void *arg)
{
    task_node_t *node = malloc(sizeof(task_node_t));
    if (!node) return -1;
    node->fn = fn;
    node->arg = arg;
    node->next = NULL;

    pthread_mutex_lock(&pool->queue_lock);
    if (pool->tail) pool->tail->next = node;
    else pool->head = node;
    pool->tail = node;
    pool->pending++;
    pthread_cond_signal(&pool->queue_cond);
    pthread_mutex_unlock(&pool->queue_lock);
    return 0;
}

void threadpool_wait(threadpool_t *pool)
{
    pthread_mutex_lock(&pool->queue_lock);
    while (pool->pending > 0)
        pthread_cond_wait(&pool->done_cond, &pool->queue_lock);
    pthread_mutex_unlock(&pool->queue_lock);
}

void threadpool_destroy(threadpool_t *pool)
{
    if (!pool) return;

    pthread_mutex_lock(&pool->queue_lock);
    pool->shutdown = 1;
    pthread_cond_broadcast(&pool->queue_cond);
    pthread_mutex_unlock(&pool->queue_lock);

    for (int i = 0; i < pool->thread_count; i++)
        pthread_join(pool->workers[i], NULL);

    pthread_mutex_destroy(&pool->queue_lock);
    pthread_cond_destroy(&pool->queue_cond);
    pthread_cond_destroy(&pool->done_cond);
    free(pool->workers);
    free(pool);
}
