#ifndef RECONPULSE_THREADPOOL_H
#define RECONPULSE_THREADPOOL_H

typedef void (*task_fn_t)(void *arg);

typedef struct threadpool threadpool_t;

threadpool_t *threadpool_create(int thread_count);
int threadpool_submit(threadpool_t *pool, task_fn_t fn, void *arg);
void threadpool_wait(threadpool_t *pool);
void threadpool_destroy(threadpool_t *pool);

#endif
