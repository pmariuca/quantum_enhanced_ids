#include "queue.h"
#include <stdlib.h>

void queue_init(struct qks_queue *q) {
    q->head = q->tail = NULL;
    q->closed = false;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);
}

void queue_close(struct qks_queue *q) {
    pthread_mutex_lock(&q->lock);
    q->closed = true;
    pthread_cond_broadcast(&q->cond); // wake any waiters
    pthread_mutex_unlock(&q->lock);
}

void queue_push(struct qks_queue *q, struct qks_event_msg *ev) {
    struct qks_queue_item *it = (struct qks_queue_item *)malloc(sizeof(*it));
    if (!it) return; // drop on OOM (could also log)
    it->ev = ev;
    it->next = NULL;

    pthread_mutex_lock(&q->lock);

    if (q->tail) q->tail->next = it;
    else         q->head = it;
    q->tail = it;

    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);
}

struct qks_event_msg *queue_pop(struct qks_queue *q) {
    pthread_mutex_lock(&q->lock);

    while (q->head == NULL && !q->closed) {
        pthread_cond_wait(&q->cond, &q->lock);
    }

    if (q->head == NULL && q->closed) {
        pthread_mutex_unlock(&q->lock);
        return NULL; // shutdown
    }

    struct qks_queue_item *it = q->head;
    q->head = it->next;
    if (!q->head) q->tail = NULL;

    pthread_mutex_unlock(&q->lock);

    struct qks_event_msg *ev = it->ev;
    free(it);
    return ev;
}