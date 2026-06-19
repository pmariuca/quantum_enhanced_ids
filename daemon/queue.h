// queue.h
#ifndef QKS_QUEUE_H
#define QKS_QUEUE_H

#include <pthread.h>
#include <stddef.h>
#include <stdbool.h>

struct qks_event_msg;

struct qks_queue_item {
    struct qks_event_msg *ev;
    struct qks_queue_item *next;
};

struct qks_queue {
    struct qks_queue_item *head;
    struct qks_queue_item *tail;
    pthread_mutex_t lock;
    pthread_cond_t  cond;

    bool closed;
};

void queue_init(struct qks_queue *q);
void queue_close(struct qks_queue *q); // wakes any waiter; pop will return NULL when closed and empty
void queue_push(struct qks_queue *q, struct qks_event_msg *ev);
struct qks_event_msg *queue_pop(struct qks_queue *q);

#endif