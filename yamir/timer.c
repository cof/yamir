/*
 *
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <sys/time.h>
#include <sys/types.h>

#include "timer.h"

struct timerheap {
    struct timer **data;
    int size;
    int used;
};

static struct timerheap *heap = NULL;

/* minium binary heap aka priortity queue
   based on the classc barkley and lee usenix 88 paper
   A Heap-Based Callout Implementation to Meet Real-Time Needs
*/
static struct timerheap *timerheap_new(void)
{
    struct timerheap *th;

    th = malloc(sizeof(*th));

    th->data = NULL;
    th->size = 0;
    th->used = 0;

    return th;
}

static void timerheap_free(struct timerheap *th)
{
    if (th->data) {
        free(th->data);
        th->data = NULL;
    }

    free(th);
}

static int get_left(int idx)
{
    return 2 * idx + 1;
}

static int get_right(int idx)
{
    return 2 * idx + 2;
}

static int get_parent(int idx)
{
    return (idx - 1) / 2;
}

static int timer_greater(struct timer *a, struct timer *b)
{
    return timercmp(&a->when, &b->when, >);
}


// min heap
static void sift_up(struct timerheap *th, int idx)
{
    if (idx > 0) {
        int pidx = get_parent(idx);
        if (timer_greater(th->data[pidx], th->data[idx])) {
            // swap
            struct timer *tmp = th->data[pidx];
            th->data[pidx] = th->data[idx];
            th->data[idx] = tmp;
            // update positions
            th->data[pidx]->idx = pidx;
            th->data[idx]->idx = idx;
            sift_up(th, pidx);
        }
    }
}

static void timerheap_push(struct timerheap *th, struct timer *value)
{
    // resize check
    if (th->used == th->size) {
        int size = th->used + 128;
        struct timer **data = realloc(th->data, sizeof(struct timer *) * size);
        if (!data) {
            fprintf(stderr, "malloc(%ld)", sizeof(struct timer *) * size);
            abort();
        }
        th->size = size;
        th->data = data;
    }

    th->data[th->used] = value;
    th->data[th->used]->idx = th->used;
    sift_up(th, th->used);

    th->used++;
}

static void sift_down(struct timerheap *th, int idx)
{
    int lidx = get_left(idx);
    int ridx = get_right(idx);
    int midx;

    if (ridx >= th->used) {
        if (lidx >= th->used) {
            return;
        }
        midx = lidx;
    }
    else {
        midx = timer_greater(th->data[lidx], th->data[ridx])
           ? ridx
           : lidx;
    }

    if (timer_greater(th->data[idx], th->data[midx])) {
        // swap
        struct timer *tmp = th->data[idx];
        th->data[idx] = th->data[midx];
        th->data[midx] = tmp;
        // update positions
        th->data[idx]->idx = idx;
        th->data[midx]->idx = midx;
        sift_down(th,midx);
    }
}

static void timerheap_remove(struct timerheap *th, struct timer *value)
{
    int idx = value->idx;

    if (idx < 0 || idx >= th->used) {
        return;
    }

    // replace item with last elem
    --th->used;
    th->data[idx] = th->data[th->used];
    th->data[idx]->idx = idx;

    if (timer_greater(th->data[idx], value)) {
        sift_down(th, idx);
    }
    else {
        sift_up(th, idx);
    }
    
    value->idx = -1;
}

static struct timer *timerheap_pop(struct timerheap *th)
{
    struct timer *t;

    if (th->used > 0) {
        --th->used;
        t = th->data[0];
        th->data[0] = th->data[th->used];
        th->data[0]->idx = 0;
        if (th->used > 0) {
            sift_down(th,0);
        }
        t->idx = -1;
    }
    else {
        t = NULL;
    }

    return t;
}


static struct timer *timerheap_min(struct timerheap *th)
{
    return (th->used > 0) ? th->data[0] : NULL;
}


int timer_init()
{
    if (heap) return 0;

    heap = timerheap_new();
    if (!heap) return -1;

    return 0;
}

void timer_deinit(void)
{
    if (heap) {
        timerheap_free(heap);
        heap = NULL;
    }
}

void timer_process(int *wait_msec)
{
    struct timeval now;
    struct timer *t;

    gettimeofday(&now, NULL);

    while (1) {
        t = timerheap_min(heap);
        if (!t) break;
        if (timercmp(&t->when, &now, >)) break;
        timerheap_pop(heap);
        t->cb_fn(t->cb_arg);
        free(t);
    } 

    struct timeval tv = { .tv_sec = 5 };
    if (t) timersub(&t->when, &now, &tv);
    *wait_msec = tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
}

struct timer *timer_add(void (*cb_fn)(void *cb_arg), void *cb_arg, struct timeval *timeout)
{
    struct timer *t;
    struct timeval now;

    t = malloc(sizeof(*t));

    t->cb_fn = cb_fn;
    t->cb_arg = cb_arg;

    gettimeofday(&now, NULL);
    timeradd(&now, timeout, &t->when);

    timerheap_push(heap, t);

    return t;
}

struct timer *timer_add_wsec(void (*cb_fn)(void *cb_arg), void *cb_arg, time_t sec)
{
    struct timeval wait;

    wait.tv_sec = sec;
    wait.tv_usec = 0;

    return timer_add(cb_fn, cb_arg, &wait);
}

void timer_del(struct timer *t)
{
    timerheap_remove(heap, t);
    free(t);
}
