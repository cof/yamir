/* SPDX-License-Identifier: MIT | (c) 2026 [cof] */

/*
 * A simple timer API
 * ------------------
 * Timer code uses a fixed-size min-heap callout queue.
 * See timer.h for API documentation
 *
*/
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "log.h"
#include "timer.h"


static inline void heap_swap(struct timer_mgr *tm, int pos1, int pos2)
{
    int idx1 = tm->heap[pos1];
    int idx2 = tm->heap[pos2];

    // swap positions
    tm->heap[pos1] = idx2;
    tm->heap[pos2] = idx1;

    // update slots
    tm->slot[idx1].hpos = pos2;
    tm->slot[idx2].hpos = pos1;
}

static inline bool timer_greater(struct timer_mgr *tm, int idx1, int idx2)
{
    return tm->slot[idx1].expiry > tm->slot[idx2].expiry;
}

static inline bool heap_greater(struct timer_mgr *tm, int pos1, int pos2)
{
    return timer_greater(tm, tm->heap[pos1], tm->heap[pos2]);
}

//  sift up or swim
static void minheap_siftup(struct timer_mgr *tm, int idx)
{
    //log_debug("nheap=%d idx=%d", tm->num_timer, idx);

    int parent = (idx - 1) / 2;

    while (idx > 0 && heap_greater(tm, parent, idx)) {
        heap_swap(tm, parent, idx);
        idx = parent;
        parent = (idx - 1) / 2;
    }
}

// sift down or sink
static void minheap_siftdown(struct timer_mgr *tm, int idx)
{
    //log_debug("nheap=%d idx=%d", tm->num_timer, idx);

    if (tm->num_timer < 2) return;

    int child = idx;
    while (idx == child && idx <= (tm->num_timer - 2) / 2) {
        // choose lesser left|right child
        child = 2 * idx + 1;
        if (child + 1 < tm->num_timer && heap_greater(tm, child, child + 1)) {
            child++;
        }
        if (heap_greater(tm, idx, child)) {
            heap_swap(tm, child, idx);
            idx = child;
        }
    }
}

static void slot_release(struct timer_mgr *tm, struct timer_slot *ts)
{
    int tid = ts - tm->slot;

    log_debug("tid=%d ntimer=%d", tm->num_timer, tid);

    ts->hpos = tm->free_head;
    ts->flags = 0;
    ts->cb = NULL;
    ts->arg = NULL;

    tm->free_head = tid;
}

static int get_free_slot(struct timer_mgr *tm)
{
    int tid = tm->free_head;

    if (tid != -1) {
        tm->free_head = tm->slot[tid].hpos;
    }

    return tid;
}

static inline uint64_t get_now_ms(void)
{
    struct timespec ts;

    int rc = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (rc == -1) return (uint64_t) -1;

    // convert to msec
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static inline int get_delta_ms(uint64_t t1, uint64_t t2)
{
    return t1 > t2 ? t1 - t2 : 0;
}

static inline int next_expiry(struct timer_mgr *tm)
{
    if (tm->num_timer <= 0) return -1;

    int tid = tm->heap[0];
    struct timer_slot *ts = &tm->slot[tid];

    return get_delta_ms(ts->expiry, tm->now_ms);
}

int timer_init(struct timer_mgr *tm)
{
    log_debug("max_timer=%d" , TIMER_MAXSLOT);

    tm->free_head = 0;

    for (int i= 0; i < TIMER_MAXSLOT - 1; i++) {
        tm->slot[i].hpos = i + 1;
    }

    tm->slot[TIMER_MAXSLOT - 1].hpos = -1;

    return 0;
}

void timer_deinit(struct timer_mgr *tm)
{
    tm->num_timer = 0;
}

int timer_check(struct timer_mgr *tm)
{
    tm->now_ms = get_now_ms();

    log_debug("now_ms=%lu ntimer=%d", tm->now_ms, tm->num_timer);

    while (tm->num_timer) {
        int tid = tm->heap[0];
        struct timer_slot *ts = &tm->slot[tid];
        int delta_ms = get_delta_ms(ts->expiry, tm->now_ms);
        log_debug("tid=%d expiry=%lu delta=%d", tid, ts->expiry, delta_ms);
        if (delta_ms) break;
        // copy expired timer
        tm->fire[tm->num_fire++] = *ts;
        // min_heappop:
        tm->heap[0] = tm->heap[--tm->num_timer];
        minheap_siftdown(tm, 0);
        slot_release(tm, ts);
    }

    // fire pending timers
    int n = tm->num_fire;
    tm->num_fire = 0;
    for (int i = 0; i < n; i++) {
        log_debug("fire cb=%p arg=%p", tm->fire[i].cb, tm->fire[i].arg);
        if (tm->fire[i].cb) {
            tm->fire[i].cb(tm->fire[i].arg);
            tm->fire[i].cb = NULL;
        }
        tm->fire[i].arg = NULL;
    }

    int next_ms = next_expiry(tm);
    log_debug("next_ms=%d", next_ms);

    return next_ms;
}

int timer_add(struct timer_mgr *tm, uint32_t delay_ms, void (*cb)(void *arg), void *arg)
{
    log_debug("delay=%u cb=%p arg=%p ntimer=%d", delay_ms, cb, arg, tm->num_timer);

    int tid = get_free_slot(tm);
    if (tid == -1) return -1;

    struct timer_slot *ts = &tm->slot[tid];
    uint64_t now_ms = get_now_ms();

    ts->expiry = now_ms + delay_ms;
    ts->hpos   = tm->num_timer;
    ts->flags  = TSF_ACTIVE;
    ts->cb  = cb;
    ts->arg = arg;

    tm->heap[tm->num_timer++] = tid;
    minheap_siftup(tm, tm->num_timer - 1);

    log_debug("tid=%d now_ms=%lu expiry=%lu hpos=%u ntimer=%d", 
        tid, now_ms, ts->expiry, ts->hpos, tm->num_timer);

    return tid;
}

void timer_cancel(struct timer_mgr *tm, int tid)
{
    log_debug("tid=%d ntimer=%d", tid, tm->num_timer);

    if (tid < 0 || tid >= TIMER_MAXSLOT) return;

    struct timer_slot *ts = &tm->slot[tid];
    int hpos = ts->hpos;
    if (hpos < 0) return;

    int last_hpos = --tm->num_timer;

    if (hpos != last_hpos) {
        heap_swap(tm, hpos, last_hpos);
        if (heap_greater(tm, hpos, last_hpos)) {
            minheap_siftdown(tm, hpos);
        }
        else {
            minheap_siftup(tm, hpos);
        }
    }

    slot_release(tm, ts);
}
