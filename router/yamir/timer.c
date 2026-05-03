/*
 * A simple timer API
 * ------------------
 * See timer.h for API description.
 *
 * Notes
 * ------
 * Uses a minimum binary heap aka priortity queue
 * Based on the classc barkley and lee usenix 88 paper
 * A Heap-Based Callout Implementation to Meet Real-Time Needs
*/
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "log.h"
#include "timer.h"

#define swap(x,y) do { \
    __typeof__(x) _tmp = (x); \
    (x) = (y); \
    (y) = _tmp; \
} while(0)

static bool timer_greater(struct timer_mgr *tm, int t1, int t2)
{
    struct timer_slot *ts1 = &tm->slot[t1];
    struct timer_slot *ts2 = &tm->slot[t2];

    return ts1->expiry > ts2->expiry;
}

//  sift up or swim
static void minheap_siftup(struct timer_mgr *tm, int idx)
{
    //log_debug("nheap=%d idx=%d", tm->num_timer, idx);

    int parent = (idx - 1) / 2;

    while (idx > 0 && timer_greater(tm, tm->heap[parent], tm->heap[idx])) {
        swap(tm->heap[parent], tm->heap[idx]);
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
        if (child + 1 < tm->num_timer && timer_greater(tm, tm->heap[child], tm->heap[child+1])) {
            child++;
        }
        if (timer_greater(tm, tm->heap[idx], tm->heap[child])) {
            swap(tm->heap[child], tm->heap[idx]);
            idx = child;
        }
    }
}

static void slot_release(struct timer_mgr *tm, struct timer_slot *ts)
{
    int tid = ts - tm->slot;

    log_debug("ntimer=%d tid=%d", tm->num_timer, tid);

    ts->hidx = tm->free_head;
    ts->flags = 0;
    ts->cb = NULL;
    ts->arg = NULL;

    tm->free_head = tid;
}

static int get_free_slot(struct timer_mgr *tm)
{
    int tid = tm->free_head;

    if (tid != -1) {
        tm->free_head = tm->slot[tid].hidx;
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
        tm->slot[i].hidx = i + 1;
    }

    tm->slot[TIMER_MAXSLOT - 1].hidx = -1;

    return 0;
}

void timer_deinit(struct timer_mgr *tm)
{
    tm->num_timer = 0;
}

int timer_check(struct timer_mgr *tm)
{
    tm->now_ms = get_now_ms();

    log_debug("ntimer=%d now_ms=%lu" , tm->num_timer, tm->now_ms);

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

int timer_add(struct timer_mgr *tm, uint64_t ms, void (*cb)(void *arg), void *arg)
{
    log_debug("ntimer=%d ms=%lu cb=%p arg=%p", tm->num_timer, ms, cb, arg);

    int tid = get_free_slot(tm);
    if (tid == -1) return -1;

    struct timer_slot *ts = &tm->slot[tid];
    uint64_t now_ms = get_now_ms();

    ts->expiry = now_ms + ms;
    ts->hidx   = tm->num_timer;
    ts->flags  = TSF_ACTIVE;
    ts->cb  = cb;
    ts->arg = arg;

    tm->heap[tm->num_timer++] = tid;
    minheap_siftup(tm, tm->num_timer - 1);

    log_debug("ntimer=%d tid=%d now_ms=%lu expiry=%lu hidx=%d", tm->num_timer, tid, now_ms, ts->expiry, ts->hidx);

    return tid;
}

void timer_cancel(struct timer_mgr *tm, int tid)
{
    log_debug("ntimer=%d tid=%d", tm->num_timer, tid);

    if (tid < 0 || tid >= TIMER_MAXSLOT) return;

    struct timer_slot *ts = &tm->slot[tid];
    int hidx = ts->hidx;
    if (hidx < 0) return;

    int last_hidx = --tm->num_timer;

    if (hidx != last_hidx) {
        swap(tm->heap[hidx], tm->heap[last_hidx]);
        if (timer_greater(tm, hidx, last_hidx)) {
            minheap_siftdown(tm, hidx);
        }
        else {
            minheap_siftup(tm, hidx);
        }
    }

    slot_release(tm, ts);
}
