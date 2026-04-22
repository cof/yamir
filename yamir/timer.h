/*
 * A simple timer API
 * -------------------
 * timer_init(tm)  : init timers state
 * timer_deinit(tm) : deinit timer state
 * timer_process(tm, next_wait) : process timers, return next_wait or next_expiry
 * timer_add(tm, msec, cb, arg) -> tid : add timer, return tid
 * time_cancel(tm, tid)  : cancel timer
 *
 */
#ifndef _TIMER_H_
#define _TIMER_H_

#define TIMER_MAXSLOT 128

struct timer_slot {
    uint64_t expiry; // milliseconds
    uint32_t hidx;   // heap position (or free slot index)
    uint32_t flags;
    void (*cb)(void *arg);
    void *arg;
};

#define TSF_ACTIVE  1

struct timer_mgr {
    int num_timer;
    int num_fire;
    int free_head;
    struct timer_slot slot[TIMER_MAXSLOT];
    struct timer_slot fire[TIMER_MAXSLOT];
    int heap[TIMER_MAXSLOT];
};

int timer_init(struct timer_mgr *tm);
void timer_deinit(struct timer_mgr *tm);
int timer_process(struct timer_mgr *tm, int wait_ms);

int timer_add(struct timer_mgr *tm, uint64_t ms, void (*cb)(void *arg), void *arg);
void timer_cancel(struct timer_mgr *tm, int tid);


#endif
