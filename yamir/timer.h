/*
 * timer
 * -----
 * A simple timer API 
 *
 * - No dynamic memory allocation (malloc-free) for deterministic performance.
 * - Structure-composable: built for inline embedding, object compostion & memory locality
 *
 * API
 * ---
 * timer_init(tm)   : init timer state
 * timer_deinit(tm) : deinit timer state
 * timer_check(tm) -> next_expiry  : process timers, return expiry_ms
 * timer_add(tm, msec, cb, arg) -> tid : add timer, return tid
 * time_cancel(tm, tid)  : cancel timer
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
    uint64_t now_ms;
    int num_timer;
    int num_fire;
    int free_head;
    struct timer_slot slot[TIMER_MAXSLOT];
    struct timer_slot fire[TIMER_MAXSLOT];
    int heap[TIMER_MAXSLOT];
};

int timer_init(struct timer_mgr *tm);
void timer_deinit(struct timer_mgr *tm);
int timer_check(struct timer_mgr *tm);

int timer_add(struct timer_mgr *tm, uint64_t ms, void (*cb)(void *arg), void *arg);
void timer_cancel(struct timer_mgr *tm, int tid);


#endif
