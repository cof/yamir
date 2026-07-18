/* SPDX-License-Identifier: MIT | (c) 2026 [cof] */

/*
 * timer
 * -----
 * A simple min-heap based timer API
 *
 * Design
 * ------
 * - malloc-free - No dynamic memory allocation for timer state
 * - Intrusive-design: structures allow for inline embedding and object composition
 * - Monotonic Precision: uses CLOCK_MONOTONIC for ms-accurate clock-shift proof time-keeping
 * - timers are stored in in fixed size array of slots
 * - slot indexes are store inside heap instead of pointers
 * - timer_add has max delay of 49 days and returns the slot index of timer slot
 * - timer_check: calcs next deadline for poll/select driven I/O timeouts.
 *
 * API
 * ---
 * timer_init(tm)   : init timer state
 * timer_deinit(tm) : deinit timer state
 * timer_check(tm) : process timers, return next_expiry 
 * timer_add(tm, delay_ms, cb, arg) : add timer, return tid (slot index)
 * timer_cancel(tm, tid)  : cancel timer
 */
#ifndef _TIMER_H_
#define _TIMER_H_

#define TIMER_MAXSLOT 128

struct timer_slot {
    uint64_t expiry; // milliseconds
    uint32_t hpos;   // heap position (or free slot index)
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
    int heap[TIMER_MAXSLOT]; // stores slot indexes
};

int timer_init(struct timer_mgr *tm);
void timer_deinit(struct timer_mgr *tm);
int timer_check(struct timer_mgr *tm);

int timer_add(struct timer_mgr *tm, uint32_t delay_ms, void (*cb)(void *arg), void *arg);
void timer_cancel(struct timer_mgr *tm, int tid);


#endif
