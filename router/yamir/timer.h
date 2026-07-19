/* SPDX-License-Identifier: MIT | (c) 2026 [cof] */

/*
 * timer
 * -----
 * A simple timer API based on the based on the Barkley and Lee usenix 88 paper
 * "A Heap-Based Callout Implementation to Meet Real-Time Needs."
 *
 * Design
 * ------
 * - Memory allocation: No dynamic memory allocation
 * - Cache-locality: Uses small fixed size arrays 
 * - Intrusive structure:  Timer manager state can be embedded directly in application state.
 * - Timekeeping: uses CLOCK_MONOTONIC for millisecond-accurate timing.
 * - Storage Model: Timers are kept in in a fixed size array of slots.
 * - Heap Structure: A binary min-heap stores slot indices rather than pointers.
 * - Constraints: Maximum timeout is capped at 49 days (uint32_t millisecond wrap).
 * - I/O Integration: Expiry calculations optimized for poll-driven event loops.
 *
 * API
 * ---
 * timer_init(tm)   : Initialize timer state
 * timer_deinit(tm) : Reset timer state
 * timer_check(tm)  : process expired timers, return next expiry 
 * timer_add(tm, delay_ms, cb, arg) : add a timer; return timer ID (slot index)
 * timer_cancel(tm, tid) : cancel a timer
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
    uint64_t now_ms;  // current montonic time
    int num_timer;    // number of active timers
    int num_fire;     // number of expired timers queued for callback
    int free_head;    // head of free slot LIFO stack (-1 if full)
    struct timer_slot slot[TIMER_MAXSLOT]; // timer storage pool
    struct timer_slot fire[TIMER_MAXSLOT]; // expire timers pending callback
    int heap[TIMER_MAXSLOT];  // min-heap of timer slot indices
};

int timer_init(struct timer_mgr *tm);
void timer_deinit(struct timer_mgr *tm);
int timer_check(struct timer_mgr *tm);

int timer_add(struct timer_mgr *tm, uint32_t delay_ms, void (*cb)(void *arg), void *arg);
void timer_cancel(struct timer_mgr *tm, int tid);


#endif
