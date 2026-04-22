/*
 *
 */
#ifndef _TIMER_H_
#define _TIMER_H_

struct timer {
    void (*cb_fn) (void *cb_arg);
    void *cb_arg;
    int idx;
    struct timeval when;
};

int timer_init(void);
void timer_deinit(void);
void timer_process(int *wait_msec);

struct timer *timer_add(void (*cb_fn)(void *cb_arg), void *cb_arg, struct timeval *timeout);
struct timer *timer_add_wsec(void (*cb_fn)(void *cb_arg), void *cb_arg, time_t sec);
void timer_del(struct timer *t);

#endif
