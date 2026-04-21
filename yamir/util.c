#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>

#include <sys/time.h>
#include <sys/types.h>

#include "util.h"

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

void timer_del(struct timer *t)
{
    timerheap_remove(heap, t);
    free(t);
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

#define hashsize(n) ((uint32_t)1<<(n))
#define hashmask(n) (hashsize(n)-1)


// jenkins hash
static uint32_t make_hash(uint32_t a, int size)
{
    a = (a+0x7ed55d16) + (a<<12);
    a = (a^0xc761c23c) ^ (a>>19);
    a = (a+0x165667b1) + (a<<5);
    a = (a+0xd3a2646c) ^ (a<<9);
    a = (a+0xfd7046c5) + (a<<3);
    a = (a^0xb55a4f09) ^ (a>>16);

    return a & hashmask(size);
}

static struct inthash_entry *find_entry(struct inthash_entry *head, uint32_t key)
{
    struct inthash_entry *entry;

    for (entry=head; entry != NULL; entry=entry->next) {
        if (entry->key == key) {
            return entry;
        }
    }

    return NULL;
}

void *inthash_table_lookup(struct inthash_table *table, uint32_t key)
{
    uint32_t hash;
    struct inthash_entry *entry;

    hash = make_hash(key, table->size);
    entry = find_entry(table->array[hash], key);
    if (entry) {
        return entry->data;
    }
    return NULL;
}

void inthash_table_del(struct inthash_table *table, uint32_t key)
{
    uint32_t hash;
    struct inthash_entry *entry, *prev;

    // need to find elem and its previous entry
    hash = make_hash(key, table->size);
    entry = table->array[hash];
    prev = NULL;
    while (entry && entry->key != key) {
        prev = entry;
        entry = entry->next;
    } 

    if (entry) {
        if (prev) {
            prev->next = entry->next;
        }
        else {
            table->array[hash] = entry->next;
        }
        entry->next = NULL;
        free(entry);
    }
}

void inthash_table_add(struct inthash_table *table, uint32_t key, void *data)
{
    uint32_t hash;
    struct inthash_entry *entry;

    hash = make_hash(key, table->size);

    entry = find_entry(table->array[hash], key);
    if (entry != NULL) {
        fprintf(stderr, "inthash_table_add(%d) key already exists!\n", key);
        abort();
    }

    entry = malloc(sizeof(*entry));
    entry->key = key;
    entry->data = data;
    entry->next = table->array[hash];
    table->array[hash] = entry;
}

void inthash_table_free(struct inthash_table *table)
{
    // TODO
}

struct inthash_table *inthash_table_create(int size)
{
    struct inthash_table *table;

    table = malloc(sizeof(*table));
    table->size = size;
    table->array = calloc(size, sizeof(struct inthash_entry *));
    if (table->array == NULL) {
        fprintf(stderr,"calloc(%d) failed\n", size);
        abort();
    }

    return table;
}

void util_init()
{
    heap = timerheap_new();
}

void util_deinit(void)
{
    if (heap) timerheap_free(heap);

}
