#ifndef _UTIL_H_
#define _UTIL_H_

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

/* macros */
#define mkptr(ptr, offset)  ((void *)  ( ((char *) ptr) + offset))
#define containerof(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))

#ifndef ARR_LEN
#define ARR_LEN(a) (sizeof (a) / sizeof ((a)[0])) 
#endif 

#define MAX(a,b) (a) > (b) ? (a) : (b)
#define UTIL_FAIL -1


/* logger api */
#define LOG_NONE  0
#define LOG_FATAL 1
#define LOG_ERROR 2
#define LOG_INFO  3
#define LOG_DEBUG 4

extern int log_level;

void _log_msg(const char *file, int line, const char *func, 
    int ec, int what, const char *what_str, const char *fmt, ...)
    __attribute__((format(printf, 7, 8)));

#define log_info(who, ...) \
    if (log_level >= LOG_INFO) _log_msg(NULL, 0, NULL, 0, LOG_INFO, who, __VA_ARGS__)

#define log_error_rf(...) ({ \
    if (log_level >= LOG_ERROR) { \
        _log_msg(__FILE__, __LINE__, __func__, 0, LOG_ERROR, NULL, __VA_ARGS__); \
    }\
    UTIL_FAIL; \
})

#define log_errno_rf(...) ({ \
    if (log_level >= LOG_ERROR) { \
        _log_msg(__FILE__, __LINE__, __func__, errno, LOG_ERROR, NULL, __VA_ARGS__); \
    } \
    UTIL_FAIL; \
})

#define log_debug(...) \
    if (log_level >= LOG_DEBUG) { \
        _log_msg(__FILE__, __LINE__, __func__, 0, LOG_DEBUG, NULL, __VA_ARGS__); \
    }

static inline const char *get_basename(const char *path)
{
    if (!path) return NULL;
    const char *base = strrchr(path, '/');
    return base ? base + 1 : path;
}

/* timer api */
struct timer {
    void (*cb_fn) (void *cb_arg);
    void *cb_arg;
    int idx;
    struct timeval when;
};

struct timerheap {
    struct timer **data;
    int size;
    int used;
};

void timer_del(struct timer *t);
struct timer *timer_add(void (*cb_fn)(void *cb_arg), 
    void *cb_arg, struct timeval *timeout);
struct timer *timer_add_wsec(void (*cb_fn)(void *cb_arg), 
    void *cb_arg, time_t sec);
void timer_process(int *wait_msec);

/* hashmap api */
struct inthash_entry {
    struct inthash_entry *next;
    uint32_t key;
    void *data;
};

struct inthash_table {
    int size;
    struct inthash_entry **array;
};

extern void *inthash_table_lookup(struct inthash_table *table, uint32_t key);
extern void inthash_table_del(struct inthash_table *table, uint32_t key);
extern void inthash_table_add(struct inthash_table *table, uint32_t key, void *data);
extern void inthash_table_free(struct inthash_table *table);
extern struct inthash_table *inthash_table_create(int size);


void util_init(void);
void util_deinit(void);

#endif
