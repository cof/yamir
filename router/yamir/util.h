/* SPDX-License-Identifier: MIT | (c) 2026 [cof] */

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

static inline const char *get_basename(const char *path)
{
    if (!path) return NULL;
    const char *base = strrchr(path, '/');
    return base ? base + 1 : path;
}

#endif
