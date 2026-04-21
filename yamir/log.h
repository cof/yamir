/*
 * LOG - the logger API
 * --------------------
 * A logger API that can report informaton and detailed error msesages.
 *
 * Just call log_init() to set the log-level and use macros to log messages.
 *
 * Examples:
 *
 *  log_init(NULL, LOG_INFO);
 *  LOG_INFO("+", "server %s is up", server->name);
 *  log_debug("Running cmd %d", state->id);
 *
 * Overview
 * --------
 * Basic idea is you use logger to report information to users, log what a 
 * process is doing and report useful error messages if something fails.
 * 
 * There are 4 basic log types:
 *
 *  FATAL - "[FATAL] file:line (func): fmt-str
 *  ERROR - "[ERROR] file:line (func): fmt-str"
 *  INFO  - "[who] fmt-str" 
 *  DEBUG - "[DEBUG] file:line func: fmt-str
 *
 * Logger use printf fmt-str to allow complete control of whats logged.
 *
 * e.g
 *  log_info("+", "The service is up");
 *  log_info("INFO", "did %s","something");
 *
 * Logger has macros that report the FILE, LINE and FUNC where an error has 
 * occured allowing users to easily trace problems in the code base.
 *
 * Logger also has a range of macros that can be used to both log a message
 * and return from a function all in one line.
 *
 * These macros using the following suffix patterns:
 *
 *  _rf - return fail (-1)
 *  _rc - return code
 *  _rn - return null
 *  _rz - return zero
 *
 * This macros provide for a clear and simple form of exception handling where
 * code can both log a error and return back to the caller all on one line.
 *
 * e.g.
 *
 *  return log_error_rf("My func failed");
 *  return log_error_rc(-2, "foo1 failed)
 *  return log_errno_rf("foo2 failed");
 *  return log_errno_rc(-4, "foo2 failed");
 *
 * For a full list see macros section below.
 *
 * API sections
 * ------------
 * functions : direct functions
 * macros    : various msg-str and fmt-str macros
 */
#ifndef _LOG_H_
#define _LOG_H_

#include <errno.h>

extern int log_level;

/*
 * functions : direct functions
 * -----------------------------
 * log_init(dst, level) : setup up logger
 * _log_msg(file, line, func, what, ec, what, whatstr, fmt, ...) : log msg - "[what] file:line (func): fmt-str":
 * log_argv(what, argc, argv) : log_info cmd-line - useful for debuing pod exec issues
 */
void log_init(FILE *dst, int level);
void _log_msg(const char *file, int line, const char *func, 
    int ec, int what, const char *what_str, const char *fmt, ...)
    __attribute__((format(printf, 7, 8)));
void log_argv(const char *what, int argc, char *argv[]);

// logger levels
#define LOG_NONE  0
#define LOG_FATAL 1
#define LOG_ERROR 2
#define LOG_INFO  3
#define LOG_DEBUG 4

/*
 * macros : various msg-str and fmt-str macros
 * -------------------------------------------
 * log_msg_rf(msg)          : log msg/return fail
 * log_info(who, ...)       : log_info
 * log_info_rc(what,rc,...) : log_info/return code
 * -
 * log_error(...)           : log_error msg - direct wrapper to _log_msg.
 * log_error_rf(...)        : log_error msg - return fail
 * log_error_rc(rc, ...)    : log_error msg - return code
 * log_error_rz(..,)        : log_error msg - return zero
 * log_error_rn(..,)        : log_error msg - return NUL
 * -
 * log_errno(...)           : log error msg + errno
 * log_errno_rf(...)        : log error msg + errno - return fail
 * log_errno_rc(...)        : log error msg + errno - return code
 * log_errno_rn(...)        : log error msg + errno - return null
 * -
 * log_ec(ec, ...)          : log error msg with ec as errno
 * log_ec_rf(ec, ..,)       : log error msg with ec as errno - return fail
 * log_debug(fmt, ...)      : simple wrapper around fprintf(stderr, fmt, ...)
 * fatal_error(...)         : log fatal error msg and exit
 * fatal_errno(...)         : log fatal error msg and errno and exit
 */


#define log_msg(...) \
    _log_msg(NULL, 0, NULL, 0, LOG_NONE, 0, __VA_ARGS__)

#define log_msg_rf(...) ({ \
    _log_msg(NULL, 0, NULL, 0, LOG_NONE, 0, __VA_ARGS__) \
    -1; \
})

#define log_info(who, ...) \
    if (log_level >= LOG_INFO) _log_msg(NULL, 0, NULL, 0, LOG_INFO, who, __VA_ARGS__)

#define log_info_rc(who, rc, ...) ({ \
    if (log_level >= LOG_INFO) _log_msg(NULL, 0, NULL, 0, LOG_INFO, who, __VA_ARGS__); \
    (rc); \
})

#define log_cmd_err(cmd, opt, ...) ({ \
    _log_msg(cmd, 0, opt, 0, LOG_NONE, "ERROR", __VA_ARGS__); \
    -1; \
})

#define log_debug(...) \
    if (log_level >= LOG_DEBUG) { \
        _log_msg(__FILE__, __LINE__, __func__, 0, LOG_DEBUG, NULL, __VA_ARGS__); \
    }

#define log_error(...) \
    if (log_level >= LOG_ERROR) { \
        _log_msg(__FILE__, __LINE__, __func__, 0, LOG_ERROR, NULL, __VA_ARGS__); \
    }

#define log_error_rf(...) ({ \
    if (log_level >= LOG_ERROR) { \
        _log_msg(__FILE__, __LINE__, __func__, 0, LOG_ERROR, NULL, __VA_ARGS__); \
    }\
    -1; \
})

#define log_error_rc(rc, ...) ({ \
    if (log_level >= LOG_ERROR) { \
        _log_msg(__FILE__, __LINE__, __func__, 0, LOG_ERROR, NULL, __VA_ARGS__); \
    } \
    (rc); \
})

#define log_error_rz(...) ({ \
    if (log_level >= LOG_ERROR) { \
        _log_msg(__FILE__, __LINE__, __func__, 0, LOG_ERROR, NULL, __VA_ARGS__); \
    } \
    0; \
})

#define log_error_rn(...) ({ \
    if (log_level >= LOG_ERROR) { \
        _log_msg(__FILE__, __LINE__, __func__, 0, LOG_ERROR, NULL, __VA_ARGS__); \
    } \
    (void *) NULL; \
})

#define log_error_rv(...) ({ \
    if (log_level >= LOG_ERROR) { \
        _log_msg(__FILE__, __LINE__, __func__, 0, LOG_ERROR, NULL, __VA_ARGS__); \
    } \
})

#define log_errno(...) \
    if (log_level >= LOG_ERROR) { \
        _log_msg(__FILE__, __LINE__, __func__, errno, LOG_ERROR, NULL, __VA_ARGS__); \
    }

#define log_ec(ec, ...) \
    if (log_level >= LOG_ERROR) { \
        _log_msg(__FILE__, __LINE__, __func__, ec, LOG_ERROR, NULL, __VA_ARGS__); \
    }

#define log_errno_rf(...) ({ \
    if (log_level >= LOG_ERROR) { \
        _log_msg(__FILE__, __LINE__, __func__, errno, LOG_ERROR, NULL, __VA_ARGS__); \
    } \
    -1; \
})

#define log_errno_rc(rc, ...) ({ \
    if (log_level >= LOG_ERROR) { \
        _log_msg(__FILE__, __LINE__, __func__, errno, LOG_ERROR, NULL, __VA_ARGS__); \
    } \
    (ec); \
})

#define log_errno_rn(...) ({ \
    if (log_level >= LOG_ERROR) { \
        _log_msg(__FILE__, __LINE__, __func__, errno, LOG_ERROR, NULL, __VA_ARGS__); \
    } \
    (void *) NULL; \
})

#define log_ec_rf(ec, ...) ({ \
    if (log_level >= LOG_ERROR) { \
        _log_msg(__FILE__, __LINE__, __func__, ec, LOG_ERROR, NULL, __VA_ARGS__); \
    } \
    -1; \
})

#define fatal_error(...) \
    _log_msg(__FILE__, __LINE__, __func__, 0, LOG_FATAL, NULL, __VA_ARGS__)
#define fatal_errno(...) \
    _log_msg(__FILE__, __LINE__, __func__, errno, LOG_FATAL, NULL, __VA_ARGS__)

#endif
