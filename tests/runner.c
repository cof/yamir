/*
 * test runner
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"
#include "pbb.h"

struct test_state {
    int tot_fail;
    int log_msg;
    int num_file;
    char **files;
};

static inline const char *get_base(const char *path)
{
    if (!path) return NULL;
    const char *base = strrchr(path, '/');
    return base ? base + 1 : path;
}

static size_t safe_strlen(const char *str)
{
    return str ? strlen(str) : 0;
}

static inline bool is_white(int ch)
{
    return ch == ' ' || ch == '\t' || ch == '\v' || ch == '\r' || ch == '\n';
}

static char *rtrim(char *str) 
{
    if (!str) return str;
    size_t len = strlen(str);

    while (len && is_white(str[len - 1])) {
        len--;
    }
    
    str[len] = '\0';
    return str;
}

static char *ltrim(char *str)
{
    if (!str) return str;

    while (is_white(*str)) {
        str++;
    }

    return str;
}

static char *trim(char *str)
{
    return ltrim(rtrim(str));
}

static int hexstr_tobin(const char *hex, void *buf, size_t len)
{
    uint8_t *ptr = buf;
    uint8_t *end = ptr + len;

    uint8_t byte = 0;
    bool nibble = false;

    while (*hex && ptr < end) {
        char ch = *hex++;
        int val = 0;
        switch(ch) {
        case '0' ... '9': val = ch - '0'; break;
        case 'a' ... 'f': val = ch - 'a' + 10; break;
        case 'A' ... 'F': val = ch - 'A' + 10; break;
        case '-': case ':':
        case ' ': case '\t': case '\v':
            // Ignore dash, colon or white space
           continue;
        default:
            // invalid ch
            return -1;
        }
        // convert nibble to byte
        if (!nibble) {
            byte = val << 4;
            nibble = true;
        } 
        else {
            *ptr++ = byte | val;
            nibble = false;
        }
    }

    if (nibble) return -1;

    return ptr - (uint8_t *) buf;
}

#define ERR_OK    0
#define ERR_HEX  -1
#define ERR_MODE -2
#define ERR_PKT  -3
#define ERR_MSG  -4

static int run_test(const char *mode, const char *hex)
{
    char tmp[2048];

    if (!safe_strlen(mode)) return ERR_MODE;
    if (!safe_strlen(hex))  return ERR_HEX;

    int len = hexstr_tobin(hex, tmp, sizeof(tmp));
    if (len < 0) return ERR_HEX;

    struct pkt_buf buf = PKT_BUF_INIT(tmp, len);
    struct pbb_hdr hdr;
    struct pbb_msg msg;

    if (!strcasecmp(mode, "MSG")) {
        int rc = pkt_buf_decode_msg(&buf, &msg);
        if (rc) return ERR_MSG;
        //log_debug("%.*s", pbb_msg_tostr(&msg, tmp, sizeof(tmp)), tmp);
        return 0;
    }

    if (!strcasecmp(mode, "PKT")) {
        int rc = pkt_buf_decode_hdr(&buf, &hdr);
        if (rc) return ERR_PKT;
        while (pkt_buf_avail(&buf)) {
            rc = pkt_buf_decode_msg(&buf, &msg);
            if (rc) return ERR_MSG;
        }
        return 0;
    }

    return ERR_MODE;
}


static int test_file(const char *file)
{
    char buf[2048];
    int lineno = 0;
    int testno = 0;
    int num_fail = 0;

    FILE *f = fopen(file, "r");
    if (f == NULL) return -1;

    while (fgets(buf, sizeof(buf), f)) {
        char *line = buf;
        lineno++;
        // strip comment
        char *ptr = strchr(line, '#');
        if (ptr) *ptr = '\0';
        line = trim(line);
        if (safe_strlen(line) == 0) continue;
        testno++;
        char *desc = strchr(line, '|');
        if (desc) *desc++ = '\0';
        char *mode = line;
        char *hex = strchr(mode, ' ');
        if (hex) *hex++ = '\0';
        mode = trim(mode);
        hex =  trim(hex);
        desc = trim(desc);
        int rc = run_test(mode, hex);
        fprintf(stderr, "test %d werr=%d desc=%s\n", testno, rc, desc ?: "");
        if (rc) num_fail++;
    }
    fclose(f);

    return num_fail;
}

static void usage(char *prog)
{
    const char *name = get_base(prog) ?: "<null>";
    printf("Usage: %s [-l log_level] [file1, file2, ...]\n", name);
}

static int parse_argv(struct test_state *ts, int argc, char *argv[])
{
    int opt;

    while ((opt = getopt(argc, argv, "l:h")) != -1) {
        switch(opt) {
        case 'l': log_level = atoi(optarg); break;
        case 'h': usage(argv[0]); exit(0); break;
        default: return log_error_rf("Unknown option %c\n", opt);
        }
    }

    // test-file list
    if (optind < argc) {
        ts->num_file = argc - optind;
        ts->files = &argv[optind];
    }

    return 0;
}

int main(int argc, char *argv[])
{
    struct test_state ts = { 0 };

    log_init(NULL, LOG_INFO);
    parse_argv(&ts, argc, argv);

    for (int i = 0; i < ts.num_file; i++) {
        int nf = test_file(ts.files[i]);
        if (nf) ts.tot_fail++;
    }

    return ts.tot_fail;
}
