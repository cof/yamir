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

enum test_cmd {
    TEST_UNSUPP = 0,
    TEST_MSG_START,
    TEST_PKT_START,
    TEST_PKT_END,
    TEST_ENC_START,
    TEST_ENC_END
};

static enum test_cmd str_tocmd(const char *str)
{
    if (!strcasecmp(str, "MSG"))       return TEST_MSG_START;
    if (!strcasecmp(str, "PKT_START")) return TEST_PKT_START;
    if (!strcasecmp(str, "PKT_END"))   return TEST_PKT_END;
    if (!strcasecmp(str, "ENC_START")) return TEST_ENC_START;
    if (!strcasecmp(str, "ENC_END"))   return TEST_ENC_END;

    return TEST_UNSUPP;
}

#define ERR_OK    0
#define ERR_HEX  -1
#define ERR_MODE -2
#define ERR_PKT  -3
#define ERR_MSG  -4
#define ERR_ENC  -5

enum enc_field {
    ENC_NONE = 0,
    ENC_PKVER,
    ENC_PKTFLAGS,
    ENC_PKTSEQNUM,
    ENC_MSGTYPE,
    ENC_MSGFLAGS,
    ENC_MSGADDRLEN,
    ENC_MSGHLIMIT,
    ENC_MSGHCOUNT,
    ENC_MSGSEQNUM,
    ENC_MSGOADDR,
    ENC_MSGTADDR,
    ENC_MSGADDR
};

static enum enc_field str_tofield(const char *str)
{
    if (!strcasecmp(str, "pkt_ver"))      return ENC_PKVER;
    if (!strcasecmp(str, "pkt_flags"))    return ENC_PKTFLAGS;
    if (!strcasecmp(str, "pkt_seqnum"))   return ENC_PKTSEQNUM;
    if (!strcasecmp(str, "msg_type"))     return ENC_MSGTYPE;
    if (!strcasecmp(str, "msg_flags"))    return ENC_MSGFLAGS;
    if (!strcasecmp(str, "msg_addrlen"))  return ENC_MSGADDRLEN;
    if (!strcasecmp(str, "msg_hlimit"))   return ENC_MSGHLIMIT;
    if (!strcasecmp(str, "msg_hcount"))   return ENC_MSGHCOUNT;
    if (!strcasecmp(str, "msg_seqnum"))   return ENC_MSGSEQNUM;
    if (!strcasecmp(str, "msg_oaddr"))    return ENC_MSGOADDR;
    if (!strcasecmp(str, "msg_taddr"))    return ENC_MSGTADDR;
    if (!strcasecmp(str, "msg_addr"))     return ENC_MSGADDR;

    return ENC_NONE;
}

static int enc_str(struct pkt_buf *dst, const char *str)
{
    if (!str) return 0;
    const char *end = str + strlen(str);
    char field[256];

    struct pbb_msg msg;
    pbb_msg_reset(&msg);

    struct pbb_node *mn;
    uint8_t addr_len;

    while (str < end)  {
        // slice splitch
        const char *ptr = memchr(str, ' ', end - str);
        size_t len = ptr ? ptr - str : end - str;
        memcpy(field, str, len);
        field[len] = '\0';
        while (str < end && str[len] == ' ') len++;
        str += len;

        // extract name:value
        char *fn = field;
        char *fv = strchr(fn, ':');
        if (!fv) return log_errno_rf("%s mising :", fn);
        *fv++= '\0';
        if (!strlen(fn)) return log_errno_rf("empty field name");
        if (!strlen(fv)) return log_errno_rf("%s empty value", fn);

        switch(str_tofield(fn)) {
        case ENC_PKVER:
        case ENC_PKTFLAGS:
        case ENC_PKTSEQNUM:
            break;
        case ENC_MSGTYPE:
            msg.type = pbb_str_totype(fv);
            break;
        case ENC_MSGFLAGS:
            msg.flags = atoi(fv);
            break;
        case ENC_MSGADDRLEN:
            msg.addr_len = atoi(fv);
            break;
        case ENC_MSGHLIMIT:
            msg.flags |= PBB_MF_HLIM;
            msg.hop_limit = atoi(fv);
            break;
        case ENC_MSGHCOUNT:
            msg.flags |= PBB_MF_HCNT;
            msg.hop_count = atoi(fv);
            break;
        case ENC_MSGSEQNUM:
            msg.flags |= PBB_MF_SEQN;
            msg.seq_num = atoi(fv);
            break;
        case ENC_MSGOADDR:
            mn = msg.origin;
            if (!mn) {
                // add it now
                msg.origin = pbb_add_node(&msg);
                mn = msg.origin;
                if (!mn) return log_error_rf("No space for %s", fn);
            }
            addr_len = pbb_str_toaddr(fv, mn->addr);
            if (!addr_len) return log_error_rf("%s invalid addr %s", fn, fv);
            if (!msg.addr_len) msg.addr_len = addr_len;
            if (addr_len != msg.addr_len) return log_error_rf("%s %s must be %d", fn, fv, msg.addr_len);
            break;
        case ENC_MSGTADDR:
            mn = msg.target;
            if (!mn) {
                // add it now
                msg.target = pbb_add_node(&msg);
                mn = msg.target;
                if (!mn) return log_error_rf("No space for %s", fn);
            }
            addr_len = pbb_str_toaddr(fv, mn->addr);
            if (!addr_len) return log_error_rf("%s invalid addr %s", fn, fv);
            if (!msg.addr_len) msg.addr_len = addr_len;
            if (addr_len != msg.addr_len) return log_error_rf("%s %s must be %d", fn, fv, msg.addr_len);
            break;
        case ENC_MSGADDR:
            mn = pbb_add_node(&msg);
            if (!mn) return log_error_rf("No space for %s", fn);
            addr_len = pbb_str_toaddr(fv, mn->addr);
            if (!addr_len) return log_error_rf("%s invalid addr %s", fn, fv);
            if (!msg.addr_len) msg.addr_len = addr_len;
            if (addr_len != msg.addr_len) return log_error_rf("%s %s must be %d", fn, fv, msg.addr_len);
            break;
        default:
            return log_errno_rf("%s unknown", fn);
        }
    }

    // encode to dst buffer
    void *mem = pkt_buf_ptr(dst);
    size_t len = pkt_buf_avail(dst);
    ssize_t rc = pbb_msg_enc(&msg, mem, len);
    if (rc < 0) return log_error_rf("ppb encode failed ec=%ld", rc);
    pkt_buf_inc(dst, rc);

    return 0;
}

static int enc_strs(struct pkt_buf *dst, int nstr, char *strs[static nstr])
{
    for (int i = 0; i < nstr; i++) {
        if (enc_str(dst, strs[i])) return -1;
    }

    return 0;
}

static int run_test(enum test_cmd cmd, 
    const char *hex, int nstr, char *strs[static nstr])
{
    char tmp[2048];

    int len = hexstr_tobin(hex, tmp, sizeof(tmp));
    if (len < 0) return ERR_HEX;

    struct pkt_buf buf;
    struct pbb_hdr hdr;
    struct pbb_msg msg;
    int rc;

    switch(cmd) {
    case TEST_MSG_START:
        pkt_buf_init(&buf, tmp, len);
        rc = pkt_buf_msg_dec(&buf, &msg);
        if (rc) rc = ERR_MSG;
        //log_debug("%.*s", pbb_msg_tostr(&msg, tmp, sizeof(tmp)), tmp);
        break;
    case TEST_PKT_END:
        pkt_buf_init(&buf, tmp, len);
        rc = pkt_buf_hdr_dec(&buf, &hdr);
        if (rc) return ERR_PKT;
        while (pkt_buf_avail(&buf)) {
            rc = pkt_buf_msg_dec(&buf, &msg);
            if (rc) return ERR_MSG;
        }
        break;
    case TEST_ENC_END:
        pkt_buf_init(&buf, tmp, sizeof(tmp));
        rc = enc_strs(&buf, nstr, strs);
        if (rc) return ERR_ENC;
        // TODO compare ehx
        break;

    default:
        rc = ERR_MODE;
    }

    return rc;
}

static int test_file(const char *file)
{
    char buf[2048];
    char desc[256];
    char hex[2048];
    char store[2048];
    int lineno = 0;
    int testno = 0;
    int num_fail = 0;
    int state = 0;
    enum test_cmd cmd = 0, cmd1;
    char *ptr;
    char *strs[10];
    int num_str = 0;
    int num_store = 0;
    char *args;

    FILE *f = fopen(file, "r");
    if (f == NULL) return -1;

    while (fgets(buf, sizeof(buf), f)) {
        lineno++;
        char *line = trim(buf);
        // skip blank lines
        if (strlen(line) == 0) continue;

        int rc = 0;
        switch(state) {
        case 0: // test start
            if (*line != '#') {
                rc = log_error_rf("line %d expect #", lineno);
                break;
            }
            line = trim(line+1);
            // new-test
            testno++;
            strcpy(desc, line);
            hex[0] = '\0';
            num_str = 0;
            num_store = 0;
            state = 1;
            break;
        case 1: // test desc
            args = strchr(line, ' ');
            if (args) *args++ = '\0';
            args = trim(args);
            cmd = str_tocmd(line);
            if (!cmd) {
                rc = log_error_rf("line %d unsupp %s", lineno, line);
                break;
            }
            if (args) strcpy(hex, args);
            if (cmd == TEST_PKT_START)  state = 2;
            else if (cmd == TEST_ENC_START) state = 3;
            else state = 4;
            break;
        case 2: // PKT
            cmd1 = str_tocmd(line);
            if (cmd1) {
                if (cmd1 != TEST_PKT_END) {
                    rc = log_error_rf("line %d unsupp %s", lineno, line);
                    break;
                }
                // PKT done
                cmd = cmd1;
                state = 4;
                break;
            }
            // remove comment
            ptr = strchr(line, '#');
            if (ptr) *ptr = '\0';
            // accumlate hex
            strcat(hex, line);
            break;
        case 3: // ENC
            cmd1 = str_tocmd(line);
            if (cmd1) {
                if (cmd1 != TEST_ENC_END) {
                    rc = log_error_rf("line %d unsupp %s", lineno, line);
                    break;
                }
                // ENC done
                cmd = cmd1;
                state = 4;
                break;
            } 
            // remove comment
            ptr = strchr(line, '#');
            if (ptr) *ptr = '\0';
            args = strchr(line, ':');
            if (args) *args++ = '\0';
            if (!args) {
                rc = log_error_rf("line %d unsupp %s", lineno, line);
                break;
            }
            args = trim(args);
            // str or hex
            if (!strcasecmp(line, "str")) {
                // add str to store
                size_t len = strlen(args);
                if (len + num_store > sizeof(store)) {
                    rc = log_error_rf("line %d no-room %s", lineno, line);
                    break;
                }
                char *str = store + num_store;
                memcpy(str, args, len);
                strs[num_str++] = str;
                num_store += len;
            }
            else if (!strcasecmp(line, "hex")) {
                // accumlate hex
                strcat(hex, args);
            }
            else {
                rc = log_error_rf("line %d unsupp %s", lineno, line);
            }
            break;
        }

        if (rc) break;
        if (state != 4) continue;

        rc = run_test(cmd, hex, num_str, strs);
        fprintf(stderr, "test %d werr=%d desc=%s\n", testno, rc, desc);
        if (rc) num_fail++;

        // next test 
        state = 0;
    }
    fclose(f);

    if (state != 0) {
        log_error_rf("line %d unsupp %s", lineno, buf);
    }

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
