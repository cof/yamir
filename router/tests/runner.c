/*
 * PacketBB tester
 *
 * Usage:
 * -----
 *  test_runner FILE...
 *
 * Example:
 * --------
 * $ test_runner tests/dymo.txt
 *
 * Notes
 * =====
 * Use xxd to safely print a hexstr
 * xxd -p -c 16 a.bin | sed 's/\(....\)/\1 /g'
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"
#include "pbb.h"

#ifndef ARR_LEN
#define ARR_LEN(a) (sizeof (a) / sizeof ((a)[0]))
#endif

struct test_state {
    int total_fail;
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
    ENC_VER,
    ENC_FLAGS,
    ENC_SEQNUM,
    ENC_TYPE,
    ENC_ADDRLEN,
    ENC_HLIMIT,
    ENC_HCOUNT,
    ENC_DID,
    ENC_DIST,
    ENC_VLDTIME,
    ENC_PREFIX,
    ENC_OADDR,
    ENC_TADDR,
    ENC_ADDR
};

static enum enc_field str_tofield(const char *str)
{
    if (!strcasecmp(str, "ver"))      return ENC_VER;
    if (!strcasecmp(str, "flags"))    return ENC_FLAGS;
    if (!strcasecmp(str, "seqnum"))   return ENC_SEQNUM;
    if (!strcasecmp(str, "type"))     return ENC_TYPE;
    if (!strcasecmp(str, "flags"))    return ENC_FLAGS;
    if (!strcasecmp(str, "addrlen"))  return ENC_ADDRLEN;
    if (!strcasecmp(str, "hlimit"))   return ENC_HLIMIT;
    if (!strcasecmp(str, "hcount"))   return ENC_HCOUNT;
    if (!strcasecmp(str, "did"))      return ENC_DID;
    if (!strcasecmp(str, "dist"))     return ENC_DIST;
    if (!strcasecmp(str, "vldtime"))  return ENC_VLDTIME;
    if (!strcasecmp(str, "prefix"))   return ENC_PREFIX;
    if (!strcasecmp(str, "oaddr"))    return ENC_OADDR;
    if (!strcasecmp(str, "taddr"))    return ENC_TADDR;
    if (!strcasecmp(str, "addr"))     return ENC_ADDR;

    return ENC_NONE;
}

static int enc_pkt(struct pkt_buf *dst, const char *str)
{
    if (!str) return 0;
    const char *end = str + strlen(str);
    char field[256];

    struct pbb_hdr hdr;
    pbb_hdr_reset(&hdr);

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
        case ENC_VER:
            hdr.version = atoi(fv);
            break;
        case ENC_FLAGS:
            hdr.flags = atoi(fv);
            break;
        case ENC_SEQNUM:
            hdr.seq_num = atoi(fv);
            hdr.flags |= PBB_HF_SEQN;
            break;
        default:
            return log_errno_rf("%s unknown", fn);
        }
    }

    return pkt_buf_hdr_enc(dst, &hdr);
}

static int enc_node(struct pbb_msg *msg, struct pbb_node *mn, char *fn, char *fv)
{
    char *attrs = strchr(fv, ',');
    if (attrs) *attrs++ = '\0';

    uint8_t addr_len = pbb_str_toaddr(fv, mn->addr);
    if (!addr_len) return log_error_rf("%s invalid addr %s", fn, fv);

    if (!msg->addr_len) msg->addr_len = addr_len;
    if (addr_len != msg->addr_len) return log_error_rf("%s %s must be %d", fn, fv, msg->addr_len);

    // dist,vldtim,seqnum,prefix [name=value,]
    while (attrs) {

        char *an = attrs;
        attrs = strchr(attrs, ',');
        if (attrs) *attrs++ = '\0';
        char *av = strchr(an, '=');
        if (av) *av++ = '\0';

        switch(str_tofield(an)) {
        case ENC_FLAGS:
            mn->flags |= strtoul(av, NULL, 0);
            break;
        case ENC_DIST:
            mn->flags |= PBB_NF_DIST;
            mn->dist= strtoul(av, NULL, 10);
            break;
        case ENC_VLDTIME:
            mn->flags |= PBB_NF_VTIM;
            mn->vldtime = strtoul(av, NULL, 10);
            break;
        case ENC_SEQNUM:
            mn->flags |= PBB_NF_SEQN;
            mn->seqnum = atoi(av);
            break;
        case ENC_PREFIX:
            mn->flags |= PBB_NF_PREF;
            mn->prefix = atoi(av);
            break;
        default:
            return log_errno_rf("%s unknown", an);
        }
    }

    return 0;
}

static int enc_msg(struct pkt_buf *dst, const char *str)
{
    if (!str) return 0;
    const char *end = str + strlen(str);
    char field[256];

    struct pbb_msg msg;
    pbb_msg_reset(&msg);

    struct pbb_node *mn;

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
        case ENC_TYPE:
            msg.type = pbb_str_totype(fv);
            break;
        case ENC_FLAGS:
            msg.flags = atoi(fv);
            break;
        case ENC_ADDRLEN:
            msg.addr_len = atoi(fv);
            break;
        case ENC_HLIMIT:
            msg.flags |= PBB_MF_HLIM;
            msg.hop_limit = atoi(fv);
            break;
        case ENC_HCOUNT:
            msg.flags |= PBB_MF_HCNT;
            msg.hop_count = atoi(fv);
            break;
        case ENC_SEQNUM:
            msg.flags |= PBB_MF_SEQN;
            msg.seq_num = atoi(fv);
            break;
        case ENC_DID:
            msg.did = atoi(fv);
            break;
        case ENC_OADDR:
            mn = msg.origin;
            if (!mn) {
                // add it now
                msg.origin = pbb_add_node(&msg);
                mn = msg.origin;
                if (!mn) return log_error_rf("No space for %s", fn);
            }
            if (enc_node(&msg, mn, fn, fv)) return -1;
            break;
        case ENC_TADDR:
            mn = msg.target;
            if (!mn) {
                // add it now
                msg.target = pbb_add_node(&msg);
                mn = msg.target;
                if (!mn) return log_error_rf("No space for %s", fn);
            }
            if (enc_node(&msg, mn, fn, fv)) return -1;
            break;
        case ENC_ADDR:
            mn = pbb_add_node(&msg);
            if (!mn) return log_error_rf("No space for %s", fn);
            if (enc_node(&msg, mn, fn, fv)) return -1;
            break;
        default:
            return log_errno_rf("%s unknown", fn);
        }
    }

    // encode to dst buffer
    return pkt_buf_msg_enc(dst, &msg);
}

static int enc_msgs(struct pkt_buf *dst, int nmsg, char *msgs[static nmsg])
{
    for (int i = 0; i < nmsg; i++) {
        if (enc_msg(dst, msgs[i])) return -1;
    }

    return 0;
}

static int cmp_buf(void *buf1, size_t len1, void *buf2, size_t len2)
{
    if (len1 != len2) return -1;
    return memcmp(buf1, buf2, len1);
}

static int run_test(enum test_cmd cmd,
    const char *hex, const char *pkt,
    int nstr, char *strs[static nstr])
{
    char hexbuf[2048];
    char msgbuf[2028];

    int hex_len = hexstr_tobin(hex, hexbuf, sizeof(hexbuf));
    if (hex_len < 0) return ERR_HEX;

    struct pkt_buf buf;
    struct pbb_hdr hdr;
    struct pbb_msg msg;
    int rc;

    switch(cmd) {
    case TEST_MSG_START:
        pkt_buf_init(&buf, hexbuf, hex_len);
        rc = pkt_buf_msg_dec(&buf, &msg);
        if (rc) rc = ERR_MSG;
        //log_debug("%.*s", pbb_msg_tostr(&msg, tmp, sizeof(tmp)), tmp);
        break;
    case TEST_PKT_END:
        pkt_buf_init(&buf, hexbuf, hex_len);
        rc = pkt_buf_hdr_dec(&buf, &hdr);
        if (rc) return ERR_PKT;
        while (pkt_buf_rem(&buf)) {
            rc = pkt_buf_msg_dec(&buf, &msg);
            if (rc) return ERR_MSG;
        }
        break;
    case TEST_ENC_END:
        pkt_buf_init(&buf, msgbuf, sizeof(msgbuf));
        if (pkt) {
            rc = enc_pkt(&buf, pkt);
            if (rc) return ERR_ENC;
        }
        rc = enc_msgs(&buf, nstr, strs);
        if (rc) return ERR_ENC;
        if (hex_len) {
            rc = cmp_buf(msgbuf, pkt_buf_pos(&buf), hexbuf, hex_len);
            if (rc) return ERR_ENC;
        }
        break;

    default:
        rc = ERR_MODE;
    }

    return rc;
}

static char *store_str(struct pkt_buf *buf, const char *str)
{
    size_t len = strlen(str);
    char *nstr = pkt_buf_mkspace(buf, len  + 1);

    if (nstr) {
        memcpy(nstr, str, len);
        nstr[len] = '\0';
    }

    return nstr;
}

static char *store_hex(struct pkt_buf *buf, const char *str)
{
    size_t len = strlen(str);
    char *nstr = pkt_buf_mkspace(buf, len +  1);

    if (nstr) {
        memcpy(nstr, str, len);
        nstr[len] = '\0';
        // rewind
        buf->ptr--;
    }

    return nstr;
}

static int test_file(const char *file)
{
    char lbuf[2048];
    char sbuf[2048];
    char hbuf[2048];
    int lineno = 0;
    int testno = 0;
    int num_fail = 0;
    int state = 0;
    enum test_cmd cmd = 0;
    char *pkt = NULL, *desc = NULL;
    char *msgs[10];
    size_t nmsg = 0;

    struct pkt_buf strs = PKT_BUF_INIT(sbuf, sizeof(sbuf));
    struct pkt_buf hex  = PKT_BUF_INIT(hbuf, sizeof(hbuf));

    FILE *f = fopen(file, "r");
    if (f == NULL) return -1;

    fprintf(stderr,"test-case: %s\n", file);

    while (fgets(lbuf, sizeof(lbuf), f)) {
        lineno++;
        char *line = trim(lbuf);
        // skip blank lines
        if (strlen(line) == 0) continue;

        char *args;
        enum test_cmd cmd1;
        int rc = 0;

        switch(state) {
        case 0: // start
            if (*line != '#') {
                rc = log_error_rf("line %d expect start #", lineno);
                break;
            }
            line = trim(line + 1);
            // new-test
            testno++;
            pkt_buf_reset(&strs);
            pkt_buf_reset(&hex);
            pkt_buf_endz(&hex);
            desc = store_str(&strs, line);
            if (!desc) {
                rc = log_error_rf("line %d store desc failed %s", lineno, line);
                break;
            }
            pkt = NULL;
            nmsg = 0;
            // next state
            state = 1;
            break;
        case 1: // MSG|PKT_START|ENC_START
            args = strchr(line, ' ');
            if (args) *args++ = '\0';
            args = trim(args);
            cmd = str_tocmd(line);
            if (!cmd) {
                rc = log_error_rf("line %d unsupp %s", lineno, line);
                break;
            }
            if (args && !store_str(&hex, args)) {
                rc = log_error_rf("line %d store hex failed %s", lineno, line);
                break;
            }
            // next-state
            if (cmd == TEST_PKT_START) state = 2;
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
            // remove trailing comment
            args = strchr(line, '#');
            if (args) *args = '\0';
            // accumlate hex
            if (!store_hex(&hex, line)) {
                rc = log_error_rf("line %d store hex failed %s", lineno, line);
                break;
            }
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
            // remove trailing comment
            args = strchr(line, '#');
            if (args) *args = '\0';

            // name ":" args
            args = strchr(line, ':');
            if (args) *args++ = '\0';
            args = trim(args);
            if (!args) {
                rc = log_error_rf("line %d unsupp %s", lineno, line);
                break;
            }
            // pkt,msg,hex
            if (!strcasecmp(line, "pkt")) {
                if (pkt) {
                    rc = log_error_rf("line %d multiple pkt %s", lineno, line);
                    break;
                }
                pkt = store_str(&strs, args);
                if (!pkt) {
                    rc = log_error_rf("line %d no-room for pkt %s", lineno, line);
                    break;
                }
            }
            else if (!strcasecmp(line, "msg")) {
                // add msg to store
                if (nmsg >= ARR_LEN(msgs)) {
                    rc = log_error_rf("line %d no-room for msg %s", lineno, line);
                    break;
                }
                char *str = store_str(&strs, args);
                if (!str) {
                    rc = log_error_rf("line %d no-room for pkt %s", lineno, line);
                    break;
                }
                msgs[nmsg++] = str;
            }
            else if (!strcasecmp(line, "hex")) {
                // accumlate hex
                if (!store_hex(&hex, args)) {
                    rc = log_error_rf("line %d no-room for hex %s", lineno, line);
                }
            }
            else {
                rc = log_error_rf("line %d unsupp %s", lineno, line);
            }
            break;
        }

        if (rc) break;
        if (state != 4) continue;

        rc = run_test(cmd, pkt_buf_start(&hex), pkt, nmsg, msgs);
        char *pass = rc == 0 ? "PASS" : "FAIL";
        fprintf(stderr, "test %d [%s] %s\n", testno, pass, desc);
        if (rc) num_fail++;

        // next test
        state = 0;
    }
    fclose(f);

    if (state != 0) {
        log_error_rf("line %d missing end %d", lineno, cmd);
    }

    return num_fail;
}

static void usage(char *prog)
{
    const char *name = get_base(prog) ?: "<null>";
    printf("Usage: %s [-l log_level] [-h] FILE...\n", name);
}

static int parse_argv(struct test_state *ts, int argc, char *argv[])
{
    int opt;

    while ((opt = getopt(argc, argv, "l:h")) != -1) {
        switch(opt) {
        case 'l': log_level = atoi(optarg); break;
        case 'h': usage(argv[0]); exit(0); break;
        default: return log_error_rf("Unknown option %c", opt);
        }
    }

    // file list
    if (optind >= argc) return log_error_rf("Missing file list");
    ts->num_file = argc - optind;
    ts->files = &argv[optind];

    return 0;
}

int main(int argc, char *argv[])
{
    struct test_state ts = { 0 };

    log_init(NULL, LOG_INFO);
    if (parse_argv(&ts, argc, argv)) exit(1);

    for (int i = 0; i < ts.num_file; i++) {
        int nfail = test_file(ts.files[i]);
        if (nfail) ts.total_fail++;
    }

    return ts.total_fail;
}
