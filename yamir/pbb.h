/*
 * PBB - PacketBB codec for MANET packets
 * --------------------------------------
 * A lightweight PacketBB (rfc5444) codec API for encoding/decoding MANET packets.
 *
 * - Structure-composable: built for inline embedding, object compostion & memory locality
 * - full rfc5444 support for encoding/decoding wire-format MANET packets/messages.
 * - provides buffer, header and message structures for easy pkt generation.
 *
 * Refs
 * ----
 * rfc5444 - Generalized Mobile Ad Hoc Network (MANET) Packet/Message Format
 */
#ifndef _PBB_H_
#define _PPB_H_

#include <stdbool.h>
#include <sys/types.h>

#define PBB_HDR_MAXTLV  16
#define PBB_MSG_MAXTLV  8
#define PBB_MSG_MAXNODE 32
#define PPB_MAX_ADDRLEN 4 // TODO support IPv6

// pkt buffer

struct pkt_buf {
    uint8_t *data;
    uint8_t *ptr;
    uint8_t *end;
};

#define PKT_BUF_INIT(buf, len) { \
    .data = (uint8_t *) (buf), \
    .ptr  = (uint8_t *) (buf), \
    .end  = (uint8_t *) (buf) + (len) \
}

static inline void pkt_buf_init(struct pkt_buf *buf, void *data, size_t len)
{
    buf->data = data;
    buf->ptr  = data;
    buf->end  = buf->ptr + len;
}

static inline void *pkt_buf_start(struct pkt_buf *buf)
{
    return buf->data;
}

static inline void *pkt_buf_ptr(struct pkt_buf *buf)
{
    return buf->ptr;
}

static inline void pkt_buf_reset(struct pkt_buf *buf)
{
    buf->ptr = buf->data;
}

static inline size_t pkt_buf_avail(struct pkt_buf *buf)
{
    return buf->end - buf->ptr;
}

static inline size_t pkt_buf_used(struct pkt_buf *buf)
{
    return buf->ptr - buf->data;
}

static inline bool pkt_buf_end(struct pkt_buf *buf)
{
    return buf->ptr >= buf->end;
}

static inline void pkt_buf_inc(struct pkt_buf *buf, size_t len)
{
    if (len > pkt_buf_avail(buf)) return;
    buf->ptr += len;
}

static inline uint8_t *pkt_buf_mkspace(struct pkt_buf *buf, size_t len)
{
    if (len > pkt_buf_avail(buf)) return NULL;

    uint8_t *ptr = buf->ptr;
    buf->ptr += len;

    return ptr;
}

static inline void pkt_buf_endz(struct pkt_buf *buf)
{
    if (buf->ptr < buf->end) *buf->ptr = '\0';
}

size_t pkt_buf_printf(struct pkt_buf *buf, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));


// 5.3 <addr-flags> 8-bit field - network order (i.e MSB is bit 0) 
#define PBB_ABF_HEAD     (1 << 7) // ahashead
#define PBB_ABF_FULLTAIL (1 << 6) // ahasfulltail
#define PBB_ABF_ZEROTAIL (1 << 5) // ahaszerotail
#define PBB_ABF_SPRELEN  (1 << 4) // ahassingleprelen
#define PBB_ABF_MPRELEN  (1 << 3) // ahasmultiprelen

// 5.4. TLVs and TLV Blocks 
struct pbb_tlv {
    uint16_t type;
    uint8_t flags;
    uint8_t index_start;
    uint8_t index_stop;
    uint16_t length;
    uint8_t *value;
};


// <tlv-flags> 8-bit field - network order (i.e MSB is bit 0) 
#define TLVF_TYPEEXT     (1 << 7)
#define TLVF_SINGLEINDEX (1 << 6)
#define TLVF_MULTIINDEX  (1 << 5)
#define TLVF_VALUE       (1 << 5)
#define TLVF_EXTVALUE    (1 << 4)
#define TLVF_MULTIVALUE  (1 << 3)

// well nown tlvs
#define PBB_TLV_VALIDITY (1 << 8)
#define PBB_TLV_DID      (9 << 8)
#define PBB_TLV_SEQNUM  (10 << 8)
#define PBB_TLV_DIST    (11 << 8)

// helpers
static inline bool pbb_tlv_hastypeext(const struct pbb_tlv *tlv)
{
    return tlv->flags & TLVF_TYPEEXT;
}

/* MANET pkt-header  5.1 */

struct pbb_hdr {
    uint8_t version;
    uint8_t flags;
    uint16_t seq_num;
    uint8_t num_tlv;
    struct pbb_tlv tlvs[PBB_HDR_MAXTLV];
};

// header flags <pkt-flags> 4-bit field - network-order (i.e MSB is bit 0) 
#define PBB_HF_SEQN (1 << 3)
#define PBB_HF_TLV  (1 << 2)

// helpers
static inline void pbb_hdr_reset(struct pbb_hdr *hdr)
{
    hdr->version = 0;
    hdr->flags   = 0;
    hdr->seq_num = 0;
    hdr->num_tlv = 0;
}

static inline bool pbb_has_seqnum(const struct pbb_hdr *hdr)
{
    return hdr->flags & PBB_HF_SEQN;
}

static inline bool pbb_has_tlv(const struct pbb_hdr *hdr)
{
    return hdr->flags & PBB_HF_TLV;
}

// message node (MN)
struct msg_node {
    union {
        uint8_t  addr[16];
        uint32_t ip4_addr;
        uint16_t ip6_addr[8];
    };
    uint32_t dist;
    uint32_t vldtime;
    uint16_t seqnum;
    uint8_t  prefix;
    uint8_t  flags;
};

// msg node flags
#define PBB_NF_SKIP  (1 << 0)
#define PBB_NF_DIST  (1 << 1)
#define PBB_NF_VTIM  (1 << 2)
#define PBB_NF_SEQN  (1 << 3)
#define PBB_NF_PREF  (1 << 4)

// helpers
static inline bool mn_must_skip(const struct msg_node *mn)
{
    return mn->flags & PBB_NF_SKIP;
}

static inline bool mn_has_dist(const struct msg_node *mn)
{
    return mn->flags & PBB_NF_DIST;
}

static inline bool mn_has_vtim(const struct msg_node *mn)
{
    return mn->flags & PBB_NF_VTIM;
}

static inline bool mn_has_seqn(const struct msg_node *mn)
{
    return mn->flags & PBB_NF_SEQN;
}

static inline bool mn_has_pref(const struct msg_node *mn)
{
    return mn->flags & PBB_NF_PREF;
}

/* MANET message 5.2 */

struct pbb_msg {
    // <msg-header> 
    uint8_t type;
    uint8_t flags; 
    uint8_t addr_len;
    uint16_t size;
    // optional fields
    union {
        uint8_t  orig_addr[16];
        uint32_t orig_ip4;
        uint16_t orig_ip6[8];
    };
    uint8_t hop_limit;
    uint8_t hop_count;
    uint8_t seq_num;
    uint8_t num_node;
    uint8_t num_tlv;
    // well know tlv fields
    uint32_t did; 
    // address extracted from address blocks
    struct msg_node *target;
    struct msg_node *origin;
    // additional nodes
    struct pbb_tlv  tlvs[PBB_MSG_MAXTLV];
    struct msg_node nodes[PBB_MSG_MAXNODE];
};

// <msg-flags> 4-bit field - network order (i.e MSB is bit 0) 
#define PBB_MF_ORIG  (1 << 3)
#define PBB_MF_HLIM  (1 << 2)
#define PBB_MF_HCNT  (1 << 1)
#define PBB_MF_SEQN  (1 << 0)

// helpers
static inline void pbb_msg_reset(struct pbb_msg *msg)
{
    // hdr
    msg->type = 0;
    msg->flags = 0;
    msg->addr_len = 0;
    msg->size = 0;

    // optional fields
    msg->hop_limit = 0;
    msg->hop_count = 0;
    msg->seq_num = 0;
    msg->num_node = 0;
    msg->num_tlv = 0;
    msg->did = 0;

    msg->target = 0;
    msg->origin = 0;
}

static inline bool pbb_msg_has_orig(const struct pbb_msg *msg)
{
    return msg->flags & PBB_MF_ORIG;
}

static inline bool pbb_msg_has_hlim(const struct pbb_msg *msg)
{
    return msg->flags & PBB_MF_HLIM;
}

static inline bool pbb_msg_has_hcnt(const struct pbb_msg *msg)
{
    return msg->flags & PBB_MF_HCNT;
}

static inline bool pbb_msg_has_seqn(const struct pbb_msg *msg)
{
    return msg->flags & PBB_MF_SEQN;
}

enum PKT_FIELD {
    PF_NONE = 0,
    PF_PKT_VER_FLAGS,
    PF_PKT_SEQ_NUM,
    PF_PKT_TLV_BLOCK,
    PF_MSG_HDR,
    PF_MSG_ADDR_LEN,
    PF_MSG_SIZE,
    PF_MSG_ORIG_ADDR,
    PF_MSG_ORIG_SEQNUM,
    PF_MSG_ORIG_LOCAL,
    PF_MSG_HOP_LIMIT,
    PF_MSG_HOP_COUNT,
    PF_MSG_SEQ_NUM,
    PF_MSG_TLV_DID,
    PF_MSG_TLV_BLOCK,
    PF_ADRBLK_NUM_ADDR,
    PF_ADRBLK_ADDR_FLAGS,
    PF_ADRBLK_HEAD_LEN,
    PF_ADRBLK_HEAD,
    PF_ADRBLK_TAIL_LEN,
    PF_ADRBLK_TAIL,
    PF_ADRBLK_MID,
    PF_ADRBLK_PREFIX_LEN,
    PF_TLVBLK_LENGTH,
    PF_TLVBLK_TLVS,
    PF_TLV_TYPE,
    PF_TLV_FLAGS,
    PF_TLV_TYPE_EXT,
    PF_TLV_INDEXSTART,
    PF_TLV_INDEXSTOP,
    PF_TLV_LENGTH,
    PF_TLV_VALUE,
    PF_TARGET_NODE,
    PF_ORIGIN_NODE,
    PF_UNREACHABLE_NODE
};

// api
struct msg_node *pbb_msg_add_node(struct pbb_msg *msg, struct msg_node *node);
ssize_t ppb_hdr_encode(struct pbb_hdr *hdr, void *mem, size_t len);
ssize_t ppb_hdr_decode(struct pbb_hdr *hdr, void *mem, size_t len);
ssize_t pbb_msg_encode(struct pbb_msg *msg, void *mem, size_t len);
ssize_t pbb_msg_decode(struct pbb_msg *msg, void *mem, size_t len);

int pkt_buf_decode_hdr(struct pkt_buf *buf, struct pbb_hdr *hdr);
int pkt_buf_decode_msg(struct pkt_buf *buf, struct pbb_msg *msg);

const char *pbb_addr_tostr(size_t len, uint8_t addr[static len]);
const char *ppb_type_tostr(uint32_t type);
int ppb_msg_tostr(struct pbb_msg *msg, char *buf, size_t len);

#endif
