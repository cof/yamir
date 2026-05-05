/* SPDX-License-Identifier: MIT | (c) 2012-2026 [cof] */

/*
 * PBB - PacketBB codec for MANET packets
 * --------------------------------------
 * A lightweight PacketBB (rfc5444) codec API for encoding/decoding MANET packets.
 *
 * - No dynamic memory allocation (malloc-free) for deterministic performance.
 * - Structure-composable: built for inline embedding, object compostion & memory locality
 * - full rfc5444 support for encoding/decoding wire-format MANET packets/messages.
 * - Provides buffer, header and message structures for easy pkt generation.
 * - Supports address compression and expansion.
 *
 * Structures
 * ----------
 * struct pkt_buf  - packet buffer for reading/writing data
 * struct pbb_hdr  - MANET packet header (pkt-header)
 * struct pbb_msg  - MANET message
 * struct pbb_node - Address info (addr-blocks/tlv-block)
 *
 *
 * API
 * ----
 * PKT_BUF_INIT(mem, len)        : macro to init buffer
 * pkt_buf_init(buf, mem, len)   : init buffer with memory
 * pkt_buf_start(buf)            : return buffer start pointer
 * pkt_buf_ptr(buf)              : return buffer position pointer
 * pkt_buf_reset(buf)            : reset buffer position pointer to start
 * pkt_buf_end(bif)              : true if buffer pos at end
 * bkt_buf_len(buf)              : return buffer size
 * pkt_buf_rem(buf)              : return remaining read/write space in buffer
 * pkt_buf_pos(buf)              : return buffer read/write index
 * pkt_buf_inc(buf)              : increment buffer read/write index
 * pkt_buf_endz(buf)             : set buffer end to nul char if space
 * pkt_buf_mkspace(buf, len)     : return position pointer and increment if space else null
 * pkt_buf_printf(buf, fmt, ...) : printf fmt to buffer
 * -
 * ppb_hdr_enc(hdr, buf, len) : encode pkt-header to buffer
 * ppb_hdr_dec(hdr, buf, len) : decode pkt-header from buffer
 * pbb_msg_enc(msg, buf, len) : encode message to buffer
 * pbb_msg_dec(msg, buf, len) : decode message from buffer
 * -
 * pkt_buf_hdr_enc(buf, hdr)  : encode pkt-header to pkt buf
 * pkt_buf_hdr_dec(buf, hdr)  : decode pkt-header from pkt buf
 * pkt_buf_msg_enc(buf, msg)  : encode message to pkt buf
 * pkt_buf_msg_dec(buf, msg)  : decode message from pkt buff
 * -
 * pbb_str_toaddr(str, addr)  : string to IP address
 * pbb_addr_tostr(len, addr)  : IP adders to string
 * pbb_type_tostr(type)       : msg-type to string
 * pbb_str_totype(str)        : string to msg-type
*  pbb_msg_tostr(msg, buf, len) : message to string
 *
 * Refs
 * ----
 * rfc5444 - Generalized Mobile Ad Hoc Network (MANET) Packet/Message Format
 */
#ifndef _PBB_H_
#define _PPB_H_

#include <stdbool.h>
#include <stdint.h>

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

static inline bool pkt_buf_end(struct pkt_buf *buf)
{
    return buf->ptr >= buf->end;
}

static inline size_t pkt_buf_len(struct pkt_buf *buf)
{
    return buf->end - buf->data;
}

static inline size_t pkt_buf_pos(struct pkt_buf *buf)
{
    return buf->ptr - buf->data;
}

static inline size_t pkt_buf_rem(struct pkt_buf *buf)
{
    return buf->end - buf->ptr;
}

static inline void pkt_buf_inc(struct pkt_buf *buf, size_t len)
{
    if (len > pkt_buf_rem(buf)) return;
    buf->ptr += len;
}

static inline void pkt_buf_endz(struct pkt_buf *buf)
{
    if (buf->ptr < buf->end) *buf->ptr = '\0';
}

static inline void *pkt_buf_mkspace(struct pkt_buf *buf, size_t len)
{
    if (len > pkt_buf_rem(buf)) return NULL;

    void *ptr = buf->ptr;
    buf->ptr += len;

    return ptr;
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
    uint8_t idx_start;
    uint8_t idx_stop;
    uint16_t vlen;
    uint8_t *val;
};

// <tlv-flags> 8-bit field - network order (i.e MSB is bit 0)
#define TLVF_TYPEEXT     (1 << 7)
#define TLVF_SINGLEINDEX (1 << 6)
#define TLVF_MULTIINDEX  (1 << 5)
#define TLVF_VALUE       (1 << 4)
#define TLVF_EXTVALUE    (1 << 3)
#define TLVF_MULTIVALUE  (1 << 2)

// well known tlvs
#define PBB_TLV_VALIDITY (1 << 8)
#define PBB_TLV_SEQNUM   (224 << 8)
#define PBB_TLV_DIST     (7 << 8)
#define PBB_TLV_DID      (9 << 8)

// helpers
static inline bool pbb_tlv_hastypeext(const struct pbb_tlv *tlv)
{
    return tlv->flags & TLVF_TYPEEXT;
}

static inline void pbb_tlv_reset(struct pbb_tlv *tlv)
{
    tlv->type  = 0;
    tlv->flags = 0;
    tlv->vlen  = 0;
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

// message node (MN) - aka addr-block + tlv
struct pbb_node {
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

static inline struct pbb_node *pbb_node_reset(struct pbb_node *mn)
{
    mn->dist = 0;
    mn->vldtime = 0;
    mn->seqnum = 0;
    mn->prefix = 0;
    mn->flags = 0;

    return mn;
}

// msg node flags
#define PBB_NF_SKIP  (1 << 0)
#define PBB_NF_PREF  (1 << 1)
#define PBB_NF_DIST  (1 << 2)
#define PBB_NF_VTIM  (1 << 3)
#define PBB_NF_SEQN  (1 << 4)

// helpers
static inline bool pbb_node_skip(const struct pbb_node *mn)
{
    return mn->flags & PBB_NF_SKIP;
}

static inline bool pbb_node_dist(const struct pbb_node *mn)
{
    return mn->flags & PBB_NF_DIST;
}

static inline bool pbb_node_vtim(const struct pbb_node *mn)
{
    return mn->flags & PBB_NF_VTIM;
}

static inline bool pbb_node_seqn(const struct pbb_node *mn)
{
    return mn->flags & PBB_NF_SEQN;
}

static inline bool pbb_node_pref(const struct pbb_node *mn)
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
    struct pbb_node *target;
    struct pbb_node *origin;
    // additional nodes
    struct pbb_tlv  tlvs[PBB_MSG_MAXTLV];
    struct pbb_node nodes[PBB_MSG_MAXNODE];
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

static inline bool pbb_msg_orig(const struct pbb_msg *msg)
{
    return msg->flags & PBB_MF_ORIG;
}

static inline bool pbb_msg_hlim(const struct pbb_msg *msg)
{
    return msg->flags & PBB_MF_HLIM;
}

static inline bool pbb_msg_hcnt(const struct pbb_msg *msg)
{
    return msg->flags & PBB_MF_HCNT;
}

static inline bool pbb_msg_seqn(const struct pbb_msg *msg)
{
    return msg->flags & PBB_MF_SEQN;
}

enum pbb_field {
    PBB_NONE = 0,
    PBB_PKT_VER_FLAGS,
    PBB_PKT_SEQ_NUM,
    PBB_PKT_TLV_BLOCK,
    PBB_MSG_HDR,
    PBB_MSG_TYPE,
    PBB_MSG_FLAGS,
    PBB_MSG_ALEN,
    PBB_MSG_SIZE,
    PBB_MSG_OADDR,
    PBB_MSG_HLIM,
    PBB_MSG_HCNT,
    PBB_MSG_SEQN,
    PBB_MSG_TLV_DID,
    PBB_MSG_TLV_BLOCK,
    PBB_ADRBLK_NUM_ADDR,
    PBB_ADRBLK_ADDR_FLAGS,
    PBB_ADRBLK_HEAD_LEN,
    PBB_ADRBLK_HEAD,
    PBB_ADRBLK_TAIL_LEN,
    PBB_ADRBLK_TAIL,
    PBB_ADRBLK_MID,
    PBB_ADRBLK_PREFIX_LEN,
    PBB_TLVBLK_LENGTH,
    PBB_TLVBLK_TLVS,
    PBB_TLV_TYPE,
    PBB_TLV_FLAGS,
    PBB_TLV_TYPE_EXT,
    PBB_TLV_INDEXSTART,
    PBB_TLV_INDEXSTOP,
    PBB_TLV_LENGTH,
    PBB_TLV_VALUE,
    PBB_MSG_TNODE,
    PBB_MSG_ONODE,
    PBB_MSG_OSEQN,
    PBB_MSG_OLADDR,
    PBB_NODE_UNREACH
};

// api
struct pbb_node *pbb_add_node(struct pbb_msg *msg);
struct pbb_node *pbb_copy_node(struct pbb_msg *msg, struct pbb_node *src);

// mem encode/decode
ssize_t ppb_hdr_enc(struct pbb_hdr *hdr, void *mem, size_t len);
ssize_t ppb_hdr_dec(struct pbb_hdr *hdr, void *mem, size_t len);
ssize_t pbb_msg_enc(struct pbb_msg *msg, void *mem, size_t len);
ssize_t pbb_msg_dec(struct pbb_msg *msg, void *mem, size_t len);

// pkt_buf encode/decode
int pkt_buf_hdr_enc(struct pkt_buf *buf, struct pbb_hdr *hdr);
int pkt_buf_hdr_dec(struct pkt_buf *buf, struct pbb_hdr *hdr);
int pkt_buf_msg_enc(struct pkt_buf *buf, struct pbb_msg *msg);
int pkt_buf_msg_dec(struct pkt_buf *buf, struct pbb_msg *msg);

const char *pbb_field_tostr(int field);
size_t pbb_str_toaddr(const char *str, uint8_t addr[static 16]);
size_t pbb_node_puts(struct pkt_buf *buf, struct pbb_node *mn, int addr_len);
const char *pbb_addr_tostr(size_t len, uint8_t addr[static len]);
const char *pbb_node_tostr(struct pbb_node *mn, int addr_len);
const char *pbb_type_tostr(uint8_t type);
uint8_t pbb_str_totype(const char *str);
int pbb_msg_tostr(struct pbb_msg *msg, char *str, size_t len);

#endif
