/*
 * PBB - PacketBB codec for MANET packets
 * ----------------------------------
 * See pbb.h for API description.
 *
 * Refs
 * ----
 * rfc5444 - Generalized Mobile Ad Hoc Network (MANET) Packet/Message Format
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>

#include "log.h"
#include "pbb.h"

#ifndef ARR_LEN
#define ARR_LEN(a) (sizeof (a) / sizeof ((a)[0])) 
#endif 

static char *field2str[] = {
    [PF_NONE] = "none",
    [PF_PKT_VER_FLAGS] = "version:pkt-flags",
    [PF_PKT_SEQ_NUM] = "pkt-seq-num",
    [PF_PKT_TLV_BLOCK] = "pkt-tlv-block",
    [PF_MSG_HDR] = "msg-hdr:type:flags:addr-length:size",
    [PF_MSG_ADDR_LEN] = "msg-addr-length",
    [PF_MSG_SIZE]= "msg-size",
    [PF_MSG_ORIG_ADDR] = "msg-orig-addr",
    [PF_MSG_ORIG_SEQNUM] = "msg-orig-seqnum",
    [PF_MSG_ORIG_LOCAL] = "msg-orig-local-addr",
    [PF_MSG_HOP_LIMIT] = "msg-hop-limit",
    [PF_MSG_HOP_COUNT] = "msg-hop-count",
    [PF_MSG_SEQ_NUM] = "msg-seq-num",
    [PF_MSG_TLV_DID] = "msg-tlv-did",
    [PF_MSG_TLV_BLOCK] = "msg-tlv-block",
    [PF_ADRBLK_NUM_ADDR] = "addr-block-num-addr",
    [PF_ADRBLK_ADDR_FLAGS] = "addr-block-addr-flags",
    [PF_ADRBLK_HEAD_LEN] = "addr-block-head-len",
    [PF_ADRBLK_HEAD] = "addr-block-head",
    [PF_ADRBLK_TAIL_LEN] = "addr-block-tail-len",
    [PF_ADRBLK_TAIL] = "addr-block-tail",
    [PF_ADRBLK_MID] = "addr-block-mid",
    [PF_ADRBLK_PREFIX_LEN] = "addr-block-prefix-length",
    [PF_TLVBLK_LENGTH] = "tlv-block-length",
    [PF_TLVBLK_TLVS] = "tlv-block-tlvs",
    [PF_TLV_TYPE] = "tlv-type",
    [PF_TLV_FLAGS] = "tlv-flags",
    [PF_TLV_TYPE_EXT] = "tlv-type-ext",
    [PF_TLV_INDEXSTART] = "tlv-index-start",
    [PF_TLV_INDEXSTOP] = "tlv-index-stop",
    [PF_TLV_LENGTH] = "tlv-length",
    [PF_TLV_VALUE] = "tlv-value",
    [PF_TARGET_NODE] = "TargetNode",
    [PF_ORIGIN_NODE] = "OriginNode",
    [PF_UNREACHABLE_NODE] = "UnreachableNode"
};

struct pbb_ablk {
    // buffers
    uint8_t *head;
    uint8_t *tail;
    uint8_t *mid;
    uint8_t *prefix;
    uint8_t addr_len;
    // state
    int num_addr;
    uint8_t flags; // <addr-flags>
    int head_len;
    int tail_len;
    int mid_len;
    struct msg_node *nodes[PBB_MSG_MAXNODE];
};

static void pbb_ablk_reset(struct pbb_ablk *ablk)
{
    ablk->num_addr = 0;
    ablk->flags = 0;
    ablk->head_len = 0;
    ablk->tail_len = 0;
    ablk->mid_len = 0;
}

/*  decoders */

static inline uint32_t dec_u32(uint8_t *ptr, int size)
{
    switch(size) {
    case 1: return ptr[0];
    case 2: return ptr[0] << 8 | ptr[1];
    case 3: return ptr[0] << 16 | ptr[1] << 8 | ptr[2];
    case 4: return ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
    default: return 0;
    }
}

static int dec_err(struct pkt_buf *buf, size_t len, enum pkt_field field)
{
    log_debug("decode_error(%s) at offset %zu. Have %zu need %zu",
        field2str[field], pkt_buf_used(buf), pkt_buf_avail(buf), len);

    return -1;
}

static uint8_t *dec_next(struct pkt_buf *buf, size_t len, enum pkt_field field)
{
    uint8_t *ptr = pkt_buf_mkspace(buf, len);

    if (!ptr) dec_err(buf, len, field);

    return ptr;
}

static void load_node_tlv(struct pbb_ablk *ablk, struct pbb_tlv *tlv)
{
    int idx_end = ablk->num_addr - 1;

    // table 5
    int idx_start, idx_stop;
    switch(tlv->flags & (TLVF_SINGLEINDEX & TLVF_MULTIINDEX)) {
    case 0:
        idx_start = 0; 
        idx_stop  = idx_end;
        break;
    case TLVF_SINGLEINDEX:
        idx_start = tlv->index_start;
        idx_stop  = tlv->index_start;
        break;
    case TLVF_MULTIINDEX:
        idx_start = tlv->index_start;
        idx_stop  = tlv->index_stop;
        break;
    default:
        idx_start = 0;
        idx_stop = 0;
        break;
    }

    int single_len = 0;
    if (tlv->flags & TLVF_VALUE) {
        int num_val = idx_stop - idx_start + 1;
        single_len = tlv->flags & TLVF_MULTIVALUE
            ? tlv->length / num_val
            : tlv->length;
    }

    for (int i = idx_start; i <= idx_stop; i++) {
        uint8_t *ptr = NULL;
        if (tlv->flags & TLVF_VALUE) {
            ptr = tlv->flags & TLVF_MULTIVALUE
                ? tlv->value + (i - idx_start) * single_len
                : tlv->value;
        }
        struct msg_node *mn = ablk->nodes[i];
        if (!mn) continue;
        // load message-node TLV
        switch(tlv->type) {
        case PBB_TLV_SEQNUM:
            if (!ptr) break;
            mn->seqnum = dec_u32(ptr, single_len);
            mn->flags |= PBB_NF_SEQN;
            break;
        case PBB_TLV_DIST:
            if (!ptr) break;
            mn->dist = dec_u32(ptr, single_len);
            mn->flags |= PBB_NF_DIST;
            break;
        default:
            // TODO add to unknown list
            break;
        }
    }
}

static int dec_pbb_tlv(struct pkt_buf *buf, struct pbb_tlv *tlv)
{
    log_debug("buf_len=%zu", pkt_buf_avail(buf));

    memset(tlv, 0, sizeof(*tlv));

    uint8_t *ptr = dec_next(buf, 1, PF_TLV_TYPE);
    if (!ptr) return -1;
    tlv->type = dec_u32(ptr, 1);

    ptr = dec_next(buf, 1, PF_TLV_FLAGS);
    if (!ptr) return -1;
    tlv->flags = dec_u32(ptr, 1);

    if (tlv->flags & TLVF_TYPEEXT) {
        ptr = dec_next(buf, 1, PF_TLV_TYPE_EXT);
        if (!ptr) return -1;
        tlv->type <<= 8;
        tlv->type |= dec_u32(ptr, 1);
    }

    // table 3
    switch(tlv->flags & (TLVF_SINGLEINDEX | TLVF_MULTIINDEX)) {
    case TLVF_SINGLEINDEX: 
        ptr = dec_next(buf, 1, PF_TLV_INDEXSTART);
        if (!ptr) return -1;
        tlv->index_start = dec_u32(ptr, 1);
        break;
    case TLVF_MULTIINDEX:
        ptr = dec_next(buf, 1, PF_TLV_INDEXSTART);
        if (!ptr) return -1;
        tlv->index_start = dec_u32(ptr, 1);
        ptr = dec_next(buf, 1, PF_TLV_INDEXSTOP);
        if (!ptr) return -1;
        tlv->index_stop = dec_u32(ptr, 1);
        break;
    }

    // table 4
    switch(tlv->flags & (TLVF_VALUE | TLVF_EXTVALUE)) {
    case TLVF_VALUE:
        ptr = dec_next(buf, 1, PF_TLV_LENGTH);
        if (!ptr) return -1;
        tlv->length = dec_u32(ptr, 1);
        ptr = dec_next(buf, tlv->length, PF_TLV_VALUE);
        if (!ptr) return -1;
        tlv->value = ptr;
        break;
    case TLVF_VALUE | TLVF_EXTVALUE:
        ptr = dec_next(buf, 2, PF_TLV_LENGTH);
        if (!ptr) return -1;
        tlv->length = dec_u32(ptr, 2);
        ptr = dec_next(buf, tlv->length, PF_TLV_VALUE);
        if (!ptr) return -1;
        tlv->value = ptr;
        break;
    }

    log_debug("pbb-tlv [type=%d flags=0x%0x idx_start=%d idx_end=%d len=%d]",
        tlv->type, tlv->flags, tlv->index_start, tlv->index_stop, tlv->length);

    return 0;
}

static int dec_addr_tlvs(struct pkt_buf *buf, struct pbb_ablk *ablk)
{
    log_debug("buf_avail=%zu", pkt_buf_avail(buf));

    // tlvs-length
    uint8_t *ptr = dec_next(buf, 2, PF_TLVBLK_LENGTH);
    if (!ptr) return -1;
    uint16_t tlvs_len = dec_u32(ptr, 2);

    // tlvs-data
    ptr = dec_next(buf, tlvs_len, PF_TLVBLK_TLVS);
    if (!ptr) return -1;

    struct pkt_buf tlv_buf = PKT_BUF_INIT(ptr, tlvs_len);
    struct pbb_tlv tlv;

    while (pkt_buf_avail(&tlv_buf))  {
        if (dec_pbb_tlv(&tlv_buf, &tlv)) return -1;
        load_node_tlv(ablk, &tlv);
    }

    return 0;
}

static void expand_addr(struct pbb_ablk *ablk, struct pbb_msg *msg)
{
    log_debug("num_addr=%d", ablk->num_addr);

    uint8_t buf[512];

    for (int i = 0; i < ablk->num_addr; i++) {
        // first gen the address
        uint8_t *ptr = buf;
        if (ablk->flags & PBB_ABF_HEAD) {
            memcpy(ptr, ablk->head, ablk->head_len);
            ptr += ablk->head_len;
        }
        if (ablk->mid_len) {
            uint8_t *mid_addr = ablk->mid + (i * ablk->mid_len);
            memcpy(ptr, mid_addr, ablk->mid_len);
            ptr += ablk->mid_len;
        }
        if (ablk->flags & PBB_ABF_FULLTAIL) {
            memcpy(ptr, ablk->tail, ablk->tail_len);
            ptr += ablk->tail_len;
        }
        if (ablk->flags & PBB_ABF_ZEROTAIL) {
            memset(ptr, 0, ablk->tail_len);
            ptr += ablk->tail_len;
        }

        size_t addr_len = ptr - buf;
        if (addr_len > 16) continue;

        // now the prefix
        bool have_prefix = false;
        uint8_t prefix = 8 * ablk->addr_len;

        if (ablk->flags & PBB_ABF_SPRELEN) {
            prefix = ablk->prefix[0];
            have_prefix = true;
        }
        if (ablk->flags & PBB_ABF_MPRELEN) {
            prefix = ablk->prefix[i];
            have_prefix = true;
        }

        log_debug("addr=%s/%d ", pbb_addr_tostr(addr_len, buf), prefix);

        // add new msg-node
        if (msg->num_node >= ARR_LEN(msg->nodes)) continue;
        struct msg_node *mn = &msg->nodes[msg->num_node++];
        memset(mn, 0, sizeof(*mn));

        memcpy(mn->addr, buf, addr_len);
        mn->prefix = prefix;
        if (have_prefix) mn->flags |= PBB_NF_PREF;
        ablk->nodes[i] = mn;
    }
}

// decode address block
static int dec_pbb_ablk(struct pkt_buf *buf, struct pbb_ablk *ablk)
{
    log_debug("buf_avail=%zu", pkt_buf_avail(buf));

    uint8_t *ptr = dec_next(buf, 1, PF_ADRBLK_NUM_ADDR);
    if (!ptr) return -1;
    ablk->num_addr = dec_u32(ptr, 1);

    ptr = dec_next(buf, 1, PF_ADRBLK_ADDR_FLAGS);
    if (!ptr) return -1;
    ablk->flags = dec_u32(ptr, 1);

    if (ablk->flags & PBB_ABF_HEAD) {
        ptr = dec_next(buf, 1, PF_ADRBLK_HEAD_LEN);
        if (!ptr) return -1;
        ablk->head_len = dec_u32(ptr, 1);
        ptr = dec_next(buf, ablk->head_len, PF_ADRBLK_HEAD);
        if (!ptr) return -1;
        ablk->head = ptr;
    }

    // table 1 : ahasfulltail and ahaszerotail flags  
    switch(ablk->flags & (PBB_ABF_FULLTAIL | PBB_ABF_ZEROTAIL)) {
    case PBB_ABF_FULLTAIL:
        ptr = dec_next(buf, 1, PF_ADRBLK_TAIL_LEN);
        if (!ptr) return -1;
        ablk->tail_len = dec_u32(ptr, 1);
        ptr = dec_next(buf, ablk->tail_len, PF_ADRBLK_TAIL);
        if (!ptr) return -1;
        ablk->tail = ptr;
        break;
    case PBB_ABF_ZEROTAIL:
        ptr = dec_next(buf, 1, PF_ADRBLK_TAIL_LEN);
        if (!ptr) return -1;
        ablk->tail_len = dec_u32(ptr, 1);
        break;
    }

    ablk->mid_len = ablk->addr_len - ablk->head_len - ablk->tail_len;
    ptr = dec_next(buf, ablk->mid_len * ablk->num_addr, PF_ADRBLK_MID);
    if (!ptr) return -1;
    ablk->mid = ptr;

    // table 2 : ahassingleprelen and ahasmultiprelen flags
    switch(ablk->flags & (PBB_ABF_SPRELEN | PBB_ABF_MPRELEN)) {
    case PBB_ABF_SPRELEN:
        ptr = dec_next(buf, 1, PF_ADRBLK_PREFIX_LEN);
        if (!ptr) return -1;
        ablk->prefix = ptr;
        break;
    case PBB_ABF_MPRELEN:
        ptr = dec_next(buf, ablk->num_addr, PF_ADRBLK_PREFIX_LEN);
        if (!ptr) return -1;
        ablk->prefix = ptr;
        break;
    }

    return 0;
}

static int dec_msg_nodes(struct pkt_buf *buf, struct pbb_msg *msg)
{
    log_debug("buf_avail=%zu", pkt_buf_avail(buf));

    uint8_t head[32];
    uint8_t tail[32];
    uint8_t mid[512];
    uint8_t prefix[32];

    struct pbb_ablk ablk = { 
        .head = head,
        .tail = tail,
        .mid  = mid,
        .prefix = prefix,
        .addr_len = msg->addr_len
    };

    while (pkt_buf_avail(buf)) {
        if (dec_pbb_ablk(buf, &ablk)) return -1;
        expand_addr(&ablk, msg);
        if (dec_addr_tlvs(buf, &ablk)) return -1;
        pbb_ablk_reset(&ablk);
    }

    return 0;
}

static int dec_msg_tlvs(struct pkt_buf *buf, struct pbb_msg *msg)
{
    log_debug("buf_avail=%zu", pkt_buf_avail(buf));

    // tlvs-length
    uint8_t *ptr = dec_next(buf, 2, PF_TLVBLK_LENGTH);
    if (!ptr) return -1;
    uint16_t tlvs_len = dec_u32(ptr, 2);

    log_debug("tlvs-len=%d", tlvs_len);

    // tlvs-data
    ptr = dec_next(buf, tlvs_len, PF_TLVBLK_TLVS);
    if (!ptr) return -1;

    struct pkt_buf tlv_buf = PKT_BUF_INIT(ptr, tlvs_len);
    struct pbb_tlv tlv;

    while (pkt_buf_avail(&tlv_buf))  {
        if (dec_pbb_tlv(&tlv_buf, &tlv)) return -1;
        switch(tlv.type) {
        case PBB_TLV_DID:
            msg->did = dec_u32(tlv.value, tlv.length);
            break;
        default:
            // add to unknown tlvs
            if (msg->num_tlv < ARR_LEN(msg->tlvs)) {
                msg->tlvs[msg->num_tlv++] = tlv;
            }
        }
    }

    // all done
    return 0;
}

// decode optional fields
static int dec_msg_flds(struct pkt_buf *buf, struct pbb_msg *msg)
{
    uint8_t *ptr;

    if (pbb_msg_has_orig(msg)) {
        ptr = dec_next(buf, msg->addr_len, PF_MSG_ORIG_ADDR);
        if (!ptr) return -1;
        memcpy(msg->orig_addr, ptr, msg->addr_len);
    }

    if (pbb_msg_has_hlim(msg)) {
        ptr = dec_next(buf, 1, PF_MSG_HOP_LIMIT);
        if (!ptr) return -1;
        msg->hop_limit = dec_u32(ptr, 1);
    }

    if (pbb_msg_has_hcnt(msg)) {
        ptr = dec_next(buf, 1, PF_MSG_HOP_COUNT);
        if (!ptr) return -1;
        msg->hop_limit = dec_u32(ptr, 1);
    }

    if (pbb_msg_has_seqn(msg)) {
        ptr = dec_next(buf, 2, PF_MSG_SEQ_NUM);
        if (!ptr) return -1;
        msg->seq_num = dec_u32(ptr, 2);
    }

    log_debug("msg-flds [orig=%s hlim=%d hcnt=%d seqn=%d]", 
        pbb_msg_has_orig(msg) ? pbb_addr_tostr(msg->addr_len, msg->orig_addr) : "",
        msg->hop_limit, msg->hop_limit, msg->seq_num);

    return 0;
}

// 5.2 decode <message>
static int dec_pbb_msg(struct pkt_buf *buf, struct pbb_msg *msg)
{
    log_debug("buf_avail=%zu", pkt_buf_avail(buf));

    pbb_msg_reset(msg);

    uint8_t *ptr = dec_next(buf, 4, PF_MSG_HDR);
    if (!ptr) return -1;

    msg->type = ptr[0];
    msg->flags = ptr[1] >> 4;
    msg->addr_len = (ptr[1] & 0xf) + 1;
    msg->size = dec_u32(ptr + 2, 2);

    log_debug("msg-hdr [type=%s flags=0x%x addr_len=%d size=%d]", 
        pbb_type_tostr(msg->type), msg->flags, msg->addr_len, msg->size);

    // msg-size
    if (msg->size < 4) return dec_err(buf, 4 - msg->size, PF_MSG_SIZE);
    ptr = dec_next(buf, msg->size - 4, PF_MSG_SIZE);
    if (!ptr) return -1;
    struct pkt_buf msg_buf = PKT_BUF_INIT(ptr, msg->size - 4);

    if (dec_msg_flds(&msg_buf, msg)) return -1;
    if (dec_msg_tlvs(&msg_buf, msg)) return -1;
    if (dec_msg_nodes(&msg_buf, msg)) return -1;

    return 0;
}

static int dec_hdr_tlvs(struct pkt_buf *buf, struct pbb_hdr *hdr)
{
    log_debug("buf_avail=%zu", pkt_buf_avail(buf));

    // tlvs-length
    uint8_t *ptr = dec_next(buf, 2, PF_TLVBLK_LENGTH);
    if (!ptr) return -1;
    uint16_t tlvs_len = dec_u32(ptr, 2);

    log_debug("tlvs-len=%d", tlvs_len);

    // tlvs-data
    ptr = dec_next(buf, tlvs_len, PF_TLVBLK_TLVS);
    if (!ptr) return -1;

    struct pkt_buf tlv_buf = PKT_BUF_INIT(ptr, tlvs_len);
    struct pbb_tlv tlv;

    while (pkt_buf_avail(&tlv_buf))  {
        if (dec_pbb_tlv(&tlv_buf, &tlv)) return -1;
        if (hdr->num_tlv < ARR_LEN(hdr->tlvs)) {
            hdr->tlvs[hdr->num_tlv++] = tlv;
        }
    }

    // all done
    return 0;
}

static int dec_pbb_hdr(struct pkt_buf *buf, struct pbb_hdr *hdr)
{
    log_debug("buf_avail=%zu", pkt_buf_avail(buf));

    pbb_hdr_reset(hdr);

    uint8_t *ptr = dec_next(buf, 1, PF_PKT_VER_FLAGS);
    if (!ptr) return -1;

    hdr->version = *ptr >> 4;
    hdr->flags = *ptr & 0xf;

    if (pbb_has_seqnum(hdr)) {
        ptr = dec_next(buf, 2, PF_PKT_SEQ_NUM);
        if (!ptr) return -1;
        hdr->seq_num = dec_u32(ptr, 2);
    }

    log_debug("pkt-hdr [ver=%d flags=0x%x seqnum=%d ]", hdr->version, hdr->flags, hdr->seq_num);

    if (pbb_has_tlv(hdr) && dec_hdr_tlvs(buf, hdr)) {
        return -1;
    }

    return 0;
}

/* encoders */

static inline uint8_t *enc_u32(uint8_t *ptr, uint32_t val, size_t len)
{
    switch(len) {
    case 4: *ptr++ = val >> 24;  /* fallthrough */
    case 3: *ptr++ = val >> 16;  /* fallthrough */
    case 2: *ptr++ = val >> 8;   /* fallthrough */
    case 1: *ptr++ = val;
    }

    return ptr;
}

static size_t pack_u32(uint8_t *buf, uint32_t val)
{
    uint8_t *pos = buf;

    if (val <= 0xff) {
        *pos++ = val;
    }
    else if (val <= 0xffff) {
        *pos++ = val >> 8;
        *pos++ = val;
    }
    else {
       *pos++ = val >> 24;
       *pos++ = val >> 16;
       *pos++ = val >> 8;
       *pos++ = val;
    }

    return pos - buf;
}

static size_t push_val(struct pkt_buf *buf, uint32_t value, size_t len)
{
    uint8_t *ptr = pkt_buf_mkspace(buf, len);
    if (!ptr) return 0;

    enc_u32(ptr, value, len);

    return len;
}

static inline size_t push_mem(struct pkt_buf *buf, uint8_t *data, size_t len)
{
    uint8_t *ptr = pkt_buf_mkspace(buf, len);
    if (!ptr) return 0;

    memcpy(ptr, data, len);

    return len;
}

// 5.4.1 TLVs
static int enc_pbb_tlv(struct pkt_buf *buf, struct pbb_tlv *tlv)
{
    uint8_t flags = tlv->flags;
    uint8_t type, ext;

    if (tlv->type <= 255) {
        type = tlv->type;
        ext = 0;
    }
    else  {
        type = tlv->type >> 8;
        ext = tlv->type & 0xff;
        flags |= TLVF_TYPEEXT;
    }

    if (!push_val(buf, type, 1)) return -1;
    if (!push_val(buf, flags, 1)) return -1;

    if (flags & TLVF_TYPEEXT) {
        if (!push_val(buf, ext, 1)) return -1;
    }
   
    // table 3
    switch(tlv->flags & (TLVF_SINGLEINDEX | TLVF_MULTIINDEX)) {
    case TLVF_SINGLEINDEX: 
        if (!push_val(buf, tlv->index_start, 1)) return -1;
        break;
    case TLVF_MULTIINDEX:
        if (!push_val(buf, tlv->index_start, 1)) return -1;
        if (!push_val(buf, tlv->index_stop, 1)) return -1;
        break;
    }

    // table 4
    switch(tlv->flags & (TLVF_VALUE | TLVF_EXTVALUE)) {
    case TLVF_VALUE:
        if (!push_val(buf, tlv->length, 1)) return -1;
        if (!push_mem(buf, tlv->value, tlv->length)) return -1;
        break;
    case TLVF_VALUE | TLVF_EXTVALUE:
        if (!push_val(buf, tlv->length, 2)) return -1;
        if (!push_mem(buf, tlv->value, tlv->length)) return -1;
        break;
    }

    return 0;
}

// encode tlv-block for pkt-header
static int enc_hdr_tlvs(struct pkt_buf *buf, struct pbb_hdr *hdr)
{
    // tlvs-length
    uint8_t *ptr = pkt_buf_mkspace(buf, 2);
    if (!ptr) return -1;

    // encode tlv-blocks
    for (int i = 0; i < hdr->num_tlv; i++) {
        if (enc_pbb_tlv(buf, &hdr->tlvs[i])) return -1;
    }

    // set tlvs-length
    enc_u32(ptr, buf->ptr - ptr, 2);

    return 0;
}

static int enc_pbb_hdr(struct pkt_buf *buf, struct pbb_hdr *hdr)
{
    uint8_t *ptr = pkt_buf_mkspace(buf, 1);
    if (!ptr) return -1;
    *ptr = (hdr->version << 4) | (hdr->flags & 0xf);

    if (pbb_has_seqnum(hdr)) {
        if (!push_val(buf, hdr->seq_num, 2)) return -1;
    }

    if (pbb_has_tlv(hdr)) {
        if (enc_hdr_tlvs(buf, hdr)) return -1;
    }

    return 0;
}

static int enc_addr_tlvs(struct pkt_buf *buf, struct pbb_ablk *ablk)
{
    uint8_t value[4];
    struct pbb_tlv tlv = {
        .flags = TLVF_SINGLEINDEX | TLVF_VALUE,
        .value = value
    };

    // tlv-length
    uint8_t *ptr = pkt_buf_mkspace(buf, 2);
    if (!ptr) return -1;

    for (int i = 0; i < ablk->num_addr; i++) {
        struct msg_node *mn = ablk->nodes[i];
        tlv.index_start = i;
        if (mn_has_seqn(mn)) {
            tlv.type = PBB_TLV_SEQNUM;
            tlv.length = pack_u32(value, mn->seqnum);
            if (enc_pbb_tlv(buf, &tlv)) return -1;
        }
        if (mn_has_dist(mn)) {
            tlv.type = PBB_TLV_DIST;
            tlv.length = pack_u32(value, mn->dist);
            if (enc_pbb_tlv(buf, &tlv)) return -1;
        }
    }

    // set tlv-length
    enc_u32(ptr, buf->ptr - ptr, 2);

    return 0;
}

// 5.3 encode <address-block>
static int enc_pbb_ablk(struct pkt_buf *buf, struct pbb_ablk *ablk)
{
    if (!push_val(buf, ablk->num_addr, 1)) return -1;
    if (!push_val(buf, ablk->flags, 1)) return -1;

    if (ablk->flags & PBB_ABF_HEAD) {
        if (!push_val(buf, ablk->head_len, 1)) return -1;
        if (!push_mem(buf, ablk->head, ablk->head_len)) return -1;
    }
    
    // table 1
    switch(ablk->flags & (PBB_ABF_FULLTAIL | PBB_ABF_ZEROTAIL)) {
    case PBB_ABF_FULLTAIL:
        if (!push_val(buf, ablk->tail_len, 1)) return -1;
        if (!push_mem(buf, ablk->tail, ablk->tail_len)) return -1;
        break;
    case PBB_ABF_ZEROTAIL:
        if (!push_val(buf, ablk->tail_len, 1)) return -1;
        break;
    }

    if (!push_mem(buf, ablk->mid, ablk->mid_len * ablk->num_addr)) return -1;

    // table 2
    switch(ablk->flags & (PBB_ABF_SPRELEN | PBB_ABF_MPRELEN)) {
    case PBB_ABF_SPRELEN:
        if (!push_mem(buf, ablk->prefix, 1)) return -1;
        break;
    case PBB_ABF_MPRELEN:
        if (!push_mem(buf, ablk->prefix, ablk->num_addr)) return -1;
        break;
    }

    return 0;
}

static bool compat_prefix(struct pbb_ablk *blk, struct msg_node *mn)
{
    bool blk_has_prefix = blk->flags & (PBB_ABF_SPRELEN | PBB_ABF_MPRELEN);
    bool mn_has_prefix = mn->flags & PBB_NF_PREF;

    if (!blk_has_prefix && !mn_has_prefix) return true;
    if (blk_has_prefix != mn_has_prefix) return false;
    if (blk->flags & PBB_ABF_SPRELEN) return mn->prefix == *blk->prefix;
    
    // blk is MULTI_PRELEN 
    return true;
}

static bool compress_addr(struct pbb_ablk *ablk, struct msg_node *mn)
{
    if (mn_must_skip(mn)) return false;

    bool added = false;
    if (ablk->num_addr == 0)  {
        // first addr
        ablk->flags = PBB_ABF_HEAD;
        memcpy(ablk->head, &mn->addr, ablk->addr_len);
        log_debug("%d.%d.%d.%d", ablk->head[0], ablk->head[1], ablk->head[2], ablk->head[3]);
        ablk->head_len = ablk->addr_len;
        ablk->tail_len = 0;
        ablk->mid_len = 0;
        added = true;
    }
    else if (compat_prefix(ablk, mn))  {
        // find common head
        uint8_t addr[16];
        memcpy(addr, &mn->addr, ablk->addr_len);
        log_debug("%d.%d.%d.%d\n", addr[0], addr[1], addr[2], addr[3]);
        int head_len = ablk->head_len;
        while (head_len > 0) {
            if (memcmp(ablk->head, addr, head_len) == 0) break;
            head_len--;
        }
        if (head_len == ablk->head_len) {
            uint8_t *mid_addr = ablk->mid + (ablk->num_addr * ablk->mid_len);
            memcpy(mid_addr, addr + ablk->mid_len, ablk->mid_len);
            added = true;
        }
        else if (ablk->mid_len == 0) {
            ablk->mid_len = ablk->head_len - head_len;
            ablk->head_len = head_len;
            memcpy(ablk->mid, ablk->head + head_len, ablk->mid_len);
            memcpy(ablk->mid + ablk->mid_len, addr + head_len, ablk->mid_len);
            added = true;
        }
    }

    if (!added) return false;

    // now add the prefix
    if (mn_has_pref(mn)) {
        if (ablk->flags & PBB_ABF_SPRELEN) {
            // already have a single prefix
            if (*ablk->prefix != mn->prefix) {
                // clear single prefix,set multi
                ablk->flags &= ~PBB_ABF_SPRELEN;
                ablk->flags |= PBB_ABF_MPRELEN;
                // need to duplicate common prefix
                uint8_t *prefix_addr = ablk->prefix + 1;
                for (int i = 1; i < ablk->num_addr; i++) {
                    *prefix_addr++ = *ablk->prefix;
                }
                // finally add new network prefix
                *prefix_addr = mn->prefix;
            }
        }
        else if (ablk->flags & PBB_ABF_MPRELEN) {
            // store multiple prefix
            uint8_t *prefix_addr = ablk->prefix + ablk->num_addr;
            *prefix_addr = mn->prefix;
        }
        else {
            // store single prefix len
            ablk->flags |= PBB_ABF_SPRELEN;
            *ablk->prefix = mn->prefix;
        }
    }

    ablk->nodes[ablk->num_addr++] = mn;

    return true;
}

static int enc_msg_nodes(struct pkt_buf *buf, struct pbb_msg *msg)
{
    uint8_t head[32];
    uint8_t tail[32];
    uint8_t mid[512];
    uint8_t prefix[32];

    struct pbb_ablk ablk = { 
        .head = head,
        .tail = tail,
        .mid  = mid,
        .prefix = prefix,
        .addr_len = msg->addr_len
    };

    for (int i = 0; i < msg->num_node; i++) {
        bool compressed = compress_addr(&ablk, &msg->nodes[i]);
        if (compressed && i != msg->num_node - 1) continue;
        if (enc_pbb_ablk(buf,  &ablk)) return -1;
        if (enc_addr_tlvs(buf, &ablk)) return -1;
        pbb_ablk_reset(&ablk);
    }

    return 0;
}

// encode well-known tlvs for message
static int enc_type_tlvs(struct pkt_buf *buf,  struct pbb_msg *msg) 
{
    struct pbb_tlv tlv;
    uint8_t value[4];

    if (!msg->did) return 0;

    tlv.type = PBB_TLV_DID;
    tlv.flags = TLVF_VALUE;
    tlv.length = pack_u32(value, msg->did);
    tlv.value = value;

    return enc_pbb_tlv(buf, &tlv);
}

// encode tlv-block for message
static int enc_msg_tlvs(struct pkt_buf *buf, struct pbb_msg *msg)
{
    // tlvs-length
    uint8_t *ptr = pkt_buf_mkspace(buf, 2);
    if (!ptr) return -1;

    // encode know tlvs
    if (enc_type_tlvs(buf, msg)) return -1;

    // encode the rest
    for (int i = 0; i < msg->num_tlv; i++) {
        if (enc_pbb_tlv(buf, &msg->tlvs[i])) return -1;
    }

    // set tlv-length
    enc_u32(ptr, buf->ptr - ptr , 2);

    return 0;
}

// encode optional fields
static int enc_msg_fields(struct pkt_buf *buf, struct pbb_msg *msg)
{
    if (pbb_msg_has_orig(msg) && !push_mem(buf, msg->orig_addr, msg->addr_len)) return -1;
    if (pbb_msg_has_hlim(msg) && !push_val(buf, msg->hop_limit, 1)) return -1;
    if (pbb_msg_has_hcnt(msg) && !push_val(buf, msg->hop_count, 1)) return -1;
    if (pbb_msg_has_seqn(msg) && !push_val(buf, msg->seq_num, 2)) return -1;

    return 0;
}

// 5.2 encode <message>
static int enc_pbb_msg(struct pkt_buf *buf, struct pbb_msg *msg)
{
    // msg-header type|flags|addr-length|size|
    uint8_t *hdr = pkt_buf_mkspace(buf, 4);
    if (!hdr) return -1;

    uint8_t addr_len = msg->addr_len;
    if (!addr_len) addr_len = 4;
    if (addr_len > 16) addr_len = 16;

    hdr[0] = msg->type;
    hdr[1] = (msg->flags << 4) | (addr_len - 1);

    if (enc_msg_fields(buf, msg)) return -1;
    if (enc_msg_tlvs(buf, msg)) return -1;
    if (enc_msg_nodes(buf, msg)) return -1;

    // update <msg-size>
    enc_u32(hdr + 2, buf->ptr - hdr, 2);

    return 0;
}

// add message node
struct msg_node *pbb_msg_add_node(struct pbb_msg *msg, struct msg_node *node)
{
    if (msg->num_node >= ARR_LEN(msg->nodes)) return NULL;

    struct msg_node *mn = &msg->nodes[msg->num_node++];
    *mn = *node;

    return mn;
}

// encode MANET pkt-header
ssize_t ppb_hdr_encode(struct pbb_hdr *hdr, void *mem, size_t len)
{
    struct pkt_buf buf = PKT_BUF_INIT(mem, len);

    int rc = enc_pbb_hdr(&buf, hdr);
    if (rc) return rc;

    return pkt_buf_used(&buf);
}

// decode MANET pkt-header
ssize_t ppb_hdr_decode(struct pbb_hdr *hdr, void *mem, size_t len)
{ 
    struct pkt_buf buf = PKT_BUF_INIT(mem, len);

    int rc = dec_pbb_hdr(&buf, hdr);
    if (rc) return rc;

    return pkt_buf_used(&buf);
}

// encode MANET message
ssize_t pbb_msg_encode(struct pbb_msg *msg, void *mem, size_t len)
{
    struct pkt_buf buf = PKT_BUF_INIT(mem, len);

    int rc = enc_pbb_msg(&buf, msg);
    if (rc) return rc;

    return pkt_buf_used(&buf);
}

// decode MANET message
ssize_t pbb_msg_decode(struct pbb_msg *msg, void *mem, size_t len)
{
    struct pkt_buf buf = PKT_BUF_INIT(mem, len);

    int rc = dec_pbb_msg(&buf, msg);
    if (rc) return rc;

    return pkt_buf_used(&buf);
}

// decode MANET pkt-header from pkt-buffer
int pkt_buf_decode_hdr(struct pkt_buf *buf, struct pbb_hdr *hdr)
{
    return dec_pbb_hdr(buf, hdr);
}

// decode MANET message from pkt-buffer
int pkt_buf_decode_msg(struct pkt_buf *buf, struct pbb_msg *msg)
{
    return dec_pbb_msg(buf, msg);
}

#define ADDR_STRLEN sizeof("ffff:ffff:ffff:ffff:ffff:ffff:fffff:ffff")

const char *pbb_addr_tostr(size_t len, uint8_t addr[static len])
{
    static char bufs[4][ADDR_STRLEN]; 
    static int idx;

    char *buf = bufs[idx];
    size_t size = sizeof(bufs[0]);
    idx = (idx + 1) & 3;

    if (len == 4 && inet_ntop(AF_INET, addr, buf, size)) return buf;
    if (len == 16 && inet_ntop(AF_INET6, addr, buf, size)) return buf;

    return "";
}

static char *u32toa(uint32_t val, char *buf, size_t len)
{
    if (!buf || len == 0) return buf;

    // start at buffer end - no reverse needed
    char *str = &buf[len -1];
    *str = '\0';
    if (val == 0) *--str = '0';

    while (val) {
        *--str = (val % 10) + '0';
        val /= 10;
    }

    return str; 
}

static char *u32_tostr(uint32_t val) 
{
    static char bufs[16][10];
    static int idx;

    char *str = bufs[idx];
    idx = (idx + 1) & 15;

    return u32toa(val, str, sizeof(bufs[0][0]));
}

// Mobile Ad hoc NETwork (MANET) Parameters
const char *pbb_type_tostr(uint32_t type)
{
    switch(type) {
    case  0:  return "HELLO";
    case  1:  return "TC";
    // DYMO / AODV2 
    case 10:  return "RREQ";
    case 11:  return "RREP";
    case 12:  return "RERR";
    case 13:  return "RREP-ACK";
    default:  return u32_tostr(type);
    }
}

size_t pkt_buf_printf(struct pkt_buf *buf, const char *fmt, ...)
{
    size_t len = pkt_buf_avail(buf);
    char *str = pkt_buf_ptr(buf);

    va_list args;
    va_start(args, fmt);
    int nw = vsnprintf(str, len, fmt, args);
    va_end(args);

    if (nw < 0) return 0;

    if ((size_t) nw >= len) {
        pkt_buf_endz(buf);
        nw = len;
    }
    buf->ptr += nw;

    return nw;
}

#define pbb_printf pkt_buf_printf

int pbb_msg_tostr(struct pbb_msg *msg, char *str, size_t len)
{
    struct pkt_buf buf = PKT_BUF_INIT(str, len);

    pbb_printf(&buf, "[MSG: type=%s flags=0x%x addr_len=%d size=%d",
        pbb_type_tostr(msg->type), msg->flags, msg->addr_len, msg->size
    );

    if (pbb_msg_has_orig(msg)) pbb_printf(&buf, " orig=%s", pbb_addr_tostr(msg->addr_len, msg->orig_addr));
    if (pbb_msg_has_hlim(msg)) pbb_printf(&buf, " hlim=%d", msg->hop_limit);
    if (pbb_msg_has_hcnt(msg)) pbb_printf(&buf, " hlim=%d", msg->hop_count);
    if (pbb_msg_has_seqn(msg)) pbb_printf(&buf, " seqn=%d", msg->seq_num);
    pbb_printf(&buf, " ]\n");

    // tlv-block
    for (int i = 0; i < msg->num_tlv; i++) {
        struct pbb_tlv *tlv = &msg->tlvs[i];
        pbb_printf(&buf, "[ TLV: type=%d flags=0x%0x ]", tlv->type, tlv->flags);
    }

    // addr-block (msg-node)
    for (int i = 0; i < msg->num_node; i++) {
        struct msg_node *mn = &msg->nodes[i];
        pbb_printf(&buf, "[ ADDR: %s", pbb_addr_tostr(msg->addr_len, mn->addr));
        pbb_printf(&buf, " flags=0x%x", mn->flags);
        if (mn_has_dist(mn)) pbb_printf(&buf, " dist=%u", mn->dist);
        if (mn_has_dist(mn)) pbb_printf(&buf, " dist=%u", mn->dist);
        if (mn_has_vtim(mn)) pbb_printf(&buf, " vtim=%u", mn->dist);
        if (mn_has_seqn(mn)) pbb_printf(&buf, " vtim=%u", mn->seqnum);
        if (mn_has_pref(mn)) pbb_printf(&buf, " pref=%u", mn->prefix);
        pbb_printf(&buf, " ]\n");
    }

    // return nw
    return pkt_buf_used(&buf);
}
