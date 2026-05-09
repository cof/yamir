/* SPDX-License-Identifier: MIT | (c) 2026 [cof] */

/*
 * YAMIR - Yet Another MANET IP Router
 *
 * This a userspace IP router with
 *
 *  - kyamir updates via netlink-generic
 *  - route management via rtnetlink
 *  - route discovery via DYMO protocol
 *  - PacketBB codec to read/write messages
 *
 * Usage:
 *
 *  ./yamird -i wlan0
 *
 * Notes:
 * -----
 * Running yarmid requires the following permissions
 *
 *  cap_net_bind_service - uses privileled port 269
 *  cap_net_raw          - uses SO_BINDTODEVICE
 *  cap_net_admin        - uses netlink multlicast nl_groups != 0
 *
 * sudo setcap cap_net_bind_service,cap_net_raw,cap_net_admin=+ep yamird
 *
 * Refs
 * ----
 * draft-ietf-manet-dymo-21 - Dynamic MANET On-demand (DYMO) Routing
 * man 7 rtnetlink - Linux IPv4 routing socket
 *
 */
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <stdalign.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <netdb.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <unistd.h>

#include "netlink.h"
#include "util.h"
#include "log.h"
#include "list.h"
#include "timer.h"
#include "pbb.h"

#define YAMIR_MAXBUF 1024
#define YAMIR_MSGSIZE NLMSG_SPACE(sizeof(struct yamir_msg))
#define YAMIR_MAXCTRL  128
#define YAMIR_MAXPKT 10
#define YAMIR_MAXTIMER 128

#define WBUF_SIZE (8 * 1024)
#define IPV4_ADDR(a,b,c,d) (uint32_t) (a << 24 | b << 16 | c << 8 | d)

// rfc5498 link local multicast address 224.0.0.109
//#define LL_MANET_ROUTERS IPV4_ADDR(224,0,0,109)
#define LL_MANET_ROUTERS "224.0.0.109"

// default settings from draft-ietf-manet-dymo-21.txt
#define DISCOVERY_ATTEMPTS_MAX 3
#define MSG_HOPLIMIT 10

// signal
volatile sig_atomic_t keep_running = 0;

// application state
struct yamir_state {
    // config
    char if_name[IFNAMSIZ];
    int port;
    int daemonize;
    int if_index;
    const char *log_file;

    // dymo udp
    int dymo_fd;
    uint32_t node_did;
    uint16_t own_seqnum;
    struct sockaddr_in if_addr;
    uint32_t local_addr;
    uint32_t bcast_addr;
    uint32_t mcast_addr;

    // our kernel module
    int kyamir_fd;
    int family_id;
    struct sockaddr_nl yamir_addr;

    // linux rtnetlink module
    uint32_t route_seqno;
    int route_fd;
    struct sockaddr_nl route_addr;

    // lists
    struct list_elem routes;
    struct list_elem free_routes;

    // timers
    struct timer_mgr timers;

    // recv buffers
    struct sockaddr_storage addr_pool[YAMIR_MAXPKT];
    struct mmsghdr msgs[YAMIR_MAXPKT];
    struct iovec   iovs[YAMIR_MAXPKT];
    union {
        char buf[YAMIR_MAXCTRL];
        struct cmsghdr align;
    } ctrl_pool[YAMIR_MAXPKT];
    uint8_t recv_pool[];
};

// rtnl error codes
#define RTNL_OK       0
#define RTNL_TIMEOUT  1
#define RTNL_NOPARENT 2

// DYMO message types
#define DYMO_RREQ 10
#define DYMO_RREP 11
#define DYMO_RERR 12

// dymo route state
enum dymo_rtstate  {
    DRS_NONE = 0,
    DRS_DISCOVER,
    DRS_ADDING,
    DRS_ACTIVE,
    DRS_DELETING,
    DRS_INVALID
};

struct dymo_req {
   	uint32_t addr;
   	int ifindex;
   	struct timeval timestamp;
   	int timer;
   	time_t wait_time;
   	int tries;
   	uint16_t seqnum;
   	int8_t hop_count;
};

// 4.1  DYMO route state
struct dymo_rt {
    struct list_elem node;
    void *parent;
    enum dymo_rtstate state;
    // route discovery
	struct dymo_req req;
    // flags
    unsigned int is_broken : 1;
    unsigned int has_dist  : 1;
    // active route
    uint32_t addr;
    uint8_t prefix;
    int seqnum;
    uint32_t nexthop_addr;
    uint32_t nexthop_ifindex;
    uint32_t dist;
    uint32_t nlseq;
    struct timeval timestamp;
    // timers
    int rtnl_timer;
    int age_timer;
    int seqnum_timer;
    int used_timer;
    int del_timer;
};

// all ROUTE timeouts scaled from secs to ms
#define DR_RNTL_TIMEOUT  500
#define DR_TIMEOUT         (5 * 1000)
#define DR_AGE_MIN         (1 * 1000)
#define DR_SEQNUM_AGE_MAX  (60 * 1000)
#define DR_USED_TIMEOUT    DR_TIMEOUT
#define DR_DELETE_TIMEOUT  (2 * DR_TIMEOUT)
#define DR_RREQ_WAIT_TIME  (2 * 1000)
#define UNICAST_MESSAGE_SENT_TIMEOUT (1 * 1000)

static inline bool yamir_islocaladdr(struct yamir_state *ys, struct pbb_node *mn)
{
    return ys->local_addr == mn->ip4_addr;
}

static const char *yamir_type_tostr(uint32_t type)
{
    static char *names[] = {
        [YAMIR_RT_REG]   = "RT_REG",
        [YAMIR_RT_NONE]  = "RT_NONE",
        [YAMIR_RT_NEED]  = "RT_NEED",
        [YAMIR_RT_INUSE] = "RT_INUSE",
        [YAMIR_RT_ERR]   = "RT_ERR"
    };

    return type < ARR_LEN(names) ? names[type] : "UNKNOWN";
}

static const char *rtnl_type_tostr(uint32_t type)
{
    if (type == RTM_NEWROUTE) return "RTM_NEWROUTE";
    if (type == RTM_DELROUTE) return "RTM_DELROUTE";
    return  "???";
}

#define ADDR_STRLEN INET_ADDRSTRLEN + sizeof(":65535")

static const char *sockaddr_tostr(struct sockaddr_in *sa)
{
    static char bufs[4][ADDR_STRLEN];
    static int idx;

    char *buf = bufs[idx];
    size_t len = sizeof(bufs[0]);
    idx = (idx + 1) & 3;

    char *ptr = buf;
    const char *str = inet_ntop(AF_INET, &sa->sin_addr, buf, len);
    if (!str) return "???";

    int nw = strlen(str);
    len -= nw;
    ptr += nw;
    snprintf(ptr, len, ":%d", ntohs(sa->sin_port));

    return buf;
}

static inline const char *addr_tostr(uint32_t addr)
{
    return pbb_addr_tostr(4, (void *) &addr);
}

static const char *route_tostr(struct dymo_rt *dr)
{
    static char bufs[4][128];
    static int idx;

    char *buf = bufs[idx];
    size_t size = sizeof(bufs[0]);
    idx = (idx + 1) & 3;

    if (!dr) return "<none>";

    snprintf(buf, size,
        "addr=%s/%d gwaddr=%s gwifindex=%u seqnum=%d dist=%u",
        addr_tostr(dr->addr), dr->prefix,
        addr_tostr(dr->nexthop_addr), dr->nexthop_ifindex,
        dr->seqnum, dr->dist);

    return buf;
}

static const char *dymo_msg_tostr(struct pbb_msg *msg)
{
    static char bufs[4][256];
    static int idx;

    char *str = bufs[idx];
    size_t len = sizeof(bufs[0]);
    idx = (idx + 1) & 3;

    if (!msg) return "<none>";

    struct pkt_buf buf = PKT_BUF_INIT(str, len);

    pkt_buf_printf(&buf,
        "type=%s flags=0x%x hlim=%d did=%u nodes=%d tlvs=%d taddr=[%s] oaddr=[%s]",
        pbb_type_tostr(msg->type), msg->flags, msg->hop_limit, msg->did,
        msg->num_node, msg->num_tlv,
        pbb_node_tostr(msg->target, msg->addr_len),
        pbb_node_tostr(msg->origin, msg->addr_len));

    return str;
}

struct recv_state {
    uint32_t saddr;
    uint32_t maddr;
    uint32_t daddr;
    uint32_t ifindex;
};

static const char *recv_state_tostr(struct recv_state *rs)
{
    static char bufs[4][128];
    static int idx;

    char *str = bufs[idx];
    size_t len = sizeof(bufs[0]);
    idx = (idx + 1) & 3;

    if (!rs) return "<none>";

    struct pkt_buf buf = PKT_BUF_INIT(str, len);

    pkt_buf_printf(&buf,
        "saddr=%s daddr=%s ifidx=%u",
        addr_tostr(rs->saddr),
        addr_tostr(rs->daddr),
        rs->ifindex);

    return str;
}

static struct dymo_req *route_findreq(struct yamir_state *ys, uint32_t addr);
static void dymo_end_req(struct dymo_req *req, int rc);
static int kyamir_send_msg(struct yamir_state *ys, int type, struct yamir_msg *msg, uint32_t *seq);
static int rtnl_send_msg(struct yamir_state *ys, int type, struct dymo_rt *dr);

// stevens page 533 // see ip 7 IP_PKTINFO
static int recvfrom_wstate(int fd, size_t vlen,
    struct mmsghdr msgs[static vlen],
    struct recv_state *states)
{
    log_debug("fd=%d", fd);

    int nr = recvmmsg(fd, msgs, vlen, MSG_DONTWAIT, NULL);
    if (nr == -1 || !states) return nr;

    // retrieve ancillary data for each packet
    for (int i = 0; i < nr; i++) {

        struct msghdr *m = &msgs[i].msg_hdr;
        struct recv_state *rs = &states[i];
        struct sockaddr_in *sin = m->msg_name;

        rs->saddr = sin->sin_addr.s_addr;
        rs->ifindex = 0;
        rs->maddr = 0;
        rs->daddr = 0;

        log_debug("msg=%d flags=0x%0x clen=%zu", i, (uint32_t) m->msg_flags, m->msg_controllen);

        if (m->msg_flags & MSG_CTRUNC) continue;
        if (m->msg_controllen < sizeof(struct cmsghdr)) continue;

        for (struct cmsghdr *cm = CMSG_FIRSTHDR(m); cm; cm = CMSG_NXTHDR(m, cm)) {
            if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_PKTINFO) {
                struct in_pktinfo *pi = (struct in_pktinfo *) CMSG_DATA(cm);
                rs->ifindex = pi->ipi_ifindex;
                rs->maddr = pi->ipi_spec_dst.s_addr;
                rs->daddr = pi->ipi_addr.s_addr;
            }
        }
    }

    return nr;
}

static int netlink_send(int fd, void *data, size_t len)
{
    log_debug("fd=%d len=%zu", fd, len);

    struct iovec iov = { .iov_base = data, .iov_len =  len };
    struct sockaddr_nl nl_dst = { .nl_family = AF_NETLINK };

    struct msghdr mh = {
        .msg_name    = &nl_dst,
        .msg_namelen = sizeof(nl_dst),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    // send msg to kernel
    ssize_t nsent = sendmsg(fd, &mh, 0);
    if (nsent == -1) return log_errno_rf("rnetlink_send");

    return 0;
}

static void catch_signal(int signo, siginfo_t *info, void *ucontext)
{
    (void) ucontext;
    keep_running = 0;
}


// find entry with longest prefix matching (rfc1812)
static struct dymo_rt *route_match(struct yamir_state *ys, uint32_t addr)
{
    struct dymo_rt *match = NULL;
    struct dymo_rt *dr;

    log_debug("addr=%s", addr_tostr(addr));

    addr = ntohl(addr);

    list_fornext_entry(&ys->routes, dr, node) {
        if (dr->state == DRS_DISCOVER) continue;
        if (!match || dr->prefix > match->prefix) {
            uint32_t mask = (dr->prefix == 0) ? 0 : (~0U << (32 - dr->prefix));
            uint32_t raddr = ntohl(dr->addr);
            if ((addr & mask) == (raddr & mask)) {
                match = dr;
            }
        }
    }

    log_debug("match=%s", route_tostr(match));

    return match;
}

static struct dymo_rt *route_nlseq_find(struct yamir_state *ys, uint32_t nlseq)
{
    log_debug("nlseq=%u", nlseq);

    struct dymo_rt *dr;

    // replace with hashmap  ?
    list_fornext_entry(&ys->routes, dr, node) {
        bool is_rtnl = dr->state == DRS_DISCOVER || dr->state == DRS_ADDING || dr->state == DRS_DELETING;
        if (is_rtnl && dr->nlseq == nlseq) return dr;
    }

    return NULL;
}

static struct dymo_req *route_findreq(struct yamir_state *ys, uint32_t addr)
{
    log_debug("addr=%s", addr_tostr(addr));

    struct dymo_rt *dr;

    // replace with hashmap ?
    list_fornext_entry(&ys->routes, dr, node) {
        if (dr->state == DRS_DISCOVER && dr->req.addr == addr) {
            return &dr->req;
        }
    }

    return NULL;
}

// section 5.2.1.
static int node_superior(struct pbb_node *mn, struct dymo_rt *dr, int msg_type)
{
    // 1. stale (what's wrong with signed 32 bit)
    if ((int16_t) mn->seqnum - (int16_t) dr->seqnum < 0) {
        return 0;
    }

    // 2. loop possible
    if (mn->seqnum == dr->seqnum &&
       (!pbb_node_dist(mn) || !dr->has_dist || (mn->dist > dr->dist + 1)))
    {
        return 0;
    }

    // 3. inferior or equivalent
    if (mn->seqnum == dr->seqnum &&
       (((mn->dist == dr->dist + 1) && !dr->is_broken) ||
       (mn->dist == dr->dist && msg_type == DYMO_RREQ && !dr->is_broken)))
    {
        return 0;
    }

    return 1;
}

static void route_delete(struct dymo_rt *dr);
static void rtnl_send_done(struct dymo_rt *dr, int rc);

static void rtnl_timeout_cb(void *arg)
{
    struct dymo_rt *dr = arg;

    log_debug("timeout seq=%u", dr->nlseq);

    dr->rtnl_timer = -1;
    rtnl_send_done(dr, RTNL_TIMEOUT);
}

static inline void stop_rtnl_timer(struct dymo_rt *dr)
{
    if (dr->rtnl_timer == -1) return;

    log_debug("Stopping timer seq=%u", dr->nlseq);

    struct yamir_state *ys = dr->parent;
    timer_cancel(&ys->timers, dr->rtnl_timer);
    dr->rtnl_timer = -1;
}

static void start_rtnl_timer(struct dymo_rt *dr)
{
    if (dr->rtnl_timer != -1) return;

    log_debug("Starting timer seq=%u", dr->nlseq);

    struct yamir_state *ys = dr->parent;

    dr->rtnl_timer = timer_add(&ys->timers,
        DR_RNTL_TIMEOUT,
        rtnl_timeout_cb,
        dr);
}

static void delete_timeout_cb(void *arg)
{
    struct dymo_rt *dr = arg;

    log_debug("delete timeout");

    dr->del_timer = -1;
    route_delete(dr);
}

static inline void stop_delete_timer(struct dymo_rt *dr)
{
    if (dr->del_timer == -1) return;

    struct yamir_state *ys = dr->parent;

    timer_cancel(&ys->timers, dr->del_timer);
    dr->del_timer = -1;
}

static void start_delete_timer(struct dymo_rt *dr)
{
    if (dr->del_timer != -1) return;

    log_debug("Starting delete timer");

    struct yamir_state *ys = dr->parent;

    dr->del_timer = timer_add(&ys->timers,
        DR_DELETE_TIMEOUT,
        delete_timeout_cb,
        dr);
}

// spec says its safe to delete after age timer expired
// but it make sense to allow start a delete timer
// similar to a route used logic
static void age_timeout_cb(void *arg)
{
    struct dymo_rt *dr = arg;

    log_debug("age timeout");

    dr->age_timer = -1;
    start_delete_timer(dr);
}

static inline void stop_age_timer(struct dymo_rt *dr)
{
    if (dr->age_timer == -1) return;

    struct yamir_state *ys = dr->parent;
    timer_cancel(&ys->timers, dr->age_timer);
    dr->age_timer = -1;
}

static void seqnum_timeout_cb(void *arg)
{
    struct dymo_rt *dr = arg;

    log_debug("seqnum timeout");

    dr->seqnum_timer = -1;
    dr->seqnum = 0;
}

static inline void stop_seqnum_timer(struct dymo_rt *dr)
{
    if (dr->seqnum_timer == -1) return;

    struct yamir_state *ys = dr->parent;
    timer_cancel(&ys->timers, dr->seqnum_timer);
    dr->seqnum_timer = -1;
}

static inline void stop_used_timer(struct dymo_rt *dr)
{
    if (dr->used_timer == -1) return;

    struct yamir_state *ys = dr->parent;
    timer_cancel(&ys->timers, dr->used_timer);
    dr->used_timer = -1 ;
}

// 5.2.3.3.
static void used_timeout_cb(void *arg)
{
    struct dymo_rt *dr = arg;

    dr->used_timer = -1;
    start_delete_timer(dr);
}

static void route_stop_timers(struct dymo_rt *dr)
{
    log_debug("Stopping timers");

    stop_rtnl_timer(dr);
    stop_delete_timer(dr);
    stop_seqnum_timer(dr);
    stop_used_timer(dr);
    stop_age_timer(dr);
}


/*
 * Send a netlink route delete message
 * note send delete to kyamir only if requested (don't drop packets)
 */
static void route_send_del(struct dymo_rt *dr)
{
    dr->state = DRS_DELETING;
    int rc = rtnl_send_msg(dr->parent, RTM_DELROUTE, dr);
    if (rc) rtnl_send_done(dr, rc);
}

static int route_send_add(struct dymo_rt *dr)
{
    dr->state = DRS_ADDING;
    int rc = rtnl_send_msg(dr->parent, RTM_NEWROUTE, dr);
    if (rc) {
        // send failed
        rtnl_send_done(dr, rc);
        return rc;
    }

    // update in progress
    return 0;
}

static void route_done(struct dymo_rt *dr)
{
    log_debug("state=%u", dr->state);

    list_remove(&dr->node);

    struct yamir_state *ys = dr->parent;
    if (!ys) {
        free(dr);
        return;
    }

    list_append(&ys->free_routes, &dr->node);
}

static void route_delete(struct dymo_rt *dr)
{
    route_stop_timers(dr);
    route_send_del(dr);
}

static struct dymo_rt *route_create(struct yamir_state *ys)
{
    struct dymo_rt *dr;

    dr = list_first(&ys->free_routes, struct dymo_rt, node);

    if (!dr) {
        // add new entry
        dr = malloc(sizeof(*dr));
        if (!dr) return NULL;
        list_init(&dr->node);
    }

    list_remove(&dr->node);
    memset(dr, 0, sizeof(*dr));
    dr->parent = ys;

    dr->rtnl_timer = -1;
    dr->age_timer = -1;
    dr->seqnum_timer = -1;
    dr->used_timer = -1;
    dr->del_timer = -1;

    list_append(&ys->routes, &dr->node);

    return dr;
}

static void rtnl_send_done(struct dymo_rt *dr, int rc)
{
    log_debug("state=%u nlseq=%u rc=%d", dr->state, dr->nlseq, rc);

    stop_rtnl_timer(dr);

    switch(dr->state) {
    case DRS_NONE:
        break;

    case DRS_DISCOVER: 
        // reused by YAMIR_RT_REG
        if (rc == 0) {
            log_info("+", "Registered netlink pid %d with kyamir ", getpid());
        }
        route_done(dr);
        break;

    case DRS_ADDING:
        if (rc != 0) {
            // add failed - discard
            route_delete(dr);
            break;
        }
        log_info("+", "Added route %s", route_tostr(dr));
        dr->state = DRS_ACTIVE;
        break;

    case DRS_ACTIVE:
        break;

    case DRS_DELETING:
        dr->state = DRS_INVALID;
        if (rc == 0) {
            log_info("+", "Deleted route %s", route_tostr(dr));
        }
        if (dr->is_broken) {
            start_delete_timer(dr);
        }
        else {
            route_done(dr);
        }
        break;

    case DRS_INVALID:
        break;
    }
}

// create or update route
static bool route_update(struct yamir_state *ys,
    int msg_type, struct pbb_node *mn,
    uint32_t nexthop_addr, uint32_t nexthop_ifindex)
{
    log_debug("type=%d mnaddr=%s gwaddr=%s gwifindex=%u",
        msg_type, addr_tostr(mn->ip4_addr),
        addr_tostr(nexthop_addr), nexthop_ifindex);

    struct dymo_rt *dr = route_match(ys, mn->ip4_addr);

    if (dr && !node_superior(mn, dr, msg_type)) return false;

    if (dr) {
        route_stop_timers(dr);
    }
    else {
        dr = route_create(ys);
    }

    // update entry 5.2.2
    gettimeofday(&dr->timestamp, NULL);
    dr->addr = mn->ip4_addr;

    // always set prefix field
    dr->prefix = mn->prefix;
    if (pbb_node_seqn(mn)) dr->seqnum = mn->seqnum;
    dr->nexthop_addr = nexthop_addr;
    dr->nexthop_ifindex = nexthop_ifindex;
    dr->is_broken  = 0;

    // route is consider superior so always set the distance
    dr->has_dist = 0;
    if (pbb_node_dist(mn)) {
        dr->has_dist = 1;
        dr->dist = mn->dist;
    }

    int rc = route_send_add(dr);
    if (rc) return false;

    // restart route timers
    dr->age_timer = timer_add(&ys->timers, DR_AGE_MIN, age_timeout_cb, dr);
    dr->seqnum_timer = timer_add(&ys->timers, DR_SEQNUM_AGE_MAX, seqnum_timeout_cb, dr);

    return true;
}

static void yamir_inc_seqnum(struct yamir_state *ys)
{
    if (ys->own_seqnum >= 0xFFFF) {
        ys->own_seqnum = 0;
    }

    ys->own_seqnum++;
}

static int dymo_send_msg(struct yamir_state *ys, struct pbb_msg *msg, uint32_t addr)
{
    static unsigned char wbuf[WBUF_SIZE];

    log_debug("dst=%s msg=(%s)", addr_tostr(addr), dymo_msg_tostr(msg));

    struct pkt_buf buf = PKT_BUF_INIT(wbuf, sizeof(wbuf));
    struct pbb_hdr hdr = { 0 };

    // encode pkt
    if (pkt_buf_hdr_enc(&buf, &hdr)) return log_error_rf("enc_hdr failed");
    if (pkt_buf_msg_enc(&buf, msg))  return log_error_rf("enc_msg failed");

    // TODO implement rfc5148 jitter

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(addr));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = addr;
    sin.sin_port = htons(DYMO_PORT);
    size_t len = pkt_buf_pos(&buf);

    log_debug("sendto pkt_len=%zu dst=%s", len, sockaddr_tostr(&sin));

    ssize_t rc = sendto(ys->dymo_fd, wbuf, len, 0, (struct sockaddr *) &sin, sizeof(sin));
    if (rc == -1) return log_errno_rf("send_msg");

    return 0;
}

// 5.3.2 (send reply back to request originator)
static int dymo_send_reply(struct yamir_state *ys, struct pbb_msg *req)
{
    log_debug("req=(%s)", dymo_msg_tostr(req));

    struct pbb_msg reply;

    pbb_msg_reset(&reply);

    reply.type = DYMO_RREP;

    // TODO get these values from routing table ?
    reply.target = pbb_copy_node(&reply, req->origin);
    reply.origin = pbb_copy_node(&reply, req->target);

    struct dymo_rt *dr = route_match(ys, reply.target->ip4_addr);
    if (!dr) return log_error_rf("No route to target");

    if (!pbb_node_seqn(reply.target) ||
        ((int16_t) reply.target->seqnum - (int16_t) ys->own_seqnum < 0) ||
        (reply.target->seqnum == ys->own_seqnum && !pbb_node_dist(reply.origin)))
    {
        yamir_inc_seqnum(ys);
    }

    reply.origin->seqnum = ys->own_seqnum;
    reply.origin->flags |= PBB_NF_SEQN;

    reply.hop_limit = MSG_HOPLIMIT;
    reply.flags |= PBB_MF_HLIM;
    reply.addr_len = 4;

    // we route the message via the next hop
    return dymo_send_msg(ys, &reply, dr->nexthop_addr);
}

static int dymo_recv_reply(struct yamir_state *ys, struct pbb_msg *reply)
{
    log_debug("reply=(%s)", dymo_msg_tostr(reply));

    struct dymo_req *req;

    req = route_findreq(ys, reply->origin->ip4_addr);
    if (req) dymo_end_req(req, 0);

    return 0;
}

// multihop-capbable unicast address (todo add prefix/if mask)
static bool is_unicast(uint32_t addr)
{
    uint32_t tmp_addr = ntohl(addr);

    // broadcast address 255.255.255.255
    if (tmp_addr == 0xF0000000) return false;

    // class D multicast address 224.0.0.0 - 239.255.255.255 (fb=0xE0.0xEF)
    if ((tmp_addr & 0xF0000000) == 0xE0000000) return false;

    return true;
}

// increment node distaince
static bool inc_node_dist(struct pbb_node *mn)
{
    if (pbb_node_dist(mn)) {
        if (mn->dist >= 0xFFFF) return false;
        mn->dist++;
    }

    return true;
}

// decrement hop limit
static bool dec_hop_limit(struct pbb_msg *msg)
{
    if (pbb_msg_hlim(msg)) {
        if (msg->hop_limit == 0) return false;
        msg->hop_limit--;
        if (msg->hop_limit == 0) return false;
    }

    return true;
}

// 5.5.3 rm message or data packet cannot be routed to addr
// TODO add unicast support
static int dymo_rerr_send(struct yamir_state *ys, uint32_t addr, uint16_t seqnum, uint8_t prefix)
{
    log_debug("addr=%s/%d seqnum=%d", addr_tostr(addr), prefix, seqnum);

    struct pbb_msg rerr;

    pbb_msg_reset(&rerr);

    rerr.type = DYMO_RERR;
    rerr.hop_limit = MSG_HOPLIMIT;
    rerr.flags |= PBB_MF_HLIM;

    struct pbb_node *unreach = pbb_add_node(&rerr);
    if (!unreach) return log_error_rf("Add unreach failed");

    unreach->ip4_addr = addr;
    if (seqnum > 0) {
        unreach->flags |= PBB_NF_SEQN;
        unreach->seqnum = seqnum;
    }
    if (prefix > 0) {
        unreach->flags |= PBB_NF_PREF;
        unreach->prefix = prefix;
    }

    return dymo_send_msg(ys, &rerr, ys->mcast_addr);
}

// 5.3.4 page 24 relay route-message
static int relay_rmsg(struct yamir_state *ys, struct pbb_msg *rmsg, struct recv_state *rs)
{
    log_debug("rs=(%s) msg(%s)", recv_state_tostr(rs), dymo_msg_tostr(rmsg));

    // append additional routing info

    // distance checks
    if (!inc_node_dist(rmsg->origin)) return 0;

    for (int i = 0; i < rmsg->num_node; i++) {
        struct pbb_node *mn = &rmsg->nodes[i];
        if (!inc_node_dist(mn)) {
            mn->flags |= PBB_NF_SKIP;
        }
    }

    // check if must discard
    if (!dec_hop_limit(rmsg)) return 0;

    // replies or unicast requests always sent via next hop addr
    uint32_t dst_addr;
    if (rmsg->type == DYMO_RREP || is_unicast(rs->daddr)) {
        // need check if rm can be routed towards target
        struct pbb_node *target = rmsg->target;
        struct dymo_rt *dr = route_match(ys, target->ip4_addr);
        if (!dr) return dymo_rerr_send(ys, target->ip4_addr, target->seqnum, target->prefix);
        if (dr->is_broken) return dymo_rerr_send(ys, target->ip4_addr, dr->seqnum, target->prefix);
        dst_addr = dr->nexthop_addr;
    }
    else {
        dst_addr = ys->mcast_addr;
    }

    return dymo_send_msg(ys, rmsg, dst_addr);
}

// check valid route-message
static int validate_msg(struct yamir_state *ys, struct pbb_msg *msg)
{
    // check required fields present
    if (!pbb_msg_hlim(msg)) return PBB_MSG_HLIM;
    if (!msg->target) return PBB_MSG_TNODE;
    if (!msg->origin) return PBB_MSG_ONODE;
    if (!pbb_node_seqn(msg->origin)) return PBB_MSG_OSEQN;
    if (msg->did != ys->node_did) return PBB_MSG_TLV_DID;
    if (yamir_islocaladdr(ys, msg->origin)) return PBB_MSG_OLADDR;

    return 0;
}

// fixup target,origin nodes
static int fixup_nodes(struct pbb_msg *msg)
{
    int skip = 0;

    if (msg->num_node > 0) {
        msg->target = &msg->nodes[0];
        skip++;
    }

    if (msg->num_node > 1) {
        msg->origin = &msg->nodes[1];
        skip++;
    }

    return skip;
}

static int handle_rreq(struct yamir_state *ys, struct pbb_msg *rreq, struct recv_state *rs)
{
    int skip = fixup_nodes(rreq);
    log_debug("rs=(%s) msg(%s)", recv_state_tostr(rs), dymo_msg_tostr(rreq));

    // check required fields present
    int rc = validate_msg(ys, rreq);
    if (rc) return log_debug_rc(rc, "invalid msg %s", pbb_field_tostr(rc));

    int orig_superior = route_update(ys, rreq->type, rreq->origin, rs->saddr, rs->ifindex);

    // additional nodes
    for (int i = skip; i < rreq->num_node; i++) {
        struct pbb_node *mn = &rreq->nodes[i];
        if (!route_update(ys, rreq->type, mn, rs->saddr, rs->ifindex)) {
            mn->flags |= PBB_NF_SKIP;
            log_debug("invalid-route node %d", i);
        }
    }

    if (!orig_superior) return 0;

    // relay request-msg if not for us
    if (!yamir_islocaladdr(ys, rreq->target)) {
        return relay_rmsg(ys, rreq, rs);
    }

    // request is for us
    return dymo_send_reply(ys, rreq);
}

static int handle_rrep(struct yamir_state *ys, struct pbb_msg *rrep, struct recv_state *rs)
{
    int skip = fixup_nodes(rrep);
    log_debug("rs=(%s) msg(%s)", recv_state_tostr(rs), dymo_msg_tostr(rrep));

    // check required fields present
    int rc = validate_msg(ys, rrep);
    if (rc) return log_debug_rc(rc, "invalid msg %s", pbb_field_tostr(rc));

    bool orig_superior = route_update(ys, rrep->type, rrep->origin, rs->saddr, rs->ifindex);

    // additional nodes
    for (int i = skip; i < rrep->num_node; i++) {
        struct pbb_node *mn = &rrep->nodes[i];
        if (!route_update(ys, rrep->type, mn, rs->saddr, rs->ifindex)) {
            mn->flags |= PBB_NF_SKIP;
            log_debug("invalid-route node %i", i);
        }
    }

    if (!orig_superior) return 0;

    // relay reply-msg if not for us
    if (!yamir_islocaladdr(ys, rrep->target)) {
        return relay_rmsg(ys, rrep, rs);
    }

    // reply is for us
    return dymo_recv_reply(ys, rrep);
}

// RERR handling page 28
static bool route_broken(struct yamir_state *ys, struct pbb_node *mn, uint32_t sender)
{
    if (!is_unicast(mn->ip4_addr)) return 0;

    struct dymo_rt *dr = route_match(ys, mn->ip4_addr);
    if (!dr) return false;

    if (!dr->is_broken &&
        (dr->nexthop_addr == sender &&
        (dr->seqnum == 0 || mn->seqnum == 0
         || !pbb_node_seqn(mn)
         || ((int16_t) dr->seqnum - (int16_t) mn->seqnum  <= 0))))
    {
        dr->is_broken = 1;
        route_send_del(dr);
        return true;
    }

    return false;
}

static int validate_rerr(struct yamir_state *s, struct pbb_msg *rerr)
{
    if (!pbb_msg_hlim(rerr)) return PBB_MSG_HLIM;
    if (rerr->num_node == 0) return PBB_NODE_UNREACH;
    if (rerr->did != s->node_did) return PBB_MSG_TLV_DID;

    return 0;
}

static int handle_rerr(struct yamir_state *ys, struct pbb_msg *rerr, struct recv_state *rs)
{
    log_debug("rs=(%s) msg(%s)", recv_state_tostr(rs), dymo_msg_tostr(rerr));

    // check required fields present
    int rc = validate_rerr(ys, rerr);
    if (rc) return log_debug_rc(rc, "invalid msg %s", pbb_field_tostr(rc));

    // need to scan our routes
    int num_skip = 0;
    for (int i = 0; i < rerr->num_node; i++) {
        struct pbb_node *mn = &rerr->nodes[i];
        if (!route_broken(ys, mn, rs->saddr)) {
            num_skip++;
            mn->flags |= PBB_NF_SKIP;
            log_debug("valid-route node %d", i);
        }
    }

    // discard if no unreachable nodes left
    if (num_skip == rerr->num_node) {
        log_debug("zero-nodes skip=%d nodes=%d", num_skip, rerr->num_node);
        return 0;
    }

    // discard if hop limit reached
    if (!dec_hop_limit(rerr)) {
        log_debug("zero hlimit %d", rerr->hop_limit);
        return 0;
    }

    // relay rerr
    // not sure what standard means by here by NextHopAddress
    // for unicast RERR is this the nexthopaddress for the unreachable node
    // or the actual ip destiation address (what happens if there are more
    // than 1 unreachable node in the RERR packet ?
    return dymo_send_msg(ys, rerr, ys->mcast_addr);
}

static void dymo_req_timeout(void *arg);

static void dymo_end_req(struct dymo_req *req, int rc)
{
    log_debug("addr=%s rc=%d", addr_tostr(req->addr), rc);

    struct dymo_rt *dr = containerof(req, struct dymo_rt, req);

    if (req->timer != -1) {
        struct yamir_state *ys = dr->parent;
        if (ys) timer_cancel(&ys->timers, req->timer);
        req->timer = -1;
    }

    if (rc) {
        // route discovery failed
        struct yamir_msg msg = { req->addr, req->ifindex };
        rc = kyamir_send_msg(dr->parent, YAMIR_RT_NONE, &msg, &dr->nlseq);
    }

    if (rc) route_done(dr);
}

static int dymo_send_request(struct yamir_state *ys, struct dymo_req *req)
{
    log_debug("addr=%s seqnum=%u hcount=%d hlimit=%d",
        addr_tostr(req->addr), req->seqnum, req->hop_count, MSG_HOPLIMIT);

    struct pbb_msg msg;
    pbb_msg_reset(&msg);

    // TODO set hoplimit using ring search RFC3561
    msg.type = DYMO_RREQ;
    msg.hop_limit = MSG_HOPLIMIT;
    msg.flags |= PBB_MF_HLIM;
    msg.addr_len = 4;

    yamir_inc_seqnum(ys);

    // add target
    struct pbb_node *target = pbb_add_node(&msg);
    if (!target) return log_error_rf("Add target failed");
    msg.target = target;
    target->ip4_addr = req->addr;
    if (req->seqnum) {
        target->flags |= PBB_NF_SEQN;
        target->seqnum = req->seqnum;
    }
    if (req->hop_count) {
        target->flags |= PBB_NF_DIST;
        target->dist = req->hop_count;
    }

    // add origin
    struct pbb_node *origin = pbb_add_node(&msg);
    if (!origin) return log_error_rf("Add origin failed");
    msg.origin = origin;
    origin->ip4_addr = ys->local_addr;
    origin->flags |= PBB_NF_SEQN;
    origin->seqnum = ys->own_seqnum;

    int ec = dymo_send_msg(ys, &msg, ys->mcast_addr);
    if (ec) return ec;

    // wait for response
    req->timer = timer_add(&ys->timers, req->wait_time, dymo_req_timeout, req);
    return 0;
}


// send request out for route
static int dymo_out_req(struct dymo_req *req)
{
    log_debug("%s attempt %d/%d wait %ld",
        addr_tostr(req->addr),
        req->tries,
        DISCOVERY_ATTEMPTS_MAX,
        req->wait_time);

    struct dymo_rt *dr = containerof(req, struct dymo_rt, req);
    struct dymo_rt *info = route_match(dr->parent, req->addr);

    if (info) {
        // have info about the target
        req->seqnum    = info->seqnum;
        req->hop_count = info->dist;
    }
    else {
        req->seqnum = 0;
        req->hop_count = 0;
    }

    // try again
    return dymo_send_request(dr->parent, req);
}

static void dymo_req_timeout(void *arg)
{
    struct dymo_req *req = arg;

    req->timer = -1;

    log_debug("%s timeout %d/%d", addr_tostr(req->addr), req->tries, DISCOVERY_ATTEMPTS_MAX);

    int ec = -1;

    if (req->tries < DISCOVERY_ATTEMPTS_MAX) {
        // try again
        req->tries += 1;
        req->wait_time = req->wait_time * 2;
        ec = dymo_out_req(req);
        if (!ec) return;
    }

    dymo_end_req(req, ec);
}

static void route_discover(struct yamir_state *ys, struct yamir_msg *msg)
{
    log_debug("addr=%s ifindex=%d", addr_tostr(msg->ip4_addr), msg->ifindex);

    struct dymo_req *req = route_findreq(ys, msg->ip4_addr);
    if (req) {
        log_debug("req already in progress");
        return;
    }

    struct dymo_rt *dr = route_create(ys);
    if (!dr) return log_errno_rv("route_create failed");

    req = &dr->req;  
    req->addr = msg->ip4_addr;
    req->ifindex = msg->ifindex;
    req->tries = 1;
    req->wait_time = DR_RREQ_WAIT_TIME;
    gettimeofday(&req->timestamp, NULL);

    // start discovery
	dr->state = DRS_DISCOVER;
    int ec = dymo_out_req(req);
    if (ec) dymo_end_req(req, ec);

}

// section 5.5.2
static void route_inuse(struct yamir_state *ys, struct yamir_msg *msg)
{
    log_debug("addr=%s ifindex=%d", addr_tostr(msg->ip4_addr), msg->ifindex);

    struct dymo_rt *dr = route_match(ys, msg->ip4_addr);
    if (!dr) return;

    // can't attend to a broken route
    if (dr->is_broken) {
        log_debug("route_update(%s:%u) route is broken", addr_tostr(dr->addr), dr->state);
        return;
    }

    stop_delete_timer(dr);
    stop_used_timer(dr);
    stop_age_timer(dr);

    // restart used timer
    dr->used_timer = timer_add(&ys->timers, DR_USED_TIMEOUT, used_timeout_cb, dr);
}

// section 5.5 a data packet to be forwarded has no route
static void route_err(struct yamir_state *ys, struct yamir_msg *msg)
{
    log_debug("addr=%s ifindex=%d", addr_tostr(msg->ip4_addr), msg->ifindex);

    struct dymo_rt *dr = route_match(ys, msg->ip4_addr);

    // normal case - no forwarding route
    if (!dr) {
        dymo_rerr_send(ys, msg->ip4_addr, 0, 0);
        return;
    }

    // did kernel lose route ?
    if (!dr->is_broken) {
        log_error("Not broken %s", route_tostr(dr));
        if (dr->state == DRS_ACTIVE) {
            route_send_add(dr);
        }
        return;
    }

    // draft says we should use seqnum if we have one
    dymo_rerr_send(ys, msg->ip4_addr, dr->seqnum, 0);
}


// process incoming dymo message packet
static int dymo_process_mmsg(struct yamir_state *ys,
    struct mmsghdr *mmsg, struct recv_state *rs)
{
    uint8_t *pkt = mmsg->msg_hdr.msg_iov->iov_base;
    size_t len = mmsg->msg_len;

    log_debug("recv %zu bytes src=%s dst=%s ifindex=%u",
        len, addr_tostr(rs->saddr), addr_tostr(rs->daddr), rs->ifindex);

    // check if we are the sender
    if (rs->saddr == ys->local_addr) {
        log_debug("saddr %s is local - will drop", addr_tostr(rs->saddr));
        return 0;
    }

    // decode pkt data - until zero or error
    struct pkt_buf buf = PKT_BUF_INIT(pkt, len);
    struct pbb_hdr hdr;

    int ec = pkt_buf_hdr_dec(&buf, &hdr);
    if (ec) return ec;

    while (pkt_buf_rem(&buf)) {
        struct pbb_msg msg;
        ec = pkt_buf_msg_dec(&buf, &msg);
        if (ec) continue;
        switch(msg.type) {
        case DYMO_RREQ: handle_rreq(ys, &msg, rs); break;
        case DYMO_RREP: handle_rrep(ys, &msg, rs); break;
        case DYMO_RERR: handle_rerr(ys, &msg, rs); break;
        default: log_debug("Unknown type %d\n", msg.type);
        }
    }

    return 0;
}

// recv dymo messages
static int dymo_recv(struct yamir_state *ys)
{
    struct recv_state states[YAMIR_MAXPKT];

    for (size_t i = 0; i < YAMIR_MAXPKT; i++) {
        ys->msgs[i].msg_hdr.msg_controllen = sizeof(ys->ctrl_pool[i].buf);
    }
    int nr = recvfrom_wstate(ys->dymo_fd, YAMIR_MAXPKT, ys->msgs, states);
    if (nr < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
        return log_errno_rf("recvfrom_wstate failed");
    }

    for (int i = 0; i < nr; i++) {
        dymo_process_mmsg(ys, &ys->msgs[i], &states[i]);
    }

    return 0;
}

// send msg to kyamir
static int kyamir_send_msg(struct yamir_state *ys, int type, struct yamir_msg *msg, uint32_t *seq)
{
    if (!ys) return 0;

    log_debug("family_id=%d type=%s addr=%s ifindex=%d",
        ys->family_id,
        yamir_type_tostr(type), addr_tostr(msg->ip4_addr), msg->ifindex);

    struct genl_request req = { 0 };
    struct nlmsghdr *nlh = &req.n;
    nlh->nlmsg_len   = NLMSG_SPACE(GENL_HDRLEN);
    nlh->nlmsg_type  = ys->family_id;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_pid   = getpid();
    nlh->nlmsg_seq   = ys->route_seqno++;

    // setup our message
    req.g.cmd = type;
    req.g.version = 1;

    struct nlattr *nla;

    // add ip4_addr attr
    nla = mkptr(&req, NLMSG_SPACE(GENL_HDRLEN));
    nla->nla_type = YAMIR_ATTR_IP4ADDR;
    nla->nla_len = sizeof(uint32_t) + NLA_HDRLEN;
    memcpy(mkptr(nla, NLA_HDRLEN), &msg->ip4_addr, sizeof(uint32_t));
    nlh->nlmsg_len += NLMSG_ALIGN(nla->nla_len);

    // add if_index attr
    nla = mkptr(&req, nlh->nlmsg_len);
    nla->nla_type = YAMIR_ATTR_IFINDEX;
    nla->nla_len = sizeof(int32_t) + NLA_HDRLEN;
    memcpy(mkptr(nla, NLA_HDRLEN), &msg->ifindex, sizeof(int32_t));
    nlh->nlmsg_len += NLMSG_ALIGN(nla->nla_len);

    int rc = netlink_send(ys->kyamir_fd, &req, nlh->nlmsg_len);
    if (rc) return rc;

    // message sent
    *seq = nlh->nlmsg_seq;
    return 0;
}

// process yamir_msg from kyamir
static void kyamir_process_msg(struct yamir_state *ys, int type, struct yamir_msg *msg)
{
    log_debug("type=%s addr=%s ifindex=%d",
        yamir_type_tostr(type), addr_tostr(msg->ip4_addr), msg->ifindex);

    switch(type) {
    case YAMIR_RT_NEED:  route_discover(ys, msg); break;
    case YAMIR_RT_INUSE: route_inuse(ys, msg);  break;
    case YAMIR_RT_ERR:   route_err(ys, msg); break;
    default: log_debug("Unsupported type %d", type); break;
    }
}

// extract netlink attrs into msg
static bool parse_genl_attrs(struct yamir_msg *msg, struct nlmsghdr *nlh)
{
    struct genlmsghdr *gnlh = NLMSG_DATA(nlh);
    struct nlattr *nla = mkptr(gnlh, GENL_HDRLEN);
    int attr_len = nlh->nlmsg_len - NLMSG_SPACE(GENL_HDRLEN);

    while (attr_len >= (int) sizeof(struct nlattr)) {
        // joker checks
        if (nla->nla_len < sizeof(struct nlattr)) return false;
        if (nla->nla_len > attr_len) return false;

        switch (nla->nla_type) {
        case YAMIR_ATTR_IP4ADDR:
            memcpy(&msg->ip4_addr, mkptr(nla, NLA_HDRLEN), sizeof(msg->ip4_addr));
            break;
        case YAMIR_ATTR_IFINDEX:
            memcpy(&msg->ifindex, mkptr(nla, NLA_HDRLEN), sizeof(msg->ifindex));
            break;
        default:
            // Ignore unknown attributes
            break;
        }
        // move to next 4-byte aligned attribute
        int advance = NLA_ALIGN(nla->nla_len);
        attr_len -= advance;
        nla = mkptr(nla, advance);
    }

    return true;
}

static int parse_family_id(struct nlmsghdr *nlh)
{
    struct genlmsghdr *gnlh = NLMSG_DATA(nlh);
    struct nlattr *nla = mkptr(gnlh, GENL_HDRLEN);
    int attr_len = nlh->nlmsg_len - NLMSG_SPACE(GENL_HDRLEN);

    log_debug("attr_len=%d", attr_len);

    // 2. Loop through controller response attributes
    while (attr_len >= (int)sizeof(struct nlattr)) {
        // joker checks
        if (nla->nla_len < sizeof(struct nlattr)) return -1;
        if (nla->nla_len > attr_len) return -1;

        if (nla->nla_type == CTRL_ATTR_FAMILY_ID) {
            uint16_t fid;
            memcpy(&fid, mkptr(nla, NLA_HDRLEN), sizeof(fid));
            log_debug("family_id=%d", fid);
            return fid;
        }

        // move to next 4-byte aligned attribute
        int advance = NLA_ALIGN(nla->nla_len);
        attr_len -= advance;
        nla = mkptr(nla, advance);
    }

    return -1; // Not found
}

static void kyamir_handle_nlerr(struct yamir_state *ys, struct nlmsghdr *nlh)
{
   struct nlmsgerr *err = NLMSG_DATA(nlh);

   if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*err))) {
        log_debug("truncated payload %u", nlh->nlmsg_len);
        return;
   }

   log_debug("recv nl-err %d (%s)", err->error, strerror(-err->error));

   struct dymo_rt *dr = route_nlseq_find(ys, nlh->nlmsg_seq);

   if (dr) rtnl_send_done(dr, 0);
}

static void kyamir_handle_nlctrl(struct yamir_state *ys, struct nlmsghdr *nlh) 
{
    int rc = parse_family_id(nlh);

    if (rc == -1) return;
    log_info("+", "Received netlink id %d", rc);
    ys->family_id = rc;

    struct dymo_rt *dr = route_create(ys);
    if (!dr) return log_error_rv("create route");

    // register with kyamir
    dr->state = DRS_DISCOVER;
    struct yamir_msg msg = { 0 };
    rc = kyamir_send_msg(ys, YAMIR_RT_REG, &msg, &dr->nlseq);

    if (rc == 0) {
        start_rtnl_timer(dr);
        return;
    }

    rtnl_send_done(dr, rc);
}

static void kyamir_handle_nldata(struct yamir_state *ys, struct nlmsghdr *nlh) 
{
    if (nlh->nlmsg_type != ys->family_id) return;
    if (nlh->nlmsg_len < NLMSG_LENGTH(GENL_HDRLEN)) return;

    // get type
    struct genlmsghdr *gnlh = NLMSG_DATA(nlh);
    int type = gnlh->cmd;
    // get attrs
    struct yamir_msg msg = { 0 };
    if (!parse_genl_attrs(&msg, nlh)) return;

    kyamir_process_msg(ys, type, &msg);

}

// process mmsg from kyamir
static void kyamir_process_mmsg(struct yamir_state *ys, struct mmsghdr *mmsg)
{
    struct nlmsghdr *nlh = mmsg->msg_hdr.msg_iov->iov_base;
    size_t msg_len = mmsg->msg_len;

    log_debug("msg_len=%zu", msg_len);

    for (; NLMSG_OK(nlh, msg_len); nlh = NLMSG_NEXT(nlh, msg_len)) {
        log_debug("nlh_type=%u nlh_len=%u", nlh->nlmsg_type, nlh->nlmsg_len);
        switch(nlh->nlmsg_type) {
        case NLMSG_DONE: 
            msg_len = 0;
            break;
        case NLMSG_ERROR:
            kyamir_handle_nlerr(ys, nlh);
            break;
        case GENL_ID_CTRL:
            kyamir_handle_nlctrl(ys, nlh);
            break;
        default:
            kyamir_handle_nldata(ys, nlh);
            break;
        }
    }
}

// recv msgs from kyamir
static int kyamir_recv(struct yamir_state *ys)
{
    int nr = recvmmsg(ys->kyamir_fd, ys->msgs, YAMIR_MAXPKT, MSG_DONTWAIT, NULL);

    log_debug("recv kyamir_fd=%d nr=%d", ys->kyamir_fd, nr);

    if (nr < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
        return log_errno_rf("recvmmsg %d failed", ys->kyamir_fd);
    }

    for (int i = 0; i < nr; i++) {
        kyamir_process_mmsg(ys, &ys->msgs[i]);
    }

    return 0;
}

static void route_process_mmsg(struct yamir_state *ys, struct mmsghdr *mmsg)
{
    struct nlmsghdr *nlh = mmsg->msg_hdr.msg_iov->iov_base;
    size_t msg_len = mmsg->msg_len;

    log_debug("msg_len=%zu, nlh_type=%u, nlh_len=%u", msg_len, nlh->nlmsg_type, nlh->nlmsg_len);

    for (; NLMSG_OK(nlh, msg_len); nlh = NLMSG_NEXT(nlh, msg_len)) {
        log_debug("nlh_type=%u nlh_len=%u", nlh->nlmsg_type, nlh->nlmsg_len);
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            // error/ack message
            struct nlmsgerr *err = NLMSG_DATA(nlh);
            struct dymo_rt *dr = route_nlseq_find(ys, nlh->nlmsg_seq);
            log_debug("recv nl-err %d (%s)", err->error, strerror(-err->error));
            if (dr) rtnl_send_done(dr, err->error);
            continue;
        }
    }
}

// recv route msg from kernel rtnetlink
static int rtnl_recv(struct yamir_state *ys)
{
    log_debug("recv route_fd=%d", ys->route_fd);

    int nr = recvmmsg(ys->route_fd, ys->msgs, YAMIR_MAXPKT, MSG_DONTWAIT, NULL);
    log_debug("nr=%d errno=%d", nr, nr < 0 ? errno : 0);

    if (nr < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
        return log_errno_rf("recvmmsg %d failed", ys->kyamir_fd);
    }

    for (int i = 0; i < nr; i++) {
        route_process_mmsg(ys, &ys->msgs[i]);
    }

    return 0;
}

// add rta attr
static int nlh_rta_add(struct nlmsghdr *nlh, size_t maxlen,
    int type, void *data, size_t len)
{
    int rta_len = RTA_LENGTH(len);

    if (NLMSG_ALIGN(nlh->nlmsg_len) + rta_len > maxlen) {
        return log_error_rf("addattr_l %d failed", type);
    }

    struct rtattr *rta = mkptr(nlh, NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = rta_len;
    memcpy(RTA_DATA(rta), data, len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + rta_len;

    return 0;
}

/*
 * send msg to rtnetlink
 * route add dest/prefix dev if metric hop_count via nexthop_addr
 */
static int rtnl_send_msg(struct yamir_state *ys, int type, struct dymo_rt *dr)
{
    log_debug("type=%s addr=%s/%d nexthop=%s ifindex=%u dist=%u",
        rtnl_type_tostr(type), addr_tostr(dr->addr), dr->prefix,
        addr_tostr(dr->nexthop_addr), dr->nexthop_ifindex, dr->dist);

    if (!ys) return RTNL_NOPARENT;

    // TODO dynamically allocate a buffer of the correct size
    struct {
        struct nlmsghdr nlm;
        struct rtmsg rtm;
        char buf[512];
    } req;

    // setup netlink msg header
    struct nlmsghdr *nlh = &req.nlm;
    memset(nlh, 0, sizeof(*nlh));
    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlh->nlmsg_type  = type;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_pid   = getpid();
    nlh->nlmsg_seq   = ys->route_seqno++;

    if (type == RTM_NEWROUTE) {
        nlh->nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
    }
    uint32_t dst_prefix = dr->prefix;
    if (dst_prefix == 0) dst_prefix = 32;

    // setup rtnetlink msg
    struct rtmsg *rtm = &req.rtm;
    memset(rtm, 0, sizeof(*rtm));
    rtm->rtm_family   = AF_INET;
    rtm->rtm_dst_len  = dst_prefix;
    rtm->rtm_table    = RT_TABLE_MAIN;
    rtm->rtm_protocol = YAMIR_RT_PROTO;
    rtm->rtm_scope    = RT_SCOPE_LINK;
    rtm->rtm_type     = RTN_UNICAST;

    // dst, interface, metric, gateway
    nlh_rta_add(nlh, sizeof(req), RTA_DST, &dr->addr, sizeof(dr->addr));
    nlh_rta_add(nlh, sizeof(req), RTA_OIF, &dr->nexthop_ifindex, sizeof(dr->nexthop_ifindex));
    nlh_rta_add(nlh, sizeof(req), RTA_PRIORITY, &dr->dist, sizeof(dr->dist));

    if (dr->addr != dr->nexthop_addr) {
        rtm->rtm_scope = RT_SCOPE_UNIVERSE;
        nlh_rta_add(nlh, sizeof(req), RTA_GATEWAY, &dr->nexthop_addr, sizeof(dr->nexthop_addr));
    }

    int rc = netlink_send(ys->route_fd, &req, req.nlm.nlmsg_len);
    if (rc != 0) return rc;

    // message sent
    dr->nlseq = nlh->nlmsg_seq;
    start_rtnl_timer(dr);

    return 0;
}

static int resolv_netlink(int fd, const char *name)
{
    struct genl_request req = {0};

    // netlink header
    req.n.nlmsg_type = GENL_ID_CTRL;
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_seq = 1;
    req.n.nlmsg_pid = getpid();

    // request GETFAMILY
    req.g.cmd = CTRL_CMD_GETFAMILY;
    req.g.version = 1;

    // need CTRL_ATTR_FAMILY_NAME
    struct nlattr *nla = (struct nlattr *)((char *)&req + NLMSG_SPACE(GENL_HDRLEN));
    nla->nla_type = CTRL_ATTR_FAMILY_NAME;
    nla->nla_len = strlen(name) + 1 + NLA_HDRLEN;
    strcpy((char *)nla + NLA_HDRLEN, name);

    req.n.nlmsg_len = NLMSG_SPACE(GENL_HDRLEN) + NLMSG_ALIGN(nla->nla_len);

    ssize_t rc = send(fd, &req, req.n.nlmsg_len, 0);
    if (rc == -1) return -1;

    return 0;
}

// setup NETLINK interface to kyamir and linux rtnetlink
static int netlink_init(struct yamir_state *ys)
{
    log_debug("init kyamir-nl=%d route-nl=%d", NETLINK_GENERIC, NETLINK_ROUTE);

    // setup netlink interface to our kernel module
    ys->kyamir_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (ys->kyamir_fd == -1) return log_errno_rf("socket netlink_yamir");

    // bind to address
    struct sockaddr_nl *nl_addr = &ys->yamir_addr;
    nl_addr->nl_family = AF_NETLINK;
    nl_addr->nl_pid = getpid();
    nl_addr->nl_groups = 0;
    int ec = bind(ys->kyamir_fd, (struct sockaddr *) nl_addr, sizeof(*nl_addr));
    if (ec == -1) return log_errno_rf("bind netlink_yamir");

    // resolve netlink family
    ec = resolv_netlink(ys->kyamir_fd, YAMIR_NL_NAME);
    if (ec) return log_errno_rf("resolv_netlink %s", YAMIR_NL_NAME);

    // setup interface to kernel routing module
    ys->route_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (ys->route_fd == -1) return log_errno_rf("socket netlink_route");

    // bind to addr
    nl_addr = &ys->route_addr;
    nl_addr->nl_family = AF_NETLINK;
    nl_addr->nl_pid = getpid();
    nl_addr->nl_groups = 0; // TODO RTMGRP_IPV4_ROUTE
    //rtnetlink_addr.nl_groups = RTMGRP_NOTIFY | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
    ec = bind(ys->route_fd, (struct sockaddr *) nl_addr, sizeof(*nl_addr));
    if (ec == -1) return log_errno_rf("bind netlink_route");

    log_info("+", "Started netlink kyamird_fd=%d route_fd=%d", ys->kyamir_fd, ys->route_fd);

    return 0;
}

static int dymo_init(struct yamir_state *ys)
{
    log_debug("ifname=%s port=%d", ys->if_name, ys->port);

    // create the socket
    int sock_type = SOCK_DGRAM | SOCK_NONBLOCK;
    ys->dymo_fd = socket(AF_INET, sock_type, 0);
    if (ys->dymo_fd == -1) return log_errno_rf("dymo_init: socket");

    // get interface index
    struct ifreq ifreq;
    strcpy(ifreq.ifr_name, ys->if_name);
    int ec = ioctl(ys->dymo_fd, SIOCGIFINDEX, &ifreq);
    if (ec == -1) return log_errno_rf("dymo_init: i/f not found");
    ys->if_index = ifreq.ifr_ifindex;

    // interface addr
    ec = ioctl(ys->dymo_fd, SIOCGIFADDR, &ifreq);
    if (ec == -1) return log_errno_rf("dymo_init: get i/f addr");
    struct sockaddr_in *sin = (struct sockaddr_in *) &ifreq.ifr_addr;
    if (sin->sin_family != AF_INET) return log_errno_rf("dymo_init: if-addr not ipv4");
    ys->local_addr = sin->sin_addr.s_addr;

    // broadcast addr
    ec = ioctl(ys->dymo_fd, SIOCGIFBRDADDR, &ifreq);
    if (ec == -1) return log_errno_rf("dymo_init: get i/f broadcast addr");
    sin = (struct sockaddr_in *) &ifreq.ifr_broadaddr;
    if (sin->sin_family != AF_INET) return log_errno_rf("dymo_init: bc-addr not ipv4");
    ys->bcast_addr = sin->sin_addr.s_addr;

    // request meta-data on IP packets
    int on = 1;
    ec = setsockopt(ys->dymo_fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
    if (ec == -1) return log_errno_rf("set IP_PKTINFO");

    // draft says set GTSM (ttl=255)
    int ttl = 255;
    ec = setsockopt(ys->dymo_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    if (ec == -1) return log_errno_rf("set IP_TTL");
    ec = setsockopt(ys->dymo_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (ec == -1) return log_errno_rf("set SO_REUSEADDR");

    // DYMO packets must have our IP address and leave/egress from our interface
    int len = strlen(ys->if_name) + 1;
    ec = setsockopt(ys->dymo_fd, SOL_SOCKET, SO_BINDTODEVICE, ys->if_name, len);
    if (ec == -1) return log_errno_rf("set bindtodevice");

    // add link-local multicast (bsd/linux grr)
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(LL_MANET_ROUTERS);
    mreq.imr_interface.s_addr = ys->local_addr;
    ec = setsockopt(ys->dymo_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    if (ec == -1) return log_errno_rf("multicast join");
    ys->mcast_addr = mreq.imr_multiaddr.s_addr;

    // turn off multicast loopback
    int off = 0;
    ec = setsockopt(ys->dymo_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &off, sizeof(off));
    if (ec == -1) return log_errno_rf("set IP_MULTICAST_LOOP");

    // draft says set GTSM (ttl=255)
    ec = setsockopt(ys->dymo_fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    if (ec == -1) return log_errno_rf("set IP_MULTICAST_TTL");

    // bind socket to 0.0.0.0:port
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(INADDR_ANY);
    sin->sin_port = htons(ys->port);
    ec = bind(ys->dymo_fd, (struct sockaddr *) sin, sizeof(*sin));
    if (ec == -1) return log_errno_rf("bind_dymo");

    log_info("+", "Started dymo if=%s addr=%s", ys->if_name, sockaddr_tostr(sin));

    return 0;
}

static int setup_daemon(struct yamir_state *ys)
{
    if (ys->daemonize) {
        log_debug("Run in background");
        int rc = daemon(1, 0);
        if (rc == -1) return log_errno_rf("daemonize");
    }
    return 0;
}

static int setup_signals(void)
{
    struct sigaction sa = { 0 };

    sa.sa_sigaction = catch_signal;
    sa.sa_flags = SA_SIGINFO;

    if (sigaction(SIGINT, &sa, NULL) == -1) return log_errno_rf("setup sigint");
    if (sigaction(SIGTERM, &sa, NULL) == -1) return log_errno_rf("setup sigterm");
    if (sigaction(SIGHUP, &sa, NULL) == -1) return log_errno_rf("setup sigterm");

    keep_running = 1;

    return 0;
}

static void usage(char *prog)
{
    const char *name = get_basename(prog) ?: "<null>";
    printf("Usage: %s -i ifname [-p port] [-l log_level] [-d]\n", name);
}

// process cmd-line args
static int get_opts(struct yamir_state *ys, int argc, char *argv[])
{
    int opt;
    size_t len;

    while ((opt = getopt(argc, argv, "dhi:p:l:f:")) != -1) {
        switch(opt) {
        case 'd': ys->daemonize = 1; break;
        case 'h': usage(argv[0]); exit(0); break;
        case 'i':  // interface
            len = strlen(optarg);
            if (len >= sizeof(ys->if_name)) return log_error_rf("ifname len %zu too big", len);
            memcpy(ys->if_name, optarg, len);
            break;
        case 'p': ys->port  = atoi(optarg); break;
        case 'l': log_level = atoi(optarg); break;
        case 'f': ys->log_file = optarg; break;
        default: return log_error_rf("Unknown option %c\n", opt);
        }
    }

    // check reqired args
    if (!ys->if_name[0]) return log_error_rf("Missing ifname");

    if (ys->log_file) {
        // log file redirect
        FILE *fp = fopen(ys->log_file, "a");
        if (!fp) return log_error_rf("Open log file %s failed", ys->log_file);
        log_init(fp, log_level);
    }

    return 0;
}

static void yamir_free(struct yamir_state *ys)
{
    // socket shutdown
    if (ys->route_fd != -1) close(ys->route_fd);
    if (ys->kyamir_fd != -1) close(ys->kyamir_fd);
    if (ys->dymo_fd != -1) close(ys->dymo_fd);

    free(ys);
}

static struct yamir_state *yamir_create(void)
{
    size_t pool_size = YAMIR_MAXPKT * YAMIR_MAXBUF;
    struct yamir_state *ys = malloc(sizeof(*ys) + pool_size);
    if (!ys) return log_errno_rn("malloc(%zu) failed", sizeof(*ys) + pool_size);

    memset(ys, 0, sizeof(*ys));

    ys->port = DYMO_PORT;
    list_init(&ys->routes);
    list_init(&ys->free_routes);

    ys->family_id = -1;
    ys->dymo_fd   = -1;
    ys->kyamir_fd = -1;
    ys->route_fd  = -1;

    // setup recv buffers
    for (int i = 0; i < YAMIR_MAXPKT; i++) {
        // packet buffer
        ys->iovs[i].iov_base = &ys->recv_pool[i * YAMIR_MAXBUF];
        ys->iovs[i].iov_len =  YAMIR_MAXBUF;
        // info buffer
        ys->msgs[i].msg_hdr.msg_name = &ys->addr_pool[i];
        ys->msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
        ys->msgs[i].msg_hdr.msg_iov = &ys->iovs[i];
        ys->msgs[i].msg_hdr.msg_iovlen = 1;
        ys->msgs[i].msg_hdr.msg_control = ys->ctrl_pool[i].buf;
        ys->msgs[i].msg_hdr.msg_controllen = sizeof(ys->ctrl_pool[i].buf);
    }

    return ys;
}

int main(int argc, char *argv[])
{
    int ec = 0;
    struct yamir_state *ys;

    log_init(NULL, LOG_INFO);

    if (!(ys = yamir_create()))   { ec = 1; goto done; };
    if (get_opts(ys, argc, argv)) { ec = 2; goto done; };
    if (timer_init(&ys->timers))  { ec = 3; goto done; };
    if (setup_signals())          { ec = 4; goto done; };
    if (setup_daemon(ys))         { ec = 5; goto done; };
    if (dymo_init(ys))            { ec = 6; goto done; };
    if (netlink_init(ys))         { ec = 7; goto done; };

    struct pollfd fds[3] = {
        { .fd = ys->dymo_fd,   .events = POLLIN },
        { .fd = ys->kyamir_fd, .events = POLLIN },
        { .fd = ys->route_fd,  .events = POLLIN },
    };
    int mask = POLLIN | POLLHUP | POLLERR;

    while (keep_running) {
        int wait_ms = timer_check(&ys->timers);
        int rc = poll(fds, ARR_LEN(fds), wait_ms);
        if (rc <= 0) {
            if (rc == 0 || errno == EINTR) continue;
            break;
        }
        if ((fds[0].revents & mask) && dymo_recv(ys)) break;
        if ((fds[1].revents & mask) && kyamir_recv(ys)) break;
        if ((fds[2].revents & mask) && rtnl_recv(ys)) break;
    }

done:
    if (ys) yamir_free(ys);

    return ec;
}
