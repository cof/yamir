/* SPDX-License-Identifier: MIT | (c) 2026 [cof] */

/*
 * YAMIR - Yet Another MANET IP Router
 * ===================================
 *
 * This a userspace IP router with
 *
 *  - receives route updates from kyamir via generic netlink
 *  - route management via rtnetlink
 *  - route discovery via DYMO protocol
 *  - PacketBB codec to read/write messages
 *
 * Usage:
 *
 *  ./yamird -i wlan0
 *
 * Routes
 * ------
 * yamir installs routes with rtm_protocol = YAMIR_RT_PROTO.
 * kyamir uses the same value to detect if route exists.
 * See inlude/netlink.h for YAMIR_RT_PROTO.
 *
 * Permissions
 * -----------
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
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
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
    uint32_t genl_seqno;
    struct sockaddr_nl yamir_addr;
    struct list_elem genl_msgs;

    // linux rtnetlink module
    int route_fd;
    uint32_t rtnl_seqno;
    struct sockaddr_nl route_addr;
    struct list_elem routes;

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

// signal
volatile sig_atomic_t keep_running = 0;

#define GNL_TIMEOUT 500

enum genl_type {
    GNL_CTRL,
    GNL_YAMIR
};

// generic netlink messages we send
struct genl_msg {
    struct list_elem node;
    struct yamir_state *ys;
    enum genl_type type;
    int cmd;
    uint32_t nl_seqno;
    struct yamir_msg ym;
    int nl_timer;
};

static void stop_nl_timer(struct genl_msg *msg);

static struct genl_msg *genl_msg_create(struct yamir_state *ys, enum genl_type type, int cmd)
{
    struct genl_msg *msg = calloc(1, sizeof(*msg));
    if (!msg) return NULL;

    msg->ys = ys;
    msg->type = type;
    msg->cmd = cmd;

    list_append(&ys->genl_msgs, &msg->node);

    return msg;
}

static void genl_msg_free(struct genl_msg *msg)
{
    // clean up
    stop_nl_timer(msg);
    list_remove(&msg->node);
    free(msg);
}

static void genl_send_done(struct genl_msg *msg, int ec)
{
    switch(msg->type) {
    case GNL_CTRL:
        if (msg->cmd == CTRL_CMD_GETFAMILY) {
            if (ec) {
                log_error("CTRL_CMD_GETFAMILY error=%d", ec);
                keep_running = 0;
            }
        }
        break;
    case GNL_YAMIR:
        if (msg->cmd == YAMIR_RT_REG) {
            if (ec) {
                log_error("Register kaymir error=%d", ec);
                keep_running = 0;
                break;
            }
            log_info("+", "Registered with kyamir");
        }
        break;
    }

    genl_msg_free(msg);
}

static struct genl_msg *genl_msg_find(struct yamir_state *ys, uint32_t nl_seqno)
{
    struct genl_msg *msg;
    list_fornext_entry(&ys->genl_msgs, msg , node) {
        if (msg->nl_seqno == nl_seqno) return msg;
    }

    // not found
    return NULL;
}

static void genl_timeout_cb(void *arg)
{
    struct genl_msg *msg = arg;
    log_debug("timeout nl_seqno=%u", msg->nl_seqno);

    msg->nl_timer = -1;
    genl_send_done(msg, -ETIMEDOUT);
}

static void start_nl_timer(struct genl_msg *msg)
{
    if (msg->nl_timer != -1) return;
    log_debug("Starting timer seqno=%u", msg->nl_seqno);

    msg->nl_timer = timer_add(&msg->ys->timers,
        GNL_TIMEOUT, genl_timeout_cb, msg);
}

static inline void stop_nl_timer(struct genl_msg *msg)
{
    if (msg->nl_timer == -1) return;
    log_debug("Stopping timer seq=%u", msg->nl_seqno);

    timer_cancel(&msg->ys->timers, msg->nl_timer);
    msg->nl_timer = -1;
}

static void genl_msg_reset(struct genl_msg *msg, enum genl_type type, int cmd)
{
    stop_nl_timer(msg);

    msg->type = type;
    msg->cmd = cmd;
    msg->nl_seqno = 0;

    msg->ym.ip4_addr = 0;
    msg->ym.ifindex = 0;
}

static inline const char *nlmsg_type_tostr(int type)
{
    switch(type) {
    case NLMSG_NOOP: return "NLMSG_NOOP";
    case NLMSG_ERROR: return "NLMSG_ERROR";
    case NLMSG_DONE: return "NLMSG_DONE";
    case NLMSG_OVERRUN: return "NLMSG_OVERRUN";
    case GENL_ID_CTRL: return "GENL_ID_CTRL";
    default: return type < NLMSG_MIN_TYPE ? "NLMSG_???" : "GENL_ID";
    }
}

// rtnl error codes
#define RTNL_OK       0
#define RTNL_TIMEOUT  1
#define RTNL_NOPARENT 2

// DYMO message types
#define DYMO_RREQ 10
#define DYMO_RREP 11
#define DYMO_RERR 12

static inline const char *msg_type_tostr(int msg_type)
{
    switch(msg_type) {
    case DYMO_RREQ: return "RREQ";
    case DYMO_RREP: return "RREP";
    case DYMO_RERR: return "RERR";
    default: return "???";
    }
}


// dymo route state
enum route_state  {
    DRS_NONE = 0,
    DRS_DISCOVER,
    DRS_ADDING,
    DRS_ACTIVE,
    DRS_DELETING
};

static inline const char *drs_tostr(enum route_state rs)
{
    switch(rs) {
    case DRS_NONE: return "NONE";
    case DRS_DISCOVER: return "DISCOVER";
    case DRS_ADDING: return "ADDING";
    case DRS_ACTIVE: return "ACTIVE";
    case DRS_DELETING: return "DELETING";
    default: return "???";
    }
}

struct dymo_req {
    uint32_t addr;
    int ifindex;
    int timer;
    uint32_t wait_time;
    int tries;
    uint16_t seqnum;
    int8_t hop_count;
};

// 4.1  DYMO route state
struct dymo_route {
    struct list_elem node;
    struct yamir_state *ys;
    enum route_state state;
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
    uint32_t nl_seqno;
    uint64_t created_ts;
    // timers
    int rtnl_timer;
    int age_timer;
    int seqnum_timer;
    int used_timer;
    int del_timer;
};


// ROUTE timeouts scaled from secs to ms
#define DR_RNTL_TIMEOUT  500
#define DR_TIMEOUT         (5 * 1000)
#define DR_AGE_MIN         (1 * 1000)
#define DR_SEQNUM_AGE_MAX  (60 * 1000)
#define DR_USED_TIMEOUT    DR_TIMEOUT
#define DR_DELETE_TIMEOUT  (2 * DR_TIMEOUT)
#define DR_RREQ_WAIT_TIME  (2 * 1000)
#define UNICAST_MESSAGE_SENT_TIMEOUT (1 * 1000)

static inline uint64_t get_now_ms(void)
{
    struct timespec ts;

    int rc = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (rc == -1) return (uint64_t) -1;

    // convert to msec
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static inline bool yamir_islocaladdr(struct yamir_state *ys, struct pbb_node *mn)
{
    return ys->local_addr == mn->ip4_addr;
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

static const char *route_tostr(struct dymo_route *dr)
{
    static char bufs[4][128];
    static int idx;

    char *buf = bufs[idx];
    size_t size = sizeof(bufs[0]);
    idx = (idx + 1) & 3;

    if (!dr) return "<none>";

    snprintf(buf, size,
        "state=%s(%u) addr=%s/%d gwaddr=%s gwifindex=%u seqnum=%d dist=%u",
        drs_tostr(dr->state), dr->state,
        addr_tostr(dr->addr), dr->prefix,
        addr_tostr(dr->nexthop_addr), dr->nexthop_ifindex,
        dr->seqnum, dr->dist);

    return buf;
}

static const char *route_info_tostr(struct dymo_route *route)
{
    static char bufs[4][128];
    static int idx;

    char *buf = bufs[idx];
    size_t size = sizeof(bufs[0]);
    idx = (idx + 1) & 3;

    if (!route) return "<none>";

    snprintf(buf, size,
        "addr=%s/%d via %s dev %u",
        addr_tostr(route->addr), route->prefix,
        addr_tostr(route->nexthop_addr), route->nexthop_ifindex);

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

    struct pkt_buf buf = PKB_INIT(str, len);

    pkb_printf(&buf,
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

    struct pkt_buf buf = PKB_INIT(str, len);

    pkb_printf(&buf,
        "saddr=%s daddr=%s ifidx=%u",
        addr_tostr(rs->saddr),
        addr_tostr(rs->daddr),
        rs->ifindex);

    return str;
}

static struct dymo_req *dymo_req_find(struct yamir_state *ys, uint32_t addr);
static void dymo_end_req(struct dymo_req *req, int rc);
static int yamir_send_msg(struct genl_msg *gm);
static int rtnl_send_msg(int cmd_type, struct dymo_route *dr);

// stevens page 533 // see ip 7 IP_PKTINFO
static int recvfrom_wstate(int fd, size_t vlen,
    struct mmsghdr msgs[static vlen],
    struct recv_state *states)
{
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
    if (nsent < 0) return log_errno_rf("send failed");
    if ((size_t) nsent != len) return log_error_rf("short send");

    return 0;
}

static void catch_signal(int signo, siginfo_t *info, void *ucontext)
{
    (void) ucontext;
    keep_running = 0;
}

// find route entry with longest prefix match (rfc1812)
static struct dymo_route *match_route(struct yamir_state *ys, uint32_t addr)
{
    uint32_t laddr = ntohl(addr);
    struct dymo_route *match = NULL, *route;
    list_fornext_entry(&ys->routes, route, node) {
        // check valid route
        if (route->state != DRS_ACTIVE && route->state != DRS_ADDING) continue;
        if (match && route->prefix <= match->prefix) continue;
        if (route->prefix > 32) continue;
        // does addr match route prefix
        uint32_t mask = route->prefix ? ~0U << (32 - route->prefix) : 0;
        uint32_t raddr = ntohl(route->addr);
        if ((laddr & mask) == (raddr & mask)) {
            match = route;
        }
    }

    log_debug("addr=%s match=%s", 
        addr_tostr(addr), match ? route_tostr(match) : "none");

    return match;
}

// find route by rtnl-seqno
static struct dymo_route *route_find_nlseq(struct yamir_state *ys, uint32_t nl_seqno)
{
    struct dymo_route *route;
    list_fornext_entry(&ys->routes, route, node) {
        if (route->state != DRS_ADDING && route->state != DRS_DELETING) continue;
        if (route->nl_seqno == nl_seqno) return route;
    }

    return NULL;
}

// find discovery route-request by ip4-addr
static struct dymo_req *dymo_req_find(struct yamir_state *ys, uint32_t addr)
{
    struct dymo_route *route;
    list_fornext_entry(&ys->routes, route, node) {
        if (route->state == DRS_DISCOVER && route->req.addr == addr) {
            return &route->req;
        }
    }

    return NULL;
}

// section 5.2.1.
static bool node_superior(struct pbb_node *mn, struct dymo_route *dr, int msg_type)
{
    // 1. stale (what's wrong with signed 32 bit)
    if ((int16_t) mn->seqnum - (int16_t) dr->seqnum < 0) {
        return false;
    }

    // 2. loop possible
    if (mn->seqnum == dr->seqnum &&
       (!pbb_node_dist(mn) || !dr->has_dist || (mn->dist > dr->dist + 1)))
    {
        return false;
    }

    // 3. inferior or equivalent
    if (mn->seqnum == dr->seqnum &&
       (((mn->dist == dr->dist + 1) && !dr->is_broken) ||
       (mn->dist == dr->dist && msg_type == DYMO_RREQ && !dr->is_broken)))
    {
        return false;
    }

    return true;
}

static void route_delete(struct dymo_route *dr);
static void rtnl_send_done(struct dymo_route *dr, int rc);

static void rtnl_timeout_cb(void *arg)
{
    struct dymo_route *dr = arg;
    log_debug("timeout nl_seqno=%u", dr->nl_seqno);

    dr->rtnl_timer = -1;
    rtnl_send_done(dr, RTNL_TIMEOUT);
}

static inline void stop_rtnl_timer(struct dymo_route *dr)
{
    if (dr->rtnl_timer == -1) return;
    log_debug("Stopping timer nl_seqno=%u", dr->nl_seqno);

    timer_cancel(&dr->ys->timers, dr->rtnl_timer);
    dr->rtnl_timer = -1;
}

static void start_rtnl_timer(struct dymo_route *dr)
{
    if (dr->rtnl_timer != -1) return;
    log_debug("Starting timer nl_seqno=%u", dr->nl_seqno);

    dr->rtnl_timer = timer_add(&dr->ys->timers,
        DR_RNTL_TIMEOUT,
        rtnl_timeout_cb,
        dr);
}

static void delete_timeout_cb(void *arg)
{
    struct dymo_route *dr = arg;

    log_debug("delete timeout");

    dr->del_timer = -1;
    route_delete(dr);
}

static inline void stop_delete_timer(struct dymo_route *dr)
{
    if (dr->del_timer == -1) return;
    log_debug("Stopping delete timer");

    timer_cancel(&dr->ys->timers, dr->del_timer);
    dr->del_timer = -1;
}

static void start_delete_timer(struct dymo_route *dr)
{
    if (dr->del_timer != -1) return;
    log_debug("Starting delete timer");

    dr->del_timer = timer_add(&dr->ys->timers,
        DR_DELETE_TIMEOUT, delete_timeout_cb, dr);
}

// spec says its safe to delete after age timer expired
// but it make sense to allow start a delete timer
// similar to a route used logic
static void age_timeout_cb(void *arg)
{
    struct dymo_route *dr = arg;

    log_debug("age timeout");

    dr->age_timer = -1;
    start_delete_timer(dr);
}

static inline void stop_age_timer(struct dymo_route *dr)
{
    if (dr->age_timer == -1) return;

    timer_cancel(&dr->ys->timers, dr->age_timer);
    dr->age_timer = -1;
}

static void seqnum_timeout_cb(void *arg)
{
    struct dymo_route *dr = arg;

    log_debug("seqnum timeout");

    dr->seqnum_timer = -1;
    dr->seqnum = 0;
}

static inline void stop_seqnum_timer(struct dymo_route *dr)
{
    if (dr->seqnum_timer == -1) return;

    timer_cancel(&dr->ys->timers, dr->seqnum_timer);
    dr->seqnum_timer = -1;
}

static inline void stop_used_timer(struct dymo_route *dr)
{
    if (dr->used_timer == -1) return;

    timer_cancel(&dr->ys->timers, dr->used_timer);
    dr->used_timer = -1 ;
}

// 5.2.3.3.
static void used_timeout_cb(void *arg)
{
    struct dymo_route *dr = arg;

    dr->used_timer = -1;
    start_delete_timer(dr);
}

static void route_stop_timers(struct dymo_route *dr)
{
    log_debug("Stopping timers");

    stop_rtnl_timer(dr);
    stop_delete_timer(dr);
    stop_seqnum_timer(dr);
    stop_used_timer(dr);
    stop_age_timer(dr);
}

// remove route via rtnl
static void rtnl_del_route(struct dymo_route *dr)
{
    dr->state = DRS_DELETING;
    log_debug("del %s", route_tostr(dr));

    int rc = rtnl_send_msg(RTM_DELROUTE, dr);
    if (rc) {
        // send failed
        rtnl_send_done(dr, rc);
        return;
    }

    // wait for ack
    start_rtnl_timer(dr);
}

// add route via rtnl
static int rtnl_add_route(struct dymo_route *dr)
{
    dr->state = DRS_ADDING;
    log_debug("add %s", route_tostr(dr));

    int rc = rtnl_send_msg(RTM_NEWROUTE, dr);
    if (rc) {
        // send failed
        rtnl_send_done(dr, rc);
        return rc;
    }

    // wait for ack
    start_rtnl_timer(dr);

    // update in progress
    return 0;
}


static void route_free(struct dymo_route *dr)
{
    log_debug("state=%s(%u)", drs_tostr(dr->state), dr->state);

    route_stop_timers(dr);
    list_remove(&dr->node);
    free(dr);
}

static void route_delete(struct dymo_route *dr)
{
    route_stop_timers(dr);
    rtnl_del_route(dr);
}

static struct dymo_route *route_create(struct yamir_state *ys)
{
    struct dymo_route *dr = calloc(1, sizeof(*dr));
    if (!dr) return NULL;

    // init fields
    dr->ys = ys;
    dr->rtnl_timer = -1;
    dr->age_timer = -1;
    dr->seqnum_timer = -1;
    dr->used_timer = -1;
    dr->del_timer = -1;

    list_append(&ys->routes, &dr->node);

    return dr;
}

static void rtnl_send_done(struct dymo_route *dr, int rc)
{
    log_debug("state=%s(%u) nl_seqno=%u rc=%d", 
        drs_tostr(dr->state), dr->state, dr->nl_seqno, rc);

    switch(dr->state) {
    case DRS_NONE:
    case DRS_DISCOVER:
    case DRS_ACTIVE:
        // should never happen
        break;

    case DRS_ADDING:
        stop_rtnl_timer(dr);
        if (rc) {
            // add failed - discard
            route_free(dr);
            break;
        }
        log_info("+", "Added route %s", route_info_tostr(dr));
        dr->state = DRS_ACTIVE;
        break;

    case DRS_DELETING:
        stop_rtnl_timer(dr);
        if (rc == 0) {
            log_info("+", "Deleted route %s", route_info_tostr(dr));
        }
        if (dr->is_broken) {
            dr->state = DRS_NONE;
            start_delete_timer(dr);
        }
        else {
            route_free(dr);
        }
        break;
    }
}

// create or update route
static bool route_update(struct yamir_state *ys,
    int msg_type, struct pbb_node *mn,
    uint32_t nexthop_addr, uint32_t nexthop_ifindex)
{
    log_debug("type=%s(%d) mnaddr=%s gwaddr=%s gwifindex=%u",
        msg_type_tostr(msg_type), msg_type, 
        addr_tostr(mn->ip4_addr), addr_tostr(nexthop_addr),
        nexthop_ifindex);

    struct dymo_route *route = match_route(ys, mn->ip4_addr);

    if (route) {
        if (!node_superior(mn, route, msg_type))
            return false;
        route_stop_timers(route);
    }
    else {
        route = route_create(ys);
    }

    // update route entry - 5.2.2
    route->created_ts = get_now_ms();
    route->addr = mn->ip4_addr;

    // always set prefix field
    route->prefix = mn->prefix;
    if (pbb_node_seqn(mn))
        route->seqnum = mn->seqnum;
    route->nexthop_addr = nexthop_addr;
    route->nexthop_ifindex = nexthop_ifindex;
    route->is_broken  = 0;

    // route is consider superior so always set the distance
    route->has_dist = 0;
    if (pbb_node_dist(mn)) {
        route->has_dist = 1;
        route->dist = mn->dist;
    }

    int rc = rtnl_add_route(route);
    if (rc) return false;

    // start route timers
    route->age_timer = timer_add(&ys->timers, DR_AGE_MIN, age_timeout_cb, route);
    route->seqnum_timer = timer_add(&ys->timers, DR_SEQNUM_AGE_MAX, seqnum_timeout_cb, route);

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

    struct pkt_buf buf = PKB_INIT(wbuf, sizeof(wbuf));
    struct pbb_hdr hdr = { 0 };

    // encode pkt
    if (pkb_hdr_enc(&buf, &hdr)) return log_error_rf("enc_hdr failed");
    if (pkb_msg_enc(&buf, msg))  return log_error_rf("enc_msg failed");

    // TODO implement rfc5148 jitter

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = addr;
    sin.sin_port = htons(DYMO_PORT);
    size_t len = pkb_pos(&buf);

    log_debug("sendto dst=%s len=%zu", sockaddr_tostr(&sin), len);

    ssize_t rc = sendto(ys->dymo_fd, wbuf, len, 0, (struct sockaddr *) &sin, sizeof(sin));
    if (rc == -1) return log_errno_rf("sendto fd=%d len=%zu", ys->dymo_fd, len);

    return 0;
}

// 5.3.2 (send reply back to request originator)
static int dymo_send_reply(struct yamir_state *ys, struct pbb_msg *req)
{
    struct pbb_msg msg;
    struct pbb_msg *reply = &msg;

    pbb_msg_reset(reply);

    reply->type = DYMO_RREP;
    struct pbb_node *target = pbb_copy_node(reply, req->origin);
    struct pbb_node *origin = pbb_copy_node(reply, req->target);

    struct dymo_route *route = match_route(ys, target->ip4_addr);
    if (!route) return log_error_rf("No route to target");

    if (!pbb_node_seqn(target) ||
        ((int16_t) target->seqnum - (int16_t) ys->own_seqnum < 0) ||
        (target->seqnum == ys->own_seqnum && !pbb_node_dist(origin)))
    {
        yamir_inc_seqnum(ys);
    }

    origin->seqnum = ys->own_seqnum;
    origin->flags |= PBB_NF_SEQN;

    reply->hop_limit = MSG_HOPLIMIT;
    reply->flags |= PBB_MF_HLIM;
    reply->addr_len = 4;

    log_debug("send RREP msg_seq=%u targ_seq=%u dest=%s nexthop=%s hlimit=%d",
        reply->seq_num,
        origin->seqnum,
        addr_tostr(target->ip4_addr),
        addr_tostr(route->nexthop_addr),
        reply->hop_limit);

    // we route the message via the next hop
    return dymo_send_msg(ys, reply, route->nexthop_addr);
}

static int dymo_recv_reply(struct yamir_state *ys, struct pbb_msg *reply)
{
    log_debug("reply(%s)", dymo_msg_tostr(reply));

    struct dymo_req *req = dymo_req_find(ys, reply->origin->ip4_addr);
    if (req) {
        struct dymo_route *route = match_route(ys, req->addr);
        dymo_end_req(req, route ? 0 : -EHOSTUNREACH);
    }

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

// 5.5.3 rm message or data packet cannot be outed to addr
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
    log_debug("rs=(%s) rmsg(%s)", recv_state_tostr(rs), dymo_msg_tostr(rmsg));

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
    if (!dec_hop_limit(rmsg))
        return 0;

    // replies or unicast requests always sent via next hop addr
    uint32_t dst_addr;
    if (rmsg->type == DYMO_RREP || is_unicast(rs->daddr)) {
        // need check if rm can be routed towards target
        struct pbb_node *target = rmsg->target;
        struct dymo_route *route = match_route(ys, target->ip4_addr);
        if (!route) 
            return dymo_rerr_send(ys, target->ip4_addr, target->seqnum, target->prefix);
        if (route->is_broken)
            return dymo_rerr_send(ys, target->ip4_addr, route->seqnum, target->prefix);
        dst_addr = route->nexthop_addr;
    }
    else {
        dst_addr = ys->mcast_addr;
    }

    return dymo_send_msg(ys, rmsg, dst_addr);
}

static int validate_msg(struct yamir_state *ys, struct pbb_msg *msg)
{
    // check required fields present
    if (!pbb_msg_hlim(msg)) return PBB_MSG_HLIM;
    if (!msg->target) return PBB_MSG_TNODE;
    if (!msg->origin) return PBB_MSG_ONODE;
    if (!pbb_node_seqn(msg->origin)) return PBB_MSG_OSEQN;
    if (msg->did != ys->node_did) return PBB_MSG_TLV_DID;
    if (yamir_islocaladdr(ys, msg->origin)) return PBB_MSG_OLADDR;

    // ok
    return 0;
}

static int handle_rreq(struct yamir_state *ys, struct pbb_msg *rreq, struct recv_state *rs)
{
    // check required fields present
    int rc = validate_msg(ys, rreq);
    if (rc) return log_debug_rc(rc, "invalid msg %s", pbb_field_tostr(rc));

    int orig_superior = route_update(ys, rreq->type, rreq->origin, rs->saddr, rs->ifindex);

    // additional nodes
    for (int i = 2; i < rreq->num_node; i++) {
        struct pbb_node *mn = &rreq->nodes[i];
        if (!route_update(ys, rreq->type, mn, rs->saddr, rs->ifindex)) {
            mn->flags |= PBB_NF_SKIP;
            log_debug("invalid-route node %d", i);
        }
    }

    if (!orig_superior) {
        return 0;
    }

    // relay request-msg if not for us
    if (!yamir_islocaladdr(ys, rreq->target)) {
        return relay_rmsg(ys, rreq, rs);
    }

    // request is for us
    return dymo_send_reply(ys, rreq);
}

static int handle_rrep(struct yamir_state *ys, struct pbb_msg *rrep, struct recv_state *rs)
{
    // check required fields present
    int rc = validate_msg(ys, rrep);
    if (rc) return log_debug_rc(rc, "invalid msg %s", pbb_field_tostr(rc));

    bool orig_superior = route_update(ys, rrep->type, rrep->origin, rs->saddr, rs->ifindex);

    // additional nodes
    for (int i = 2; i < rrep->num_node; i++) {
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

    struct dymo_route *dr = match_route(ys, mn->ip4_addr);
    if (!dr) return false;

    if (!dr->is_broken &&
        (dr->nexthop_addr == sender &&
        (dr->seqnum == 0 || mn->seqnum == 0
         || !pbb_node_seqn(mn)
         || ((int16_t) dr->seqnum - (int16_t) mn->seqnum  <= 0))))
    {
        dr->is_broken = 1;
        rtnl_del_route(dr);
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
    log_debug("rs=(%s) rerr(%s)", recv_state_tostr(rs), dymo_msg_tostr(rerr));

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

// tell kernel module discovery failed
static void discovery_failed(struct yamir_state *ys, uint32_t addr, int ifindex)
{
    struct genl_msg *msg = genl_msg_create(ys, GNL_YAMIR, YAMIR_RT_FAIL);
    if (!msg) return log_error_rv("create YAMIR_RT_FAIL");

    struct yamir_msg *ym = &msg->ym;
    ym->ip4_addr = addr;
    ym->ifindex  = ifindex;

    int rc = yamir_send_msg(msg);
    if (rc) {
        genl_send_done(msg, rc);
    }
}

static void dymo_end_req(struct dymo_req *req, int rc)
{
    log_debug("addr=%s rc=%d", addr_tostr(req->addr), rc);

    struct dymo_route *route = containerof(req, struct dymo_route, req);

    if (req->timer != -1) {
        struct yamir_state *ys = route->ys;
        if (ys) timer_cancel(&ys->timers, req->timer);
        req->timer = -1;
    }

    if (rc) {
        discovery_failed(route->ys, req->addr, req->ifindex);
    }

    // discovey done
    route_free(route);
}

static int dymo_send_req(struct yamir_state *ys, struct dymo_req *req)
{
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

    log_debug("send RREQ msg_seq=%u orig_seq=%u src=%s dst=%s hlimit=%d",
        req->seqnum,
        origin->seqnum,
        addr_tostr(origin->ip4_addr),
        addr_tostr(target->ip4_addr),
        msg.hop_limit);

    int ec = dymo_send_msg(ys, &msg, ys->mcast_addr);
    if (ec) return ec;

    // wait for response
    req->timer = timer_add(&ys->timers, req->wait_time, dymo_req_timeout, req);
    return 0;
}


// send out request for route
static int dymo_out_req(struct dymo_req *req)
{
    log_debug("%s attempt %d/%d wait %u",
        addr_tostr(req->addr),
        req->tries,
        DISCOVERY_ATTEMPTS_MAX,
        req->wait_time);

    struct dymo_route *route = containerof(req, struct dymo_route, req);
    struct dymo_route *info = match_route(route->ys, req->addr);

    if (info) {
        // have info about target
        req->seqnum    = info->seqnum;
        req->hop_count = info->dist;
    }
    else {
        // no info about target
        req->seqnum = 0;
        req->hop_count = 0;
    }

    return dymo_send_req(route->ys, req);
}

static void dymo_req_timeout(void *arg)
{
    struct dymo_req *req = arg;

    req->timer = -1;
    log_debug("%s timeout %d/%d", addr_tostr(req->addr), req->tries, DISCOVERY_ATTEMPTS_MAX);

    int ec = -ETIMEDOUT;

    if (req->tries < DISCOVERY_ATTEMPTS_MAX) {
        // try again
        req->tries++;
        req->wait_time = req->wait_time * 2;
        ec = dymo_out_req(req);
        if (!ec) return;
    }

    // discovery failed
    dymo_end_req(req, ec);
}

static void route_discover(struct yamir_state *ys, struct yamir_msg *msg)
{

    struct dymo_req *req = dymo_req_find(ys, msg->ip4_addr);
    if (req) {
        log_debug("discovery already in progress");
        return;
    }

    struct dymo_route *route = route_create(ys);
    if (!route) {
        discovery_failed(ys, msg->ip4_addr, msg->ifindex);
        return;
    }

    // start route discovery
    route->state = DRS_DISCOVER;
    route->created_ts = get_now_ms();

    // start dymo request
    req = &route->req;  
    req->addr = msg->ip4_addr;
    req->ifindex = msg->ifindex;
    req->tries = 1;
    req->wait_time = DR_RREQ_WAIT_TIME;

    log_debug("Staring discovery for addr=%s ifindex=%d", addr_tostr(msg->ip4_addr), msg->ifindex);
    int ec = dymo_out_req(req);
    if (ec)
        dymo_end_req(req, ec);

}

// section 5.5.2
static void route_inuse(struct yamir_state *ys, struct yamir_msg *msg)
{
    log_debug("addr=%s ifindex=%d", addr_tostr(msg->ip4_addr), msg->ifindex);

    struct dymo_route *dr = match_route(ys, msg->ip4_addr);
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

    struct dymo_route *route = match_route(ys, msg->ip4_addr);

    // normal case - no forwarding route
    if (!route) {
        dymo_rerr_send(ys, msg->ip4_addr, 0, 0);
        return;
    }

    // did kernel lose route ?
    if (!route->is_broken) {
        log_error("Not broken %s", route_tostr(route));
        if (route->state == DRS_ACTIVE) {
            rtnl_add_route(route);
        }
        return;
    }

    // draft says we should use seqnum if we have one
    dymo_rerr_send(ys, msg->ip4_addr, route->seqnum, 0);
}

static int dymo_rx_mmsg(struct yamir_state *ys,
    struct mmsghdr *mmsg, struct recv_state *rs)
{
    uint8_t *pkt = mmsg->msg_hdr.msg_iov->iov_base;
    size_t len = mmsg->msg_len;

    log_debug("src=%s dst=%s ifindex=%u bytes=%zu",
        addr_tostr(rs->saddr), addr_tostr(rs->daddr), rs->ifindex, len);

    // check if we are the sender
    if (rs->saddr == ys->local_addr) {
        log_debug("saddr %s is local - will drop", addr_tostr(rs->saddr));
        return 0;
    }

    // decode pkt data - until zero or error
    struct pkt_buf buf = PKB_INIT(pkt, len);
    struct pbb_hdr hdr;

    int ec = pkb_hdr_dec(&buf, &hdr);
    if (ec) return ec;

    while (pkb_rem(&buf)) {
        struct pbb_msg msg;
        ec = pkb_msg_dec(&buf, &msg);
        if (ec) continue;
        log_debug("dymo-msg type=%s(%d) flags=0x%x nodes=%d",
            pbb_type_tostr(msg.type), msg.type, msg.flags, msg.num_node);
        switch(msg.type) {
        case DYMO_RREQ: handle_rreq(ys, &msg, rs); break;
        case DYMO_RREP: handle_rrep(ys, &msg, rs); break;
        case DYMO_RERR: handle_rerr(ys, &msg, rs); break;
        default: 
            break;
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

    log_debug("recvfrom_wstate fd=%d nr=%d", ys->dymo_fd, nr);

    if (nr < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
        return log_errno_rf("recvfrom_wstate failed");
    }

    for (int i = 0; i < nr; i++) {
        dymo_rx_mmsg(ys, &ys->msgs[i], &states[i]);
    }

    return 0;
}

static int yamir_send_msg(struct genl_msg *msg)
{
    struct yamir_state *ys = msg->ys;
    struct yamir_msg *ym = &msg->ym;

    // request header
    struct genl_req req = { 0 };
    struct nlmsghdr *nlh = &req.n;
    nlh->nlmsg_len   = NLMSG_SPACE(GENL_HDRLEN);
    nlh->nlmsg_type  = ys->family_id;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq   = ys->genl_seqno++;
    nlh->nlmsg_pid   = getpid();

    // set cmd
    req.g.cmd = msg->cmd;
    req.g.version = 1;

    struct nlattr *nla;

    // add IP4_ADDR attr
    nla = mkptr(&req, nlh->nlmsg_len);
    nla->nla_type = YAMIR_ATTR_IP4ADDR;
    nla->nla_len = sizeof(uint32_t) + NLA_HDRLEN;
    memcpy(mkptr(nla, NLA_HDRLEN), &ym->ip4_addr, sizeof(uint32_t));
    nlh->nlmsg_len += NLMSG_ALIGN(nla->nla_len);

    // add IF_INDEX attr
    nla = mkptr(&req, nlh->nlmsg_len);
    nla->nla_type = YAMIR_ATTR_IFINDEX;
    nla->nla_len = sizeof(int32_t) + NLA_HDRLEN;
    memcpy(mkptr(nla, NLA_HDRLEN), &ym->ifindex, sizeof(int32_t));
    nlh->nlmsg_len += NLMSG_ALIGN(nla->nla_len);

    log_debug("send seq=%u type=%d cmd=%s(%d) addr=%s ifindex=%d len=%u",
        nlh->nlmsg_seq, nlh->nlmsg_type,
        yamir_cmd_tostr(msg->cmd), msg->cmd,
        addr_tostr(ym->ip4_addr), ym->ifindex,
        nlh->nlmsg_len);

    int rc = netlink_send(ys->kyamir_fd, &req, nlh->nlmsg_len);
    if (rc) return rc;

    // message sent
    msg->nl_seqno = nlh->nlmsg_seq;
    return 0;
}

static void yamir_process_msg(struct yamir_state *ys, int cmd, struct yamir_msg *msg)
{
    log_debug("cmd=%s(%d) addr=%s ifindex=%d",
        yamir_cmd_tostr(cmd), cmd, addr_tostr(msg->ip4_addr), msg->ifindex);

    switch(cmd) {
    case YAMIR_RT_NEED:  route_discover(ys, msg); break;
    case YAMIR_RT_INUSE: route_inuse(ys, msg);  break;
    case YAMIR_RT_ERR:   route_err(ys, msg); break;
    default: 
        break;
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
            uint16_t family_id;
            memcpy(&family_id, mkptr(nla, NLA_HDRLEN), sizeof(family_id));
            log_debug("family_id=%d", family_id);
            return family_id;
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
    struct genl_msg *msg = genl_msg_find(ys, nlh->nlmsg_seq);
    if (!msg) {
        log_debug("no msg for seq=%u", nlh->nlmsg_seq);
        return;
    }

    // get ack code
    struct nlmsgerr *err;
    int rc;
    if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*err))) {
        log_error("truncated NLMSG_ERROR seq=%u len=%u", nlh->nlmsg_seq, nlh->nlmsg_len);
        rc = -EBADMSG;
    }
    else {
        err = NLMSG_DATA(nlh);
        rc = -err->error;
        log_debug("netlink seq=%u err=%s(%d)", nlh->nlmsg_seq, strerror(rc), rc);
    }

    // acked
    genl_send_done(msg, rc);
}

static void kyamir_handle_nlctrl(struct yamir_state *ys, struct nlmsghdr *nlh) 
{
    struct genl_msg *msg = genl_msg_find(ys, nlh->nlmsg_seq);
    if (!msg) {
        log_debug("no msg for %u", nlh->nlmsg_seq);
        return;
    } 

    // set netlink family-id
    ys->family_id = parse_family_id(nlh);
    if (ys->family_id == -1) {
        genl_send_done(msg, -EBADMSG);
        return;
    }

    log_info("+", "Received netlink id %d", ys->family_id);

    // register with kyamir
    genl_msg_reset(msg, GNL_YAMIR, YAMIR_RT_REG);
    int rc = yamir_send_msg(msg);
    if (rc) {
        genl_send_done(msg, rc);
        return;
    }

    start_nl_timer(msg);
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

    yamir_process_msg(ys, type, &msg);
}

static void kyamir_rx_mmsg(struct yamir_state *ys, struct mmsghdr *mmsg)
{
    struct nlmsghdr *nlh = mmsg->msg_hdr.msg_iov->iov_base;
    size_t msg_len = mmsg->msg_len;

    for (; NLMSG_OK(nlh, msg_len); nlh = NLMSG_NEXT(nlh, msg_len)) {
        log_debug("nl-msg seq=%u type=%s(%u) len=%u", 
            nlh->nlmsg_seq, nlmsg_type_tostr(nlh->nlmsg_type),
            nlh->nlmsg_type, nlh->nlmsg_len);
        switch(nlh->nlmsg_type) {
        case NLMSG_DONE: 
            msg_len = 0;
            break;
        case NLMSG_ERROR: // error/ack message
            kyamir_handle_nlerr(ys, nlh);
            break;
        case GENL_ID_CTRL: // generic netlink
            kyamir_handle_nlctrl(ys, nlh);
            break;
        default: // yamir request
            kyamir_handle_nldata(ys, nlh);
            break;
        }
    }
}

// receive msgs from kernel module
static int kyamir_recv(struct yamir_state *ys)
{
    int nr = recvmmsg(ys->kyamir_fd, ys->msgs, YAMIR_MAXPKT, MSG_DONTWAIT, NULL);

    log_debug("recvmmsg fd=%d nr=%d", ys->kyamir_fd, nr);
    if (nr < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
        return log_errno_rf("recvmmsg %d failed", ys->kyamir_fd);
    }

    for (int i = 0; i < nr; i++) {
        kyamir_rx_mmsg(ys, &ys->msgs[i]);
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
            struct dymo_route *dr = route_find_nlseq(ys, nlh->nlmsg_seq);
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
 * send rtnetlink message
 * route add dest/prefix dev if metric hop_count via nexthop_addr
 */
static int rtnl_send_msg(int cmd_type, struct dymo_route *dr)
{
    log_debug("type=%s addr=%s/%d nexthop=%s ifindex=%u dist=%u",
        rtnl_type_tostr(cmd_type), addr_tostr(dr->addr), dr->prefix,
        addr_tostr(dr->nexthop_addr), dr->nexthop_ifindex, dr->dist);

    struct yamir_state *ys = dr->ys;
    if (!ys) return RTNL_NOPARENT;

    // TODO dynamically allocate a buffer of the correct size
    struct {
        struct nlmsghdr nlm;
        struct rtmsg rtm;
        char buf[512];
    } req;

    memset(&req, 0, sizeof(req));

    // setup netlink msg header
    struct nlmsghdr *nlh = &req.nlm;
    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlh->nlmsg_type  = cmd_type;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq   = ys->rtnl_seqno++;
    nlh->nlmsg_pid   = getpid();

    if (cmd_type == RTM_NEWROUTE) {
        // NOTE: IPv4 FIB reports this as FIB_EVENT_ENTRY_REPLACE
        nlh->nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
    }
    uint32_t dst_prefix = dr->prefix;
    if (!dst_prefix) dst_prefix = 32;

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

    int rc = netlink_send(ys->route_fd, &req, nlh->nlmsg_len);
    if (rc != 0) return log_error_rc(rc, "send route_update failed");

    // message sent
    dr->nl_seqno = nlh->nlmsg_seq;
    return 0;
}

static int resolv_family_id(struct yamir_state *ys)
{
    const char *name = YAMIR_NL_NAME;
    size_t name_len = sizeof(YAMIR_NL_NAME) - 1;

    struct genl_msg *msg = genl_msg_create(ys, GNL_CTRL, CTRL_CMD_GETFAMILY);
    if (!msg) return log_error_rf("create CMD_GETFAMILY failed");

    // request header
    struct genl_req req = { 0 };
    struct nlmsghdr *nlh = &req.n;
    nlh->nlmsg_len  = NLMSG_SPACE(GENL_HDRLEN);
    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = ys->genl_seqno++;
    nlh->nlmsg_pid = getpid();

    // set cmd
    req.g.cmd = msg->cmd;
    req.g.version = 1;

    // add CTRL_ATTR_FAMILY_NAME
    struct nlattr *nla = mkptr(&req, NLMSG_SPACE(GENL_HDRLEN));
    nla->nla_type = CTRL_ATTR_FAMILY_NAME;
    nla->nla_len = name_len + 1 + NLA_HDRLEN;
    memcpy((char *)nla + NLA_HDRLEN, name, name_len + 1);
    nlh->nlmsg_len += NLMSG_ALIGN(nla->nla_len);

    log_debug("send seq=%u type=%d cmd=%s name=%s len=%u",
        nlh->nlmsg_seq, nlh->nlmsg_type,
        "CTRL_CMD_GETFAMILY", name, nlh->nlmsg_len);

    int rc = netlink_send(ys->kyamir_fd, &req, nlh->nlmsg_len);
    if (rc) return log_error_rc(rc, "send CMD_GETFAMILY failed");

    // sent - wait for ack
    msg->nl_seqno = nlh->nlmsg_seq;
    start_nl_timer(msg);

    return 0;
}

// set up kernel module and rtnetlink interfaces
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
    ec = resolv_family_id(ys);
    if (ec) return log_errno_rf("resolv_family_id failed");

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

    // TODO clear lists ?

    free(ys);
}

static struct yamir_state *yamir_create(void)
{
    size_t pool_size = YAMIR_MAXPKT * YAMIR_MAXBUF;
    struct yamir_state *ys = malloc(sizeof(*ys) + pool_size);
    if (!ys) return log_errno_rn("malloc(%zu) failed", sizeof(*ys) + pool_size);

    memset(ys, 0, sizeof(*ys));

    ys->port = DYMO_PORT;
    list_init(&ys->genl_msgs);
    list_init(&ys->routes);

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
