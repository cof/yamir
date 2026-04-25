/*
 *
 * YAMIR - Yet Another Manet IP Router
 *
 * yamir userspace router
 *
 * We originally where going for DSR but ended up using DYMO instead
 *
 * draft-ietf-manet-dymo-21 k
 * rfc5444 - packetbb
 * RFC3549 - netlink
 * android-ndk
   TODO use manet port 269 (requires root access)
   suexec then drop privliges
    iptables -A PREROUTING -t nat -i eth0 -p tcp 
   --dport 843 -j REDIRECT --to-port 8430
    
   Notes
   ===== 
   Running yarmid as not root requires the following permssions

   cap_net_bind_service - uses privileled port 269
   cap_net_raw          - uses SO_BINDTODEVICE
   cap_net_admin        - uses netlink multlicast nl_groups != 0
    
   sudo setcap cap_net_bind_service,cap_net_raw,cap_net_admin=+ep yamird

   Okay 
    netlink_set_nonroot(NETLINK_YAMIR, NL_NONROOT_RECV);

   cannot use python sl4a
  #define DYMO_PORT 20000
   ip addr add 192.168.0.1/24  brd + dev wlan0 label wlan0:dymo
   route add -net 224.0.0.0 netmask 240.0.0.0 dev eth0
   iptables -F (turn off iptables)
   iptables -I INPUT 1 -p udp --dst "224.0.0.109" -j ACCEPT

    cannot use getifaddrs - android ndk unsupported
    <module>: disagrees about version of symbol module_layout
    samsung c1_rev02_defconfig is incorrect.

   make ARCH=arm CROSS_COMPILE=arm-none-eabi- c1_rev02_defconfig
   make ARCH=arm CROSS_COMPILE=arm-none-eabi- modules_prepare
   make ARCH=arm CROSS_COMPILE=arm-none-eabi- modules
   make -j2 ARCH=arm CROSS_COMPILE=arm-none-eabi-

   linphone - use standard ports
   wirelesstools iwconfig
   psmisc killall

   arp req/rsp
   cat /proc/kmsg 
    ip route add 192.168.1.6/32 dev eth0 metric 1 via 192.168.1.6
    ethertype 802.1Q (0x8100) caused by linphone setsockopt IP_TOS
    strip --strip-unneeded 

   htc-desire 
     - need wireless firmware file from HTC Evo 4g to enable ad-hoc mode
     - Get Evo system dump, extract firmware file fw_bcm4329_ap.bin & rename to fw_bcm4329.bin
     - kernel/module version mismatc due to config file missing EXTRAVERSION var 

   samsung-s2
     - kernel config file on website differnt to what was used for production handsets
     - firmware sending out wirless frames with VLAN tags (802.1Q) which htc-desire cant grok

 * Refs
 * ----
 * draft-ietf-manet-dymo-21 Dynamic MANET On-demand (DYMO) Routing
 *
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
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
#include <unistd.h>

#include "netlink.h"
#include "util.h"
#include "log.h"
#include "list.h"
#include "timer.h"
#include "pbb.h"

#define YAMIR_MAXBUF 1024
#define YAMIR_MSGSIZE NLMSG_SPACE(sizeof(struct yamir_msg))
#define YAMIR_MAXCTRL CMSG_SPACE(sizeof(struct in_pktinfo))
#define YAMIR_MAXPKT 10
#define YAMIR_MAXTIMER 128

#define WBUF_SIZE (8 * 1024)
#define ADDR_STRLEN INET_ADDRSTRLEN + sizeof(":65535")
#define IPV4_ADDR(a,b,c,d) (uint32_t) (a << 24 | b << 16 | c << 8 | d)

// rfc5498 link local multicast address 224.0.0.109
//#define LL_MANET_ROUTERS IPV4_ADDR(224,0,0,109)
#define LL_MANET_ROUTERS "224.0.0.109"

// default settings from draft-ietf-manet-dymo-21.txt
#define DISCOVERY_ATTEMPTS_MAX 3

// all DYMO timeouts in secs mapped to ms
#define ROUTE_TIMEOUT (5 * 1000)
#define ROUTE_AGE_MIN_TIMEOUT (1 * 1000)
#define ROUTE_SEQNUM_AGE_MAX_TIMEOUT (60 * 1000)
#define ROUTE_USED_TIMEOUT ROUTE_TIMEOUT
#define ROUTE_DELETE_TIMEOUT (2 * ROUTE_TIMEOUT)
#define ROUTE_RREQ_WAIT_TIME (2 * 1000)
#define UNICAST_MESSAGE_SENT_TIMEOUT (1 * 1000)

volatile sig_atomic_t keep_running = 0;

// application state
struct yamir_state {
    // config
    char if_name[IFNAMSIZ];
    int port;
    int daemonize;
    int if_index;

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
    struct sockaddr_nl yamir_addr;

    // linux rtnetlink module
    int route_fd;
    struct sockaddr_nl route_addr;

    // lists
    struct list_elem requests;
    struct list_elem free_reqs;
    struct list_elem routes;
    struct list_elem free_routes;

    // timers
    struct timer_mgr timers;
    
    // recv buffers
    struct sockaddr_storage addr_pool[YAMIR_MAXPKT];
    struct mmsghdr msgs[YAMIR_MAXPKT];
    struct iovec   iovs[YAMIR_MAXPKT];
    uint8_t ctrl_pool[YAMIR_MAXPKT * YAMIR_MAXCTRL];
    uint8_t recv_pool[];
};

struct dymo_req {
    struct list_elem node;
    void *parent;
    uint32_t addr;
    int ifindex;
    struct timeval timestamp;
    int timer;
    time_t wait_time;
    int tries;
    uint16_t seqnum;
    uint8_t hop_count;
    
};

// DYMO message types
#define DYMO_RREQ 10
#define DYMO_RREP 11
#define DYMO_RERR 12

// 4.1 (addr are in network byte order)
struct dymo_route {
    struct list_elem node;
    void *parent;
    uint32_t addr;
    uint8_t prefix;
    int seqnum;
    uint32_t nexthop_addr;
    uint32_t nexthop_ifr;
    uint32_t flags;
    uint32_t dist;
    struct timeval timestamp;
    // timers
    int age_timer;
    int seqnum_timer;
    int used_timer;
    int del_timer;
};

// dymo route flags
#define DRF_IS_BROKEN    (1 << 0)
#define DRF_ADD_PENDING  (1 << 1)
#define DRF_DEL_PENDING  (1 << 2)
#define DRF_INSTALLED    (1 << 3)
#define DRF_HAS_DIST     (1 << 4)

// helpers
static inline bool dr_isbroken(const struct dymo_route *dr)
{
    return dr->flags & DRF_IS_BROKEN;
}

static inline bool dr_isadding(const struct dymo_route *dr)
{
    return dr->flags & DRF_ADD_PENDING;
}

static inline bool dr_isdeleting(const struct dymo_route *dr)
{
    return dr->flags & DRF_DEL_PENDING;
}

static inline bool dr_isinstalled(const struct dymo_route *dr)
{
    return dr->flags & DRF_INSTALLED;
}

static inline bool dr_dist(const struct dymo_route *dr)
{
    return dr->flags & DRF_HAS_DIST;
}

static inline bool yamir_islocaladdr(struct yamir_state *s, uint32_t addr)
{
    return s->local_addr == addr;
}

static const char *type_tostr(uint32_t type)
{
    static char *names[] = {
        [YAMIR_ROUTE_NEED] = "ROUTE_NEED",
        [YAMIR_ROUTE_INUSE] = "ROUTE_INUSE",
        [YAMIR_ROUTE_ERR] = "ROUTE_ERR",
        [YAMIR_ROUTE_NOTFOUND] = "ROUTE_NOTFOUND",
        [YAMIR_ROUTE_ADD] = "ROUTE_ADD",
        [YAMIR_ROUTE_DEL] = "ROUTE_DEL"
    };

    return type < ARR_LEN(names) ? names[type] : "!UNKNOWN";
}


#define RESPONSIBLE_ADDRESSES 0
#define MSG_HOPLIMIT 10

struct recv_state {
    uint32_t saddr;
    uint32_t maddr;
    uint32_t daddr;
    uint32_t ifidx;
};

static struct dymo_req *find_req(struct yamir_state *s, uint32_t addr);
static void dymo_req_done(struct dymo_req *req, int reason);
static int kyamir_send(struct yamir_state *ys, uint32_t type, uint32_t addr, int ifindex);
static int route_send(struct yamir_state *ys, int type, struct dymo_route *dr);

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

static void catch_signal(int signo, siginfo_t *info, void *ucontext)
{
    (void) ucontext;
    keep_running = 0;
}

static void route_delete(struct dymo_route *dr);

// find entry with longest prefix matching (rfc1812)
static struct dymo_route *route_find(struct yamir_state *ys, uint32_t addr)
{
    struct dymo_route *match = NULL;
    struct dymo_route *dr;

    addr = ntohl(addr);

    list_fornext_entry(&ys->routes, dr, node) {
        if (!match || dr->prefix > match->prefix) {
            uint32_t mask = (dr->prefix == 0) ? 0 : (~0U << (32 - dr->prefix));
            uint32_t raddr = ntohl(dr->addr);
            if ((addr & mask) == (raddr & mask)) {
                match = dr;
            }
        }
    }

    return match;
}

// section 5.2.1.
static int node_superior(struct pbb_node *mn, struct dymo_route *dr, int msg_type)
{
    // 1. stale (whats wrong with signed 32 bit)
    if ((int16_t) mn->seqnum - (int16_t) dr->seqnum < 0) {
        return 0;
    }

    // 2. loop possible
    if (mn->seqnum == dr->seqnum &&
       (!pbb_node_dist(mn) || !dr_dist(dr) || (mn->dist > dr->dist + 1)))
    {
        return 0;
    }

    // 3. inferior or equivalent
    if (mn->seqnum == dr->seqnum &&
       (((mn->dist == dr->dist + 1) && !dr_isbroken(dr)) ||
       (mn->dist == dr->dist && msg_type == DYMO_RREQ && !dr_isbroken((dr)))))
    {
        return 0;
    }

    return 1;
}

static void delete_timeout_cb(void *arg)
{
    struct dymo_route *dr = arg;

    dr->del_timer = -1;
    route_delete(dr);
}

static inline void stop_delete_timer(struct dymo_route *dr)
{
    if (dr->del_timer == -1) return;

    struct yamir_state *ys = dr->parent;

    timer_cancel(&ys->timers, dr->del_timer);
    dr->del_timer = -1;
}

static void start_delete_timer(struct dymo_route *dr)
{
    if (dr->del_timer != -1) return;

    log_debug("Starting delete timer");

    struct yamir_state *ys = dr->parent;

    dr->del_timer = timer_add(&ys->timers, 
        ROUTE_DELETE_TIMEOUT,
        delete_timeout_cb,
        dr);
}

// spec says its safe to delete after age timer expired
// but it make sense to allow start a delete timer
// similar to a route used logic
static void age_timeout_cb(void *arg)
{
    struct dymo_route *dr = arg;

    dr->age_timer = -1;
    start_delete_timer(dr);
}

static inline void stop_age_timer(struct dymo_route *dr)
{
    if (dr->age_timer == -1) return;

    struct yamir_state *ys = dr->parent;
    timer_cancel(&ys->timers, dr->age_timer);
    dr->age_timer = -1;
}

static void seqnum_timeout_cb(void *arg)
{
    struct dymo_route *dr = arg;

    dr->seqnum_timer = -1;
    dr->seqnum = 0;
}

static inline void stop_seqnum_timer(struct dymo_route *dr)
{
    if (dr->seqnum_timer == -1) return;

    struct yamir_state *ys = dr->parent;
    timer_cancel(&ys->timers, dr->seqnum_timer);
    dr->seqnum_timer = -1;
}

static inline void stop_used_timer(struct dymo_route *dr)
{
    if (dr->used_timer == -1) return;

    struct yamir_state *ys = dr->parent;
    timer_cancel(&ys->timers, dr->used_timer);
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
    stop_delete_timer(dr);
    stop_seqnum_timer(dr);
    stop_used_timer(dr);
    stop_age_timer(dr);
}

static void print_route(const char *prefix, struct dymo_route *dr)
{
    if (prefix) {
        log_debug("%s :",prefix);
    }

    log_debug("route addr=%s prefix=%d seqnum=%d "
        "nexthop=%s ifr=%d flags=%u dist=%d "
        "timestamp=%ld.%ld",
        addr_tostr(dr->addr),
        dr->prefix,
        dr->seqnum,
        addr_tostr(dr->nexthop_addr),
        dr->nexthop_ifr,
        dr->flags,
        dr->dist,
        dr->timestamp.tv_sec,
        dr->timestamp.tv_usec);
}

// note only remove yamir if expliclty requested (don't drop packets)
static void route_send_del(struct dymo_route *dr, int yamir)
{
    struct yamir_state *ys = dr->parent;

    if (!ys || !dr_isinstalled(dr)) return;
    dr->flags |= DRF_DEL_PENDING;

    // what to do if a netlink calls fail ?
    route_send(ys, RTM_DELROUTE, dr);

    if (yamir) {
        kyamir_send(ys, YAMIR_ROUTE_DEL, dr->addr, dr->nexthop_ifr);
    }
}

static void route_done(struct dymo_route *dr)
{
    struct yamir_state *ys = dr->parent;

    if (!ys) {
        free(dr);
        return;
    }

    list_append(&ys->free_routes, &dr->node);
}

static void route_delete(struct dymo_route *dr)
{
    list_remove(&dr->node);

    route_stop_timers(dr);
    route_send_del(dr, 1);
    route_done(dr);
}

static struct dymo_route *route_create(struct yamir_state *ys)
{
    struct dymo_route *dr;

    dr = list_first(&ys->free_routes, struct dymo_route, node);
    if (!dr) {
        // add new entry
        dr = malloc(sizeof(*dr));
        if (!dr) return NULL;
        list_init(&dr->node);
    }
    list_remove(&dr->node);
    memset(dr, 0, sizeof(*dr));
    dr->parent = ys;

    list_append(&ys->routes, &dr->node);

    return dr;
}

static int route_update(struct yamir_state *ys,
    int msg_type, struct pbb_node *mn,
    uint32_t nexthop_addr, uint32_t nexthop_ifr)
{
    struct dymo_route *dr = route_find(ys, mn->ip4_addr);
    if (dr && !node_superior(mn, dr, msg_type)) return 0;

    if (dr) {
        route_stop_timers(dr);
        // should we really be doing a route update ?
        // deleting the existing route creates a window where 
        // kernel has no route for valid packets
        route_send_del(dr, 0);
    }
    else {
        dr = route_create(ys);
    }

    // update entry 5.2.2
    gettimeofday(&dr->timestamp, NULL);
    dr->addr = mn->ip4_addr;
    // note prefix always set
    dr->prefix = mn->prefix;
    if (pbb_node_seqn(mn)) dr->seqnum = mn->seqnum;
    dr->nexthop_addr = nexthop_addr;
    dr->nexthop_ifr = nexthop_ifr;
    dr->flags &= ~DRF_IS_BROKEN;

    // route is consider superior so always set the distance
    dr->dist = 0;
    if (pbb_node_dist(mn)) {
        dr->flags |= DRF_HAS_DIST;
        dr->dist = mn->dist;
    }

    // restart route updated timers
    dr->age_timer = timer_add(&ys->timers, ROUTE_AGE_MIN_TIMEOUT, age_timeout_cb, dr);
    dr->seqnum_timer = timer_add(&ys->timers, ROUTE_SEQNUM_AGE_MAX_TIMEOUT, seqnum_timeout_cb, dr);

    // add route forwarding
    dr->flags |= DRF_ADD_PENDING;
    kyamir_send(ys, YAMIR_ROUTE_ADD, dr->addr, dr->nexthop_ifr);
    route_send(ys, RTM_NEWROUTE, dr);
    
    return 1;
}

static void yamir_inc_seqnum(struct yamir_state *ys)
{
    if (ys->own_seqnum >= 0xFFFF) {
        ys->own_seqnum = 0;
    }

    ys->own_seqnum++;
}

static int dymo_msg_send(struct yamir_state *ys, struct pbb_msg *msg, uint32_t addr)
{
    static unsigned char wbuf[WBUF_SIZE];

    log_debug("msg(type=%s flags=0x%x nodes=%d tlvs=%d) dst=%s", 
        pbb_type_tostr(msg->type), msg->flags, msg->num_node, msg->num_tlv, addr_tostr(addr));

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
    size_t len = pkt_buf_used(&buf);

    log_debug("sendto len=%zu dst=%s", len, sockaddr_tostr(&sin));

    ssize_t rc = sendto(ys->dymo_fd, wbuf, len, 0, (struct sockaddr *) &sin, sizeof(sin));
    if (rc == -1) return log_errno_rf("send_msg");

    return 0;
}

// 5.3.2 (send reply back to request originator)
static int dymo_reply_send(struct yamir_state *ys, struct pbb_msg *req)
{
    struct pbb_msg reply;

    pbb_msg_reset(&reply);

    reply.type = DYMO_RREP;

    // TODO get these values from routing table ?
    reply.target = pbb_copy_node(&reply, req->origin);
    reply.origin = pbb_copy_node(&reply, req->target);

    struct dymo_route *dr = route_find(ys, reply.target->ip4_addr);
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
    return dymo_msg_send(ys, &reply, dr->nexthop_addr);
}

static int dymo_reply_recv(struct yamir_state *ys, struct pbb_msg *reply)
{
    struct dymo_req *req;

    req = find_req(ys, reply->origin->ip4_addr);
    if (req) dymo_req_done(req, YAMIR_ROUTE_ADD);

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
    struct pbb_msg rerr;

    pbb_msg_reset(&rerr);

    rerr.type = DYMO_RERR;
    rerr.hop_limit = MSG_HOPLIMIT;
    rerr.flags |= PBB_MF_HLIM;

    struct pbb_node unreach = { 0 };
    unreach.ip4_addr = addr;
    if (seqnum > 0) {
        unreach.flags |= PBB_NF_SEQN;
        unreach.seqnum = seqnum;
    }
    if (prefix > 0) {
        unreach.flags |= PBB_NF_PREF;
        unreach.prefix = prefix;
    }

    return dymo_msg_send(ys, &rerr, ys->mcast_addr);
}

// 5.3.4 page 24 relay route-message
static int relay_rm(struct yamir_state *ys, struct pbb_msg *msg, struct recv_state *rs)
{
    // append addtional routing info

    // distance checks
    if (!inc_node_dist(msg->origin)) return 0;

    for (int i = 0; i < msg->num_node; i++) {
        struct pbb_node *mn = &msg->nodes[i];
        if (!inc_node_dist(mn)) {
            mn->flags |= PBB_NF_SKIP;
        }
    }

    // check if must discard
    if (!dec_hop_limit(msg)) return 0;

    // replies or unicast requests always sent via next hop addr
    uint32_t dst_addr;
    if (msg->type == DYMO_RREP || is_unicast(rs->daddr)) {
        // need check if rm can be routed towards target
        struct pbb_node *target = msg->target;
        struct dymo_route *dr = route_find(ys, target->ip4_addr);
        if (!dr) return dymo_rerr_send(ys, target->ip4_addr, target->seqnum, target->prefix);
        if (dr_isbroken(dr)) return dymo_rerr_send(ys, target->ip4_addr, dr->seqnum, target->prefix);
        dst_addr = dr->nexthop_addr;
    }
    else {
        dst_addr = ys->mcast_addr;
    }

    return dymo_msg_send(ys, msg, dst_addr);
}

// check valid route-message
static int validate_msg(struct yamir_state *s, struct pbb_msg *msg)
{
    // check required fields present
    if (!pbb_msg_hlim(msg)) return PBB_MSG_HLIM;
    if (!msg->target) return PBB_MSG_TNODE;
    if (!msg->origin) return PBB_MSG_ONODE;
    if (!pbb_node_seqn(msg->origin)) return PBB_MSG_OSEQN;
    if (msg->did != s->node_did) return PBB_MSG_TLV_DID;
    if (yamir_islocaladdr(s, msg->orig_ip4)) return PBB_MSG_OLADDR;

    return 0; 
}

static int handle_rreq(struct yamir_state *ys, struct pbb_msg *req, struct recv_state *rs)
{
    if (validate_msg(ys, req)) return 0;
    
    int orig_superior = route_update(ys, req->type, req->origin, rs->saddr, rs->ifidx);

    // additional nodes 
    for (int i = 0; i < req->num_node; i++) {
        struct pbb_node *mn = &req->nodes[i];
        if (!route_update(ys, req->type, mn, rs->saddr, rs->ifidx)) {
            mn->flags |= PBB_NF_SKIP;
        }
    }

    if (!orig_superior) return 0;

    // relay request-msg if not for us
    if (!yamir_islocaladdr(ys, req->target->ip4_addr)) {
        return relay_rm(ys, req, rs);
    }

    // request is for us
    return dymo_reply_send(ys, req);
}

static int handle_rrep(struct yamir_state *ys, struct pbb_msg *rep, struct recv_state *rs)
{
    if (validate_msg(ys, rep)) return 0;
    
    int orig_superior = route_update(ys, rep->type, rep->origin, rs->saddr, rs->ifidx);

    // additional nodes 
    for (int i = 0; i < rep->num_node; i++) {
        struct pbb_node *mn = &rep->nodes[i];
        if (!route_update(ys, rep->type, mn, rs->saddr, rs->ifidx)) {
            mn->flags |= PBB_NF_SKIP;
        }
    }

    if (!orig_superior) return 0;

    // relay reply-msg if not for us
    if (!yamir_islocaladdr(ys, rep->target->ip4_addr)) {
        return relay_rm(ys, rep, rs);
    }

    // reply is for us
    return dymo_reply_recv(ys, rep);
}

// RERR handling page 28
static int route_broken(struct yamir_state *ys, struct pbb_node *mn, uint32_t sender)
{
    if (!is_unicast(mn->ip4_addr)) return 0;

    struct dymo_route *dr = route_find(ys, mn->ip4_addr);
    if (!dr) return 0;

    if (!dr_isbroken(dr) &&
        (dr->nexthop_addr == sender &&
        (dr->seqnum == 0 || mn->seqnum == 0 
         || !pbb_node_seqn(mn)
         || ((int16_t) dr->seqnum - (int16_t) mn->seqnum  <= 0))))
    {
        dr->flags |= DRF_IS_BROKEN;
        route_send_del(dr, 1);
        start_delete_timer(dr);
        return 1;
    }

    return 0;
}

static int validate_rerr(struct yamir_state *s, struct pbb_msg *rerr)
{
    if (!pbb_msg_hlim(rerr)) return PBB_MSG_HLIM;
    if (rerr->num_node == 0) return PBB_NODE_UNREACH;
    if (rerr->did != s->node_did) return PBB_MSG_TLV_DID;

    return 0;
}

static void handle_rerr(struct yamir_state *s, struct pbb_msg *rerr, struct recv_state *state)
{
    // first check required fields present
    if (validate_rerr(s, rerr)) return;

    // need to scan our routes
    int num_skip = 0;
    for (int i = 0; i < rerr->num_node; i++) {
        struct pbb_node *mn = &rerr->nodes[i];
        if (!route_broken(s, mn, state->saddr)) {
            mn->flags |= PBB_NF_SKIP;
            num_skip++;
        }
    }

    // discard if no unreachable nodes left
    if (num_skip == rerr->num_node) return;

    // discard if hop limit reached
    if (!dec_hop_limit(rerr)) return;

    // relay rerr
    // not sure what standard means by here by NextHopAddress
    // for unicast RERR is this the nexthopaddress for the unreachable node
    // or the actual ip destiation address (what happens if there are more
    // than 1 unreachable node in the RERR packet ?
    dymo_msg_send(s, rerr, s->mcast_addr);
}

static struct dymo_req *req_create(struct yamir_state *s)
{
    struct dymo_req *req;

    req = list_first(&s->free_reqs, struct dymo_req, node);
    if (!req) {
        req = malloc(sizeof(*req));
        if (!req) return NULL;
        list_init(&req->node);
    }

    list_remove(&req->node);
    memset(req, 0, sizeof(*req));
    req->parent = s;

    return req;

    return req;
}

static void dymo_req_free(struct dymo_req *req)
{
    struct yamir_state *ys = req->parent;

    if (!ys) {
        free(req);
        return;
    }

    list_append(&ys->free_reqs, &req->node);
}

static struct dymo_req *find_req(struct yamir_state *ys, uint32_t addr)
{
    struct dymo_req *req;

    list_fornext_entry(&ys->requests, req, node) {
        if (req->addr == addr) return req;
    }

    return NULL; 
}

static void dymo_req_send(struct yamir_state *ys, struct dymo_req *req)
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
    if (!target) return log_error_rv("Add target failed");
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
    if (!origin) return log_error_rv("Add origin failed");
    msg.origin = origin;
    origin->ip4_addr = ys->local_addr;
    //origin->flags |= PBB_NF_SEQN;
    origin->seqnum = ys->own_seqnum;

    // multicast request
    log_debug("Sending RREQ target=%s origin=%s seqnum=%d",  
        addr_tostr(target->ip4_addr), 
        addr_tostr(origin->ip4_addr),
        origin->seqnum);

    dymo_msg_send(ys, &msg, ys->mcast_addr);
}

static void dymo_req_timeout(void *arg);

// send request out - route/timer/send
static void dymo_req_out(struct dymo_req *req)
{
    struct yamir_state *ys = req->parent;
    struct dymo_route *dr = route_find(ys, req->addr);

    if (dr) {
        // have info about the target
        req->seqnum = dr->seqnum;
        req->hop_count = dr->dist;
    }
    else {
        req->seqnum = 0;
        req->hop_count = 0;
    }

    log_debug("RREQ %s attempt %d/%d wait %ld", 
        addr_tostr(req->addr),
        req->tries, 
        DISCOVERY_ATTEMPTS_MAX,
        req->wait_time);

    // try again
    req->timer = timer_add(&ys->timers, req->wait_time, dymo_req_timeout, req);
    dymo_req_send(ys, req);
}

static void dymo_req_timeout(void *arg) 
{
    struct dymo_req *req = arg;

    req->timer = -1;

    log_debug("RREQ %s timeout %d/%d", addr_tostr(req->addr), req->tries, DISCOVERY_ATTEMPTS_MAX);

    if (req->tries < DISCOVERY_ATTEMPTS_MAX) {
        // try again
        req->tries += 1;
        req->wait_time = req->wait_time * 2;
        dymo_req_out(req);
    }
    else {
        dymo_req_done(req, YAMIR_ROUTE_NOTFOUND);
    }
}

static void route_discover(struct yamir_state *ys, uint32_t daddr, int ifidx)
{
    log_debug("route_discover(%s,%d)", addr_tostr(daddr), ifidx);

    struct dymo_req *req = find_req(ys, daddr);
    if (req) {
        log_debug("req already in progress");
        return;
    }

    req = req_create(ys);
    req->addr = daddr;
    req->ifindex = ifidx;
    req->tries = 1;
    req->wait_time = ROUTE_RREQ_WAIT_TIME;
    gettimeofday(&req->timestamp, NULL);

    list_append(&ys->requests, &req->node);

    dymo_req_out(req);
}

// section 5.5.2
static void route_inuse(struct yamir_state *ys, uint32_t addr, int if_index)
{
    log_debug("addr=%s if_index=%d", addr_tostr(addr), if_index);

    struct dymo_route *dr = route_find(ys, addr);
    if (!dr) return;

    // can't really attend to a route thats been marked as broken
    if (dr_isbroken(dr)) {
        log_debug("route_update(%s:%d) route is broken", addr_tostr(dr->addr), dr->flags);
        return;
    }

    stop_delete_timer(dr);
    stop_used_timer(dr);

    // need this for new/updated routes
    stop_age_timer(dr);

    // restart used timer
    dr->used_timer = timer_add(&ys->timers, ROUTE_USED_TIMEOUT, used_timeout_cb, dr);
}

// section 5.5 a data packet to be forwarded has no route
static void route_err(struct yamir_state *ys, uint32_t addr, int ifindex)
{
    log_debug("%s:%d", addr_tostr(addr), ifindex);

    int seqnum;
    struct dymo_route *dr = route_find(ys, addr);

    if (dr) {
        if (!dr_isbroken(dr)) {
            // looks like our kernel module lost some route details
            print_route("Not broken!", dr);
            if (dr_isinstalled(dr)) {
                // update kernel
                kyamir_send(ys, YAMIR_ROUTE_ADD, dr->addr, dr->nexthop_ifr);
            }
            return;
        }
        // draft says we should use seqnum if we have one
        seqnum = dr->seqnum;
    }
    else {
        // normal case kernel module has no forwarding route
        seqnum = 0;
    }

    // TODO shoud we get prefix from interface
    dymo_rerr_send(ys, addr, seqnum, 0);
}

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
        rs->ifidx = 0;
        rs->maddr = 0;
        rs->daddr = 0;

        if (m->msg_flags & MSG_CTRUNC) continue;
        if (m->msg_controllen < sizeof(struct cmsghdr)) continue;

        for (struct cmsghdr *cm = CMSG_FIRSTHDR(m); cm; cm = CMSG_NXTHDR(m, cm)) {
            if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_PKTINFO) {
                struct in_pktinfo *pi = (struct in_pktinfo *) CMSG_DATA(cm);
                rs->ifidx = pi->ipi_ifindex;
                rs->maddr = pi->ipi_spec_dst.s_addr;
                rs->daddr = pi->ipi_addr.s_addr;
            }
        }
    }

    return nr;
}

// process incoming dymo message packet
static int dymo_process_mmsg(struct yamir_state *ys,
    struct mmsghdr *mmsg, struct recv_state *rs)
{
    uint8_t *pkt = mmsg->msg_hdr.msg_iov->iov_base;
    size_t len = mmsg->msg_len;

    log_debug("recv %zu bytes src=%s dst=%s ifr=%d",
        len, addr_tostr(rs->saddr), addr_tostr(rs->daddr), rs->ifidx);

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

    while (pkt_buf_avail(&buf)) {
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

static void dymo_req_done(struct dymo_req *req, int reason)
{
    list_remove(&req->node);

    struct yamir_state *ys = req->parent;

    if (req->timer != -1) {
        if (ys) timer_cancel(&ys->timers, req->timer);
        req->timer = -1;
    }

    // update_route takes care of kernel routing
    if (ys && reason != YAMIR_ROUTE_ADD) {
        kyamir_send(req->parent, reason, req->addr, req->ifindex);
    }

    dymo_req_free(req);
}


// function from iproute2 used in quagga/zebra
static int addattr_l(struct nlmsghdr *n, size_t maxlen, int type, void *data, int alen)
{
    int len = RTA_LENGTH(alen);
    if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen) {
        return log_error_rf("addattr_l %d failed", type);
    }

    struct rtattr *rta = (struct rtattr *) (((char *) n) + NLMSG_ALIGN (n->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy (RTA_DATA (rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + len;

    return 0;
}

// send msg to kyamir
static int kyamir_send(struct yamir_state *ys, uint32_t type, uint32_t addr, int ifindex)
{
    char buf[NLMSG_SPACE(sizeof(struct yamir_msg))];

    // first setup the netlink header
    struct nlmsghdr *hdr_ptr = (struct nlmsghdr *) buf;
    hdr_ptr->nlmsg_len = sizeof(buf);
    hdr_ptr->nlmsg_type = type;
    hdr_ptr->nlmsg_flags = NLM_F_REQUEST;
    hdr_ptr->nlmsg_seq = 0; 
    hdr_ptr->nlmsg_pid = getpid();

    // setup our message
    struct yamir_msg *msg_ptr = NLMSG_DATA(hdr_ptr);
    msg_ptr->addr = addr;
    msg_ptr->ifindex = ifindex;

    // load buffer address
    struct iovec iov[1];
    iov[0].iov_base = buf;
    iov[0].iov_len = hdr_ptr->nlmsg_len;

    // setup dest addr
    struct sockaddr_nl dest;
    memset(&dest, 0, sizeof(struct sockaddr_nl));
    dest.nl_family = AF_NETLINK;
    dest.nl_pid = 0;
    dest.nl_groups = 0;

    // setup the datagram message
    struct msghdr msg;
    msg.msg_name = &dest;
    msg.msg_namelen = sizeof(dest);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    log_debug("msg type=%s addr=%s if=%d", type_tostr(type), addr_tostr(addr), ifindex);

    int ec = sendmsg(ys->kyamir_fd, &msg, 0); 
    if (ec == -1) return log_errno_rf("netlink_send");

    return 0;
}

// process yamir_msg from kyamir
static void kyamir_process_msg(struct yamir_state *ys, int type, struct yamir_msg *msg)
{
    log_debug("type=%s addr=%s if=%d", type_tostr(type), addr_tostr(msg->addr), msg->ifindex);

    switch(type) {
    case YAMIR_ROUTE_NEED:  route_discover(ys, msg->addr, msg->ifindex); break;
    case YAMIR_ROUTE_INUSE: route_inuse(ys, msg->addr, msg->ifindex); break;
    case YAMIR_ROUTE_ERR:   route_err(ys, msg->addr, msg->ifindex); break;
    default: log_debug("Unsupported netlink msg type %d\n", type); break;
    }
}

// process mmsg from kyamir
static void kyamir_process_mmsg(struct yamir_state *ys, struct mmsghdr *mmsg)
{
    log_debug("msg len=%u", mmsg->msg_len);

    struct nlmsghdr *nlh = mmsg->msg_hdr.msg_iov->iov_base;
    size_t msg_len = mmsg->msg_len;

    for (; NLMSG_OK(nlh, msg_len); nlh = NLMSG_NEXT(nlh, msg_len)) {
        if (nlh->nlmsg_type == NLMSG_DONE) break;
        if (nlh->nlmsg_type == NLMSG_ERROR) continue;
        struct yamir_msg *msg = NLMSG_DATA(nlh);
        size_t len = NLMSG_PAYLOAD(nlh, 0);
        if (len < sizeof(*msg)) continue;
        kyamir_process_msg(ys, nlh->nlmsg_type, msg);
    }
}

// recv msgs from kyamir
static int kyamir_recv(struct yamir_state *ys)
{
    log_debug("recv kyamird_fd=%d", ys->kyamir_fd);

    int nr = recvmmsg(ys->kyamir_fd, ys->msgs, YAMIR_MAXPKT, MSG_DONTWAIT, NULL);
    if (nr < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
        return log_errno_rf("recvmmsg %d failed", ys->kyamir_fd);
    }

    for (int i = 0; i < nr; i++) {
        kyamir_process_mmsg(ys, &ys->msgs[i]);
    }

    return 0;
}

static void route_process_mmsg(struct yamir_state *ys, struct mmsghdr *msg)
{
    // TODO convert route update to dymo_route
    return;
}

// recv route msg from kernel
static int route_recv(struct yamir_state *ys)
{
    log_debug("recv route_fd=%d", ys->route_fd);

    int nr = recvmmsg(ys->kyamir_fd, ys->msgs, YAMIR_MAXPKT, MSG_DONTWAIT, NULL);
    if (nr < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
        return log_errno_rf("recvmmsg %d failed", ys->kyamir_fd);
    }

    for (int i = 0; i < nr; i++) {
        route_process_mmsg(ys, &ys->msgs[i]);
    }

    return 0;
}

/* 
 * we support add/delete ipv4 routes only
 * ./linux/rtnetlink.h
 * route add dest/prefix dev if metric hop_count via nexthop_addr"
 * TODO 
 * probably should request successful route updates from kernel via
 * a NLM_F_ACK flag but this means async routing updates with 
 * callback to original route change request
*/
static int route_send(struct yamir_state *ys, int type, struct dymo_route *dr)
{
    // TODO dynamically allocate a buffer of the correct size
    static struct {
        struct nlmsghdr nlm;
        struct rtmsg rtm;
        char buf[512];
    } req;

    // setup netlink msg header
    struct nlmsghdr *nlm = &req.nlm;
    memset(nlm, 0, sizeof(*nlm));
    nlm->nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg)); 
    nlm->nlmsg_type  = type;
    nlm->nlmsg_flags = NLM_F_REQUEST;
    nlm->nlmsg_pid   = getpid();
    
    if (type == RTM_NEWROUTE) {
        nlm->nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
    }
    uint32_t dst_prefix = dr->prefix;
    if (dst_prefix == 0) dst_prefix = 32;
   
    // setup rtnetlink msg 
    struct rtmsg *rtm = &req.rtm;
    memset(rtm, 0, sizeof(*rtm));
    rtm->rtm_family   = AF_INET;
    rtm->rtm_dst_len  = dst_prefix;
    rtm->rtm_table    = RT_TABLE_MAIN;
    rtm->rtm_protocol = YAMIR_RTNETLINK;
    rtm->rtm_scope    = RT_SCOPE_LINK;
    rtm->rtm_type     = RTN_UNICAST;

    // add rtattr (dst,interface, metric, gateway)
    addattr_l(nlm, sizeof(req), RTA_DST, &dr->addr, sizeof(&dr->addr));
    addattr_l(nlm, sizeof(req), RTA_OIF, &dr->nexthop_ifr, sizeof(&dr->nexthop_ifr));
    addattr_l(nlm, sizeof(req), RTA_PRIORITY, &dr->dist, sizeof(&dr->dist));

    if (dr->addr != dr->nexthop_addr) {
        rtm->rtm_scope = RT_SCOPE_UNIVERSE;
        addattr_l(nlm, sizeof(req), RTA_GATEWAY, &dr->nexthop_addr, sizeof(dr->nexthop_addr));
    }

    // load buffer address
    struct iovec iov[1];
    iov[0].iov_base = &req;
    iov[0].iov_len = req.nlm.nlmsg_len;

    // setup dest addr
    struct sockaddr_nl dest;
    memset(&dest, 0, sizeof(struct sockaddr_nl));
    dest.nl_family = AF_NETLINK;
    dest.nl_pid = 0; // kernel
    dest.nl_groups = 0;

    // setup the datagram message itself
    struct msghdr msg;
    msg.msg_name = &dest;
    msg.msg_namelen = sizeof(dest);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    int ec = sendmsg(ys->route_fd, &msg, 0); 
    if (ec == -1) return log_errno_rf("rnetlink_send");

    return 0;
}

// setup NETLINK interface to kyamir kernel module and linux routing tables
static int netlink_init(struct yamir_state *ys)
{
    log_debug("init kyamir-nl=%d route-nl=%d", NETLINK_YAMIR, NETLINK_ROUTE);

    // setup netlink interface to our kernel module
    ys->kyamir_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_YAMIR);
    if (ys->kyamir_fd == -1) return log_errno_rf("socket netlink_yamir");

    // bind to address
    struct sockaddr_nl *nl_addr = &ys->yamir_addr;
    nl_addr->nl_family = AF_NETLINK;
    nl_addr->nl_pid = getpid();
    nl_addr->nl_groups = NETLINK_YAMIR_GROUP; //NETLINK_DYMO_GROUP; 
    int ec = bind(ys->kyamir_fd, (struct sockaddr *) nl_addr, sizeof(*nl_addr));
    if (ec == -1) return log_errno_rf("bind netlink_yamir");

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
    log_debug("init ifname=%s", ys->if_name);

    // create the socket 
    int sock_type =  SOCK_DGRAM | SOCK_NONBLOCK;
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
    sin->sin_port = htons(DYMO_PORT);
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

    while ((opt = getopt(argc, argv, "i:p:l:dh")) != -1) {
        switch(opt) {
        case 'i':  // interface
            len = strlen(optarg);
            if (len >= sizeof(ys->if_name)) return log_error_rf("ifname len %zu too big", len);
            memcpy(ys->if_name, optarg, len);
            break;
        case 'p': ys->port   = atoi(optarg); break;
        case 'l': log_level = atoi(optarg); break;
        case 'd': ys->daemonize = 1; break;
        case 'h': usage(argv[0]); exit(0); break;
        default: return log_error_rf("Unknown option %c\n", opt);
        }
    }

    // check reqired args
    if (!ys->if_name[0]) return log_error_rf("Missing ifname");

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
    list_init(&ys->requests);
    list_init(&ys->free_reqs);
    list_init(&ys->routes);
    list_init(&ys->free_routes);

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
        ys->msgs[i].msg_hdr.msg_control = &ys->ctrl_pool[i * YAMIR_MAXCTRL];
        ys->msgs[i].msg_hdr.msg_controllen = YAMIR_MAXCTRL;
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
    int wait_ms = -1;

    while (keep_running) {
        wait_ms = timer_check(&ys->timers);
        int rc = poll(fds, ARR_LEN(fds), wait_ms); 
        if (rc <= 0) {
            if (rc == 0 || errno == EINTR) continue;
            break;
        }
        if ((fds[0].revents & mask) && dymo_recv(ys)) break;
        if ((fds[1].revents & mask) && kyamir_recv(ys)) break;
        if ((fds[2].revents & mask) && route_recv(ys)) break;
    }

done:
    if (ys) yamir_free(ys);

    return ec;
}
