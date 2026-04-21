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
    
   sudo setcap cap_net_bind_service,cap_net_raw=+ep some-binary

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

#include "util.h"
#include "list.h"
#include "netlink.h"
#include "pbb.h"

#define RTNETLINK_YAMIR 30

#define RBUF_SIZE 1024 * 8
#define WBUF_SIZE 1024 * 8
#define ADDR_STRLEN INET_ADDRSTRLEN + sizeof(":65535")

#define IPV4_ADDR(a,b,c,d) (uint32_t) (a << 24 | b << 16 | c << 8 | d)

// rfc5498 link local multicast address 224.0.0.109
//#define LL_MANET_ROUTERS IPV4_ADDR(224,0,0,109)
#define LL_MANET_ROUTERS "224.0.0.109"

// default settings from draft-ietf-manet-dymo-21.txt
#define DISCOVERY_ATTEMPTS_MAX 3

#define ROUTE_TIMEOUT 5
#define ROUTE_AGE_MIN_TIMEOUT 1
#define ROUTE_SEQNUM_AGE_MAX_TIMEOUT 60
#define ROUTE_USED_TIMEOUT ROUTE_TIMEOUT
#define ROUTE_DELETE_TIMEOUT (2 * ROUTE_TIMEOUT)
#define ROUTE_RREQ_WAIT_TIME 2
#define UNICAST_MESSAGE_SENT_TIMEOUT 1

volatile sig_atomic_t keep_running = 0;


struct yamir_serv {
    // config
    char if_name[IFNAMSIZ];
    int port;
    int daemonize;
    int if_index;
    uint32_t node_did;
    uint16_t own_seqnum;
    // dymo
    int dymo_fd;
    struct sockaddr_in if_addr;
    uint32_t local_addr;
    uint32_t bcast_addr;
    uint32_t mcast_addr;
    // our netlink module
    int kyamir_fd;
    struct sockaddr_nl yamir_addr;
    // kernel rtnetlink module
    int route_fd;
    struct sockaddr_nl route_addr;
    // lists
    struct list_elem requests;
    struct list_elem free_reqs;
    struct list_elem routes;
    struct list_elem free_routes;
};

struct dymo_req {
    struct list_elem node;
    void *parent;
    uint32_t addr;
    int ifindex;
    struct timeval timestamp;
    struct timer *timer;
    time_t wait_time;
    int tries;
};

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
    struct timer *age_timer;
    struct timer *seqnum_timer;
    struct timer *used_timer;
    struct timer *delete_timer;
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

static inline bool dr_has_dist(const struct dymo_route *dr)
{
    return dr->flags & DRF_HAS_DIST;
}

static inline bool yamir_islocaladdr(struct yamir_serv *s, uint32_t addr)
{
    return s->local_addr == addr;
}

// N.B all addr are stored in network byte order

// message types
#define DYMO_RREQ 10
#define DYMO_RREP 11
#define DYMO_RERR 12

#define RESPONSIBLE_ADDRESSES 0
#define MSG_HOPLIMIT 10

// ipv4= 4, ipv6=16
#define MAX_ADDR_LEN 4


struct recv_state {
    uint32_t saddr;
    uint32_t maddr;
    uint32_t daddr;
    uint32_t ifindex;
};

static struct dymo_req *find_req(struct yamir_serv *s, uint32_t addr);
static void dymo_req_done(struct dymo_req *req, int reason);
static int kyamir_send(struct yamir_serv *s, uint32_t type, uint32_t addr, int ifindex);
static int route_send(struct yamir_serv *s, int type, struct dymo_route *dr);

static const char *sockaddr_tostr(struct sockaddr_in *sa)
{
    static char bufs[4][ADDR_STRLEN]; 
    static int idx;

    char *buf = bufs[idx];
    size_t len = sizeof(bufs[0]);
    idx = (idx + 1) & 3;

    const char *str = inet_ntop(AF_INET, &sa->sin_addr, buf, len);
    if (!str) return "???";

    size_t nw = strlen(str);
    len -= nw;
    buf += nw;
    snprintf(buf, len, ":%d", ntohs(sa->sin_port));

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
static struct dymo_route *route_find(struct yamir_serv *s, uint32_t addr)
{
    struct dymo_route *match = NULL;
    struct dymo_route *dr;

    addr = ntohl(addr);

    list_fornext_entry(&s->routes, dr, node) {
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
static int node_superior(struct msg_node *mn, struct dymo_route *dr, int msg_type)
{
    // 1. stale (whats wrong with signed 32 bit)
    if ((int16_t) mn->seqnum - (int16_t) dr->seqnum < 0) {
        return 0;
    }

    // 2. loop possible
    if (mn->seqnum == dr->seqnum &&
       (!mn_has_dist(mn) ||
        !dr_has_dist(dr) ||
        (mn->dist > dr->dist + 1)))
    {
        return 0;
    }

    // 3. inferior or equivalent
    if (mn->seqnum == dr->seqnum &&
       (((mn->dist == dr->dist + 1) && !dr_isbroken(dr)) ||
       ((mn->dist == dr->dist) && 
         msg_type == DYMO_RREQ && !dr_isbroken((dr)))))
    {
        return 0;
    }

    return 1;
}

static void delete_timeout_cb(void *arg)
{
    struct dymo_route *dr = arg;

    dr->delete_timer = NULL;
    route_delete(dr);
}

static inline void stop_delete_timer(struct dymo_route *dr)
{
    if (!dr->delete_timer) return;

    timer_del(dr->delete_timer);
    dr->delete_timer = NULL;
}

static void start_delete_timer(struct dymo_route *dr)
{
    if (dr->delete_timer) return;
    log_debug("Starting delete timer");

    dr->delete_timer = timer_add_wsec(
        delete_timeout_cb,
        dr, 
        ROUTE_DELETE_TIMEOUT);
}

// spec says its safe to delete after age timer expired
// but it make sense to allow start a delete timer
// similar to a route used logic
static void age_timeout_cb(void *cb_arg)
{
    struct dymo_route *dr = cb_arg;

    dr->age_timer = NULL;
    start_delete_timer(dr);
}

static inline void stop_age_timer(struct dymo_route *dr)
{
    if (!dr->age_timer) return;

    timer_del(dr->age_timer);
    dr->age_timer = NULL;
}

static void seqnum_timeout_cb(void *cb_arg)
{
    struct dymo_route *dr = cb_arg;

    dr->seqnum_timer = NULL;
    dr->seqnum = 0;
}

static inline void stop_seqnum_timer(struct dymo_route *dr)
{
    if (!dr->seqnum_timer) return;
    timer_del(dr->seqnum_timer);
    dr->seqnum_timer = NULL;
}

static inline void stop_used_timer(struct dymo_route *dr)
{
    if (!dr->used_timer) return;
    timer_del(dr->used_timer);
    dr->used_timer = NULL;
}

// 5.2.3.3.
static void used_timeout_cb(void *cb_arg)
{
    struct dymo_route *dr = cb_arg;

    dr->used_timer = NULL;
    start_delete_timer(dr);
}

static void stop_all_timers(struct dymo_route *dr)
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
    struct yamir_serv *s = dr->parent;
    if (!s || !dr_isinstalled(dr)) return;

    dr->flags |= DRF_DEL_PENDING;

    // what to do if a netlink calls fail ?
    route_send(s, RTM_DELROUTE, dr);

    if (yamir) {
        kyamir_send(s, YAMIR_ROUTE_DEL, dr->addr, dr->nexthop_ifr);
    }
}

static void route_done(struct dymo_route *dr)
{
    struct yamir_serv *s = dr->parent;

    if (!s) {
        free(dr);
        return;
    }

    list_append(&s->free_routes, &dr->node);
}

static void route_delete(struct dymo_route *dr)
{
    list_remove(&dr->node);

    stop_all_timers(dr);
    route_send_del(dr, 1);
    route_done(dr);
}

static struct dymo_route *route_create(struct yamir_serv *s)
{
    struct dymo_route *dr;

    // adding new entry
    dr = list_first(&s->free_routes, struct dymo_route, node);
    if (!dr) {
        dr = malloc(sizeof(*dr));
        if (!dr) return NULL;
        list_init(&dr->node);
    }
    list_remove(&dr->node);
    memset(dr, 0, sizeof(*dr));
    dr->parent = s;

    list_append(&s->routes, &dr->node);

    return dr;
}

static int route_update(struct yamir_serv *s,
    int msg_type, struct msg_node *mn,
    uint32_t nexthop_addr, uint32_t nexthop_ifr)
{
    struct dymo_route *dr = route_find(s, mn->ip4_addr);
    if (dr && !node_superior(mn, dr, msg_type)) return 0;

    if (dr) {
        stop_all_timers(dr);
        // should we really be doing a route update ?
        // deleting the existing route creates a window where 
        // kernel has no route for valid packets
        route_send_del(dr, 0);
    }
    else {
        dr = route_create(s);
    }

    // update entry 5.2.2
    gettimeofday(&dr->timestamp, NULL);
    dr->addr = mn->ip4_addr;
    // note prefix always set
    dr->prefix = mn->prefix;
    if (mn_has_seqn(mn)) dr->seqnum = mn->seqnum;
    dr->nexthop_addr = nexthop_addr;
    dr->nexthop_ifr = nexthop_ifr;
    dr->flags &= ~DRF_IS_BROKEN;

    // route is consider superior so always set the distance
    dr->dist = 0;
    if (mn_has_dist(mn)) {
        dr->flags |= DRF_HAS_DIST;
        dr->dist = mn->dist;
    }

    // restart route updated timers
    dr->age_timer = timer_add_wsec(age_timeout_cb, dr, ROUTE_AGE_MIN_TIMEOUT);
    dr->seqnum_timer = timer_add_wsec(seqnum_timeout_cb, dr, ROUTE_SEQNUM_AGE_MAX_TIMEOUT);

    // add route forwarding
    dr->flags |= DRF_ADD_PENDING;
    kyamir_send(s, YAMIR_ROUTE_ADD, dr->addr, dr->nexthop_ifr);
    route_send(s, RTM_NEWROUTE, dr);
    
    return 1;
}

static void yamir_inc_seqnum(struct yamir_serv *s)
{
    if (s->own_seqnum >= 0xFFFF) {
        s->own_seqnum = 0;
    }

    s->own_seqnum++;
}

static int send_dymo_msg(struct yamir_serv *s, struct pbb_msg *msg, uint32_t dest)
{
    static unsigned char wbuf[WBUF_SIZE];

    // encode pkt
    ssize_t rc = pbb_msg_encode(msg, wbuf, sizeof(wbuf));
    if (rc <= 0) return rc;
    size_t len = rc;

    // TODO implement rfc5148 jitter

    // should we use getaddrinfo() ?
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = dest;
    addr.sin_port = htons(DYMO_PORT);

    log_debug("msg(type=%d,len=%zu) dst=%s", msg->type, len, sockaddr_tostr(&addr));

    rc = sendto(s->dymo_fd, wbuf, len, 0, (struct sockaddr *) &addr, sizeof(addr));
    if (rc == -1) return log_errno_rf("send_msg");

    return 0;
}

// 5.3.2 (send reply back to request originator)
static int send_dymo_reply(struct yamir_serv *s, struct pbb_msg *req)
{
    struct pbb_msg reply;

    pbb_msg_reset(&reply);

    reply.type = DYMO_RREP;

    // TODO get these values from routing table ?
    reply.target = pbb_msg_add_node(&reply, req->origin);
    reply.origin = pbb_msg_add_node(&reply, req->target);

    struct dymo_route *dr = route_find(s, reply.target->ip4_addr);
    if (!dr) return log_error_rf("No route to target");

    if (!mn_has_seqn(reply.target) ||
        ((int16_t) reply.target->seqnum - (int16_t) s->own_seqnum < 0) ||
        (reply.target->seqnum == s->own_seqnum && !mn_has_dist(reply.origin)))
    {
        yamir_inc_seqnum(s);
    }

    reply.origin->seqnum = s->own_seqnum;
    reply.origin->flags |= PBB_NF_SEQN;

    reply.hop_limit = MSG_HOPLIMIT;
    reply.flags |= PBB_MF_HLIM;
    reply.addr_len = 4;

    // we route the message via the next hop
    return send_dymo_msg(s, &reply, dr->nexthop_addr);
}

static int recv_dymo_reply(struct yamir_serv *s, struct pbb_msg *reply)
{
    struct dymo_req *req;

    req = find_req(s, reply->origin->ip4_addr);
    if (req) dymo_req_done(req, YAMIR_ROUTE_ADD);

    return 0;
}

// multihop-capbable unicast address (todo add prefix/if mask)
static int unicast_addr(uint32_t addr)
{
    uint32_t tmp_addr = ntohl(addr);

    // broadcast address 255.255.255.255
    if (tmp_addr == 0xF0000000) return 0;

    // class D multicast address 224.0.0.0 - 239.255.255.255 (fb=0xE0.0xEF)
    if ((tmp_addr & 0xF0000000) == 0xE0000000) return 0;

    return 1;
}

static int inc_node_dist(struct msg_node *mn)
{
    if (mn_has_dist(mn)) {
        if (mn->dist >= 0xFFFF) return 0;
        mn->dist++;
    }

    return 1;
}

static int dec_hop_limit(struct pbb_msg *msg)
{
    if (pbb_msg_has_hlim(msg)) {
        if (msg->hop_limit == 0) return 0;
        msg->hop_limit--;
        if (msg->hop_limit == 0) return 0;
    }

    return 1;
}

// 5.5.3 rm message or data packet cannot be routed to addr
// TODO add unicast support
static int send_dymo_rerr(struct yamir_serv *s, uint32_t addr, uint16_t seqnum, uint8_t prefix)
{
    struct pbb_msg rerr;

    pbb_msg_reset(&rerr);

    rerr.type = DYMO_RERR;
    rerr.hop_limit = MSG_HOPLIMIT;
    rerr.flags |= PBB_MF_HLIM;

    struct msg_node unreach = { 0 };
    unreach.ip4_addr = addr;
    if (seqnum > 0) {
        unreach.flags |= PBB_NF_SEQN;
        unreach.seqnum = seqnum;
    }
    if (prefix > 0) {
        unreach.flags |= PBB_NF_PREF;
        unreach.prefix = prefix;
    }

    return send_dymo_msg(s, &rerr, s->mcast_addr);
}

// 5.3.4 page 24 relay route-message
static int relay_rm(struct yamir_serv *s, struct pbb_msg *msg, struct recv_state *state)
{
    // append addtional routing info

    // distance checks
    if (!inc_node_dist(msg->origin)) return 0;

    for (int i = 0; i < msg->num_node; i++) {
        struct msg_node *mn = &msg->nodes[i];
        if (!inc_node_dist(mn)) {
            mn->flags |= PBB_NF_SKIP;
        }
    }

    // check if must discard
    if (!dec_hop_limit(msg)) return 0;

    // replies or unicast requests always sent via next hop addr
    uint32_t dst_addr;
    if (msg->type == DYMO_RREP || unicast_addr(state->daddr)) {
        // need check if rm can be routed towards target
        struct msg_node *target = msg->target;
        struct dymo_route *dr = route_find(s, target->ip4_addr);
        if (!dr) return send_dymo_rerr(s, target->ip4_addr, target->seqnum, target->prefix);
        if (dr_isbroken(dr)) return send_dymo_rerr(s, target->ip4_addr, dr->seqnum, target->prefix);
        dst_addr = dr->nexthop_addr;
    }
    else {
        dst_addr = s->mcast_addr;
    }

    return send_dymo_msg(s, msg, dst_addr);
}

// check valid route-message
static int validate_msg(struct yamir_serv *s, struct pbb_msg *msg)
{
    // check required fields present
    if (!pbb_msg_has_hlim(msg)) return PF_MSG_HOP_LIMIT;
    if (!msg->target) return PF_TARGET_NODE;
    if (!msg->origin) return PF_ORIGIN_NODE;
    if (!mn_has_seqn(msg->origin)) return PF_MSG_ORIG_SEQNUM;
    if (msg->did != s->node_did) return PF_MSG_TLV_DID;
    if (yamir_islocaladdr(s, msg->orig_ip4)) return PF_MSG_ORIG_LOCAL;

    return 0; 
}

static int handle_rreq(struct yamir_serv *s, struct pbb_msg *req, struct recv_state *state)
{
    if (validate_msg(s, req)) return 0;
    
    int orig_superior = route_update(s, 
        req->type, req->origin, 
        state->saddr, state->ifindex
    );

    // additional nodes 
    for (int i = 0; i < req->num_node; i++) {
        struct msg_node *mn = &req->nodes[i];
        if (!route_update(s, req->type, mn, state->saddr, state->ifindex)) {
            mn->flags |= PBB_NF_SKIP;
        }
    }

    if (!orig_superior) return 0;

    // relay request-msg if not for us
    if (!yamir_islocaladdr(s, req->target->ip4_addr)) {
        return relay_rm(s, req, state);
    }

    // request is for us
    return send_dymo_reply(s, req);
}

static int handle_rrep(struct yamir_serv *s, struct pbb_msg *rep, struct recv_state *state)
{
    if (validate_msg(s, rep)) return 0;
    
    int orig_superior = route_update(s, 
        rep->type, rep->origin, 
        state->saddr, state->ifindex
    );

    // additional nodes 
    for (int i = 0; i < rep->num_node; i++) {
        struct msg_node *mn = &rep->nodes[i];
        if (!route_update(s, rep->type, mn, state->saddr, state->ifindex)) {
            mn->flags |= PBB_NF_SKIP;
        }
    }

    if (!orig_superior) return 0;

    // relay reply-msg if not for us
    if (!yamir_islocaladdr(s, rep->target->ip4_addr)) {
        return relay_rm(s, rep, state);
    }

    // reply is for us
    return recv_dymo_reply(s, rep);
}

// RERR handling page 28
static int route_broken(struct yamir_serv *s, struct msg_node *mn, uint32_t sender)
{
    if (!unicast_addr(mn->ip4_addr)) return 0;

    struct dymo_route *dr = route_find(s, mn->ip4_addr);
    if (!dr) return 0;

    if (!dr_isbroken(dr) &&
        (dr->nexthop_addr == sender &&
        (dr->seqnum == 0 || mn->seqnum == 0 
         || !mn_has_seqn(mn)
         || ((int16_t) dr->seqnum - (int16_t) mn->seqnum  <= 0))))
    {
        dr->flags |= DRF_IS_BROKEN;
        route_send_del(dr, 1);
        start_delete_timer(dr);
        return 1;
    }

    return 0;
}

static int validate_rerr(struct yamir_serv *s, struct pbb_msg *rerr)
{
    if (!pbb_msg_has_hlim(rerr)) return PF_MSG_HOP_LIMIT;
    if (rerr->num_node == 0) return PF_UNREACHABLE_NODE;
    if (rerr->did != s->node_did) return PF_MSG_TLV_DID;

    return 0;
}

static void handle_rerr(struct yamir_serv *s, struct pbb_msg *rerr, struct recv_state *state)
{
    // first check required fields present
    if (validate_rerr(s, rerr)) return;

    // need to scan our routes
    int num_skip = 0;
    for (int i = 0; i < rerr->num_node; i++) {
        struct msg_node *mn = &rerr->nodes[i];
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
    send_dymo_msg(s, rerr, s->mcast_addr);
}

static struct dymo_req *req_create(struct yamir_serv *s)
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
    struct yamir_serv *s = req->parent;

    if (!s) {
        free(req);
        return;
    }

    list_append(&s->free_reqs, &req->node);
}

static struct dymo_req *find_req(struct yamir_serv *s, uint32_t addr)
{
    struct dymo_req *req;

    list_fornext_entry(&s->requests, req, node) {
        if (req->addr == addr) return req;
    }

    return NULL; 
}

static void send_dymo_req(struct yamir_serv *s,
    uint32_t addr, uint32_t seqnum, uint32_t hop_count)
{
    struct pbb_msg req;

    pbb_msg_reset(&req);
    
    // TODO set hoplimit using ring search RFC3561
    req.type = DYMO_RREQ;
    req.hop_limit = MSG_HOPLIMIT;
    req.flags |= PBB_MF_HLIM;
    req.addr_len = 3;

    yamir_inc_seqnum(s);

    // add target
    struct msg_node target = { 0 };
    target.ip4_addr = addr;
    if (seqnum > 0) {
        target.flags |= PBB_NF_SEQN;
        target.seqnum = seqnum;
    }
    if (hop_count > 0) {
        target.flags |= PBB_NF_DIST;
        target.dist = hop_count;
    }
    req.target = pbb_msg_add_node(&req, &target);

    // add origin
    struct msg_node origin = { 0 };
    origin.ip4_addr = s->local_addr;
    origin.flags |= PBB_NF_SEQN;
    origin.seqnum = s->own_seqnum;
    req.origin = pbb_msg_add_node(&req, &origin);

    // multicast request
    log_debug("Sending RREQ target=%s origin=%s seqnum=%d",  
        addr_tostr(target.ip4_addr), 
        addr_tostr(origin.ip4_addr),
        origin.seqnum);

    send_dymo_msg(s, &req, s->mcast_addr);
}

static void dymo_req_timeout(void *cb_arg);

static void dymo_req_send(struct dymo_req *req)
{
    struct yamir_serv *s = req->parent;

    // have we info about the target
    struct dymo_route *route = route_find(s, req->addr);
    uint32_t seqnum, hop_count;
    if (route) {
        seqnum = route->seqnum;
        hop_count = route->dist;
    }
    else {
        seqnum = 0;
        hop_count = 0;
    }

    log_debug("RREQ %s attempt %d/%d wait %ld", 
        addr_tostr(req->addr),
        req->tries, 
        DISCOVERY_ATTEMPTS_MAX,
        req->wait_time);

    // try again
    req->timer = timer_add_wsec(dymo_req_timeout, req, req->wait_time);
    send_dymo_req(s, req->addr, seqnum, hop_count);
}

static void dymo_req_timeout(void *cb_arg) 
{
    struct dymo_req *req = cb_arg;

    req->timer = NULL;

    log_debug("RREQ %s timeout %d/%d", addr_tostr(req->addr), req->tries, DISCOVERY_ATTEMPTS_MAX);

    if (req->tries < DISCOVERY_ATTEMPTS_MAX) {
        // try again
        req->tries += 1;
        req->wait_time = req->wait_time * 2;
        dymo_req_send(req);
    }
    else {
        dymo_req_done(req, YAMIR_ROUTE_NOTFOUND);
    }
}

static void route_discover(struct yamir_serv *s, uint32_t daddr, int ifindex)
{
    struct dymo_req *req;

    log_debug("route_discover(%s,%d)", addr_tostr(daddr), ifindex);

    req = find_req(s, daddr);
    if (req) {
        log_debug("req already in progress");
        return;
    }

    req = req_create(s);

    req->addr = daddr;
    req->ifindex = ifindex;
    req->tries = 1;
    req->wait_time = ROUTE_RREQ_WAIT_TIME;
    gettimeofday(&req->timestamp, NULL);

    list_append(&s->requests, &req->node);

    dymo_req_send(req);
}

// section 5.5.2
static void route_inuse(struct yamir_serv *s, uint32_t addr, int ifindex)
{
    struct dymo_route *dr = route_find(s, addr);

    log_debug("route_inuse(%s,%d) dr=%p", addr_tostr(addr), ifindex, dr);

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
    dr->used_timer = timer_add_wsec(used_timeout_cb, dr, ROUTE_USED_TIMEOUT);
}

// section 5.5 a data packet to be forwarded has no route
static void route_err(struct yamir_serv *s, uint32_t addr, int ifindex)
{
    int seqnum;
    log_debug("%s:%d", addr_tostr(addr), ifindex);
    struct dymo_route *dr = route_find(s, addr);

    if (dr) {
        if (!dr_isbroken(dr)) {
            // looks like our kernel module lost some route details
            print_route("Not broken!", dr);
            if (dr_isinstalled(dr)) {
                // update kernel
                kyamir_send(s, YAMIR_ROUTE_ADD, dr->addr, dr->nexthop_ifr);
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
    send_dymo_rerr(s, addr, seqnum, 0);
}


// stevens page 533 // see ip 7 IP_PKTINFO
static ssize_t recvfrom_wstate(int fd, void *buf, size_t len, struct recv_state *state)
{
    char ctrl[CMSG_SPACE(sizeof(struct in_pktinfo))*10];

    // load buffer address
    struct iovec iov[1];
    iov[0].iov_base = buf;
    iov[0].iov_len = len;

    struct sockaddr_in saddr;
    struct msghdr msg = {
        .msg_name = (struct sockaddr *) &saddr,
        .msg_namelen = sizeof(saddr),
        .msg_iov = iov,
        .msg_iovlen = 1,
        .msg_control = ctrl,
        .msg_controllen = sizeof(ctrl)
    };

    ssize_t nr = recvmsg(fd, &msg, 0);
    if (nr == -1 || !state) return nr;

    state->saddr =  saddr.sin_addr.s_addr;
    state->ifindex = 0;
    state->maddr = 0;
    state->daddr = 0;

    if (msg.msg_controllen < sizeof(struct cmsghdr) || (msg.msg_flags & MSG_CTRUNC)) {
        return nr;
    }

    struct cmsghdr *cmsg;
    for (cmsg= CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg,cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo *pi = (struct in_pktinfo *) CMSG_DATA(cmsg);
            state->ifindex = pi->ipi_ifindex;
            state->maddr = pi->ipi_spec_dst.s_addr;
            state->daddr = pi->ipi_addr.s_addr;
        }
    }

    return nr;
}

// recv a dymo route-message (rm)
static int dymo_recv(struct yamir_serv *s)
{
    static uint8_t rbuf[RBUF_SIZE];
    struct recv_state state;

    ssize_t nr = recvfrom_wstate(s->dymo_fd, rbuf, sizeof(rbuf), &state);
    if (nr < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
        return log_errno_rf("dymo_recv:recvfrom_wstate");
    }

    log_debug("recvfrom %zd bytes src=%s dst=%s ifr=%d",
        nr, addr_tostr(state.saddr), 
        addr_tostr(state.daddr),
        state.ifindex);

    // check if we are the sender
    if (state.saddr == s->local_addr) {
        log_debug("saddr %s is local - will drop", addr_tostr(state.saddr));
        return 0;
    }
    
    // decode all - until zero or error
    struct pkt_buf buf = PKT_BUF_INIT(rbuf, nr);
    struct pbb_hdr hdr;

    int ec = pkt_buf_decode_hdr(&buf, &hdr);
    while (!ec && pkt_buf_avail(&buf)) {
        struct pbb_msg msg;
        ec = pkt_buf_decode_msg(&buf, &msg);
        if (ec) continue;
        switch(msg.type) {
        case DYMO_RREQ: handle_rreq(s, &msg, &state); break;
        case DYMO_RREP: handle_rrep(s, &msg, &state); break;
        case DYMO_RERR: handle_rerr(s, &msg, &state); break;
        default: log_debug("Unknown type %d\n", msg.type);
        }
    }

    return 0;
}

static void dymo_req_done(struct dymo_req *req, int reason)
{
    list_remove(&req->node);

    if (req->timer) {
        timer_del(req->timer);
        req->timer = NULL;
    }

    // update_route takes care of kernel routing
    if (reason != YAMIR_ROUTE_ADD) {
        kyamir_send(req->parent, reason, req->addr, req->ifindex);
    }

    dymo_req_free(req);
}

static int dymo_init(struct yamir_serv *s)
{
    // create the socket 
    int sock_type =  SOCK_DGRAM | SOCK_NONBLOCK;
    s->dymo_fd = socket(AF_INET, sock_type, 0);
    if (s->dymo_fd == -1) return log_errno_rf("dymo_init: socket");

    // get interface index
    struct ifreq ifreq;
    strcpy(ifreq.ifr_name, s->if_name); 
    int ec = ioctl(s->dymo_fd, SIOCGIFINDEX, &ifreq);
    if (ec == -1) return log_errno_rf("dymo_init: i/f not found");
    s->if_index = ifreq.ifr_ifindex;

    // interface addr
    ec = ioctl(s->dymo_fd, SIOCGIFADDR, &ifreq);
    if (ec == -1) return log_errno_rf("dymo_init: get i/f addr");
    struct sockaddr_in *sin = (struct sockaddr_in *) &ifreq.ifr_addr;
    if (sin->sin_family != AF_INET) return log_errno_rf("dymo_init: if-addr not ipv4");
    s->local_addr = sin->sin_addr.s_addr;

    // broadcast addr
    ec = ioctl(s->dymo_fd, SIOCGIFBRDADDR, &ifreq);
    if (ec == -1) return log_errno_rf("dymo_init: get i/f broadcast addr");
    sin = (struct sockaddr_in *) &ifreq.ifr_broadaddr;
    if (sin->sin_family != AF_INET) return log_errno_rf("dymo_init: bc-addr not ipv4");
    s->bcast_addr = sin->sin_addr.s_addr;

    // request meta-data on IP packets
    int on = 1;
    ec = setsockopt(s->dymo_fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
    if (ec == -1) return log_errno_rf("set IP_PKTINFO");

    // draft says set GTSM (ttl=255)
    int ttl = 255;
    ec = setsockopt(s->dymo_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    if (ec == -1) return log_errno_rf("set IP_TTL");
    ec = setsockopt(s->dymo_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (ec == -1) return log_errno_rf("set SO_REUSEADDR");

    // need this to ensure all originate packets have our address
    // and they only leave or egress from our interface
    ec = setsockopt(s->dymo_fd, SOL_SOCKET, SO_BINDTODEVICE, s->if_name, strlen(s->if_name));
    if (ec == -1) return log_errno_rf("set bindtodevice");

    // add link-local multicast (bsd/linux grr)
    struct ip_mreq mreq; 
    mreq.imr_multiaddr.s_addr = inet_addr(LL_MANET_ROUTERS);
    mreq.imr_interface.s_addr = s->local_addr;
    ec = setsockopt(s->dymo_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    if (ec == -1) return log_errno_rf("multicast join");
    s->mcast_addr = mreq.imr_multiaddr.s_addr;

    // turn off multicast loopback
    int off = 0;
    ec = setsockopt(s->dymo_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &off, sizeof(off));
    if (ec == -1) return log_errno_rf("set IP_MULTICAST_LOOP");

    // draft says set GTSM (ttl=255)
    ec = setsockopt(s->dymo_fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    if (ec == -1) return log_errno_rf("set IP_MULTICAST_TTL");

    // bind socket to 0.0.0.0:port
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(INADDR_ANY);
    sin->sin_port = htons(DYMO_PORT);
    ec = bind(s->dymo_fd, (struct sockaddr *) sin, sizeof(*sin));
    if (ec == -1) return log_errno_rf("bind_dymo");

    log_info("+", "Started dymo on if %s addr %s\n", s->if_name, sockaddr_tostr(sin));

    return 0;
}

// function from iproute2 used in quagga/zebra
static int addattr_l(struct nlmsghdr *n, size_t maxlen, int type, void *data, int alen)
{
    int len = RTA_LENGTH(alen);
    if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen) {
        return log_error_rf("addattr_l %d failed\n", type);
    }

    struct rtattr *rta = (struct rtattr *) (((char *) n) + NLMSG_ALIGN (n->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy (RTA_DATA (rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + len;

    return 0;
}

static const char *yamir_type_tostr(uint32_t type)
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

// send msg to kyamir
static int kyamir_send(struct yamir_serv *s, uint32_t type, uint32_t addr, int ifindex)
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

    log_debug("Send msg(type=%s addr=%s,ifindex=%d)",
        yamir_type_tostr(type), addr_tostr(addr), ifindex);

    int ec = sendmsg(s->kyamir_fd, &msg, 0); 
    if (ec == -1) return log_errno_rf("netlink_send");

    return 0;
}

// recv msg from kyamir
static int kyamir_recv(struct yamir_serv *s)
{
    static uint8_t rbuf[NLMSG_SPACE(sizeof(struct yamir_msg))];

    struct sockaddr_nl addr;
    socklen_t addr_len = sizeof(struct sockaddr_nl);
    ssize_t nr = recvfrom(s->kyamir_fd, rbuf, sizeof(rbuf), 0, (struct sockaddr *) &addr, &addr_len);
    if (nr < 0) return log_errno_rf("netlink_recv");

    // TODO this should be a loop  NLMSG_PAYLOAD
    struct nlmsghdr *hdr = (struct nlmsghdr *) rbuf;
    if (!NLMSG_OK(hdr,nr)) {
        log_debug("NLMSG_OK() not okay\n");
        return -1;
    }

    size_t msg_len = NLMSG_PAYLOAD(hdr, 0);
    struct yamir_msg *msg = NLMSG_DATA(hdr);
    if (msg_len < sizeof(*msg)) {
        log_debug("msg_len %lu < required %lu\n", 
        msg_len, sizeof(*msg));
        return -1;
    }

    switch(hdr->nlmsg_type) {
    case YAMIR_ROUTE_NEED:  route_discover(s, msg->addr, msg->ifindex); break;
    case YAMIR_ROUTE_INUSE: route_inuse(s, msg->addr, msg->ifindex); break;
    case YAMIR_ROUTE_ERR:   route_err(s, msg->addr, msg->ifindex); break;
    default: log_debug("Unsupported netlink msg type %d\n", hdr->nlmsg_type); break;
    }

    return 0;
}

// TODO update our routing tables if route changed by another process
static int route_recv(struct yamir_serv *s)
{
    static unsigned char rbuf[1024];
    struct sockaddr_nl addr;
    socklen_t addr_len = sizeof(struct sockaddr_nl);

    // just a /dev/null
    ssize_t nr = recvfrom(s->route_fd, rbuf, sizeof(rbuf), 0, (struct sockaddr *) &addr, &addr_len);
    if (nr < 0) return log_errno_rf("rnetlink_recv");

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
static int route_send(struct yamir_serv *s, int type, struct dymo_route *dr)
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
    rtm->rtm_protocol = RTNETLINK_YAMIR;
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

    int ec = sendmsg(s->route_fd, &msg, 0); 
    if (ec == -1) return log_errno_rf("rnetlink_send");

    return 0;
}

static int netlink_init(struct yamir_serv *s)
{
    // setup netlink interface to our kernel module
    s->kyamir_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_YAMIR);
    if (s->kyamir_fd == -1) return log_errno_rf("socket netlink_yamir");

    // bind to address
    struct sockaddr_nl *nl_addr = &s->yamir_addr;
    nl_addr->nl_family = AF_NETLINK;
    nl_addr->nl_pid = getpid();
    nl_addr->nl_groups = NETLINK_YAMIR_GROUP; //NETLINK_DYMO_GROUP; 
    int ec = bind(s->kyamir_fd, (struct sockaddr *) nl_addr, sizeof(*nl_addr));
    if (ec == -1) return log_errno_rf("bind netlink_yamir");

    // setup interface to kernel routing module
    s->route_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (s->route_fd == -1) return log_errno_rf("socket netlink_route");

    // bind to addr
    nl_addr = &s->route_addr;
    nl_addr->nl_family = AF_NETLINK;
    nl_addr->nl_pid = getpid();
    nl_addr->nl_groups = 0; // TODO RTMGRP_IPV4_ROUTE
    //rtnetlink_addr.nl_groups = RTMGRP_NOTIFY | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
    ec = bind(s->route_fd, (struct sockaddr *) nl_addr, sizeof(*nl_addr));
    if (ec == -1) return log_errno_rf("bind netlink_route");

    log_info("+", "netlink active kyamird=%d route=%d\n", s->kyamir_fd, s->route_fd);

    return 0;
}

static int setup_daemon(struct yamir_serv *s)
{
    if (s->daemonize) {
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
static int parse_argv(struct yamir_serv *s, int argc, char *argv[])
{
    int opt;
    size_t len;

    while ((opt = getopt(argc, argv, "i:p:l:dh")) != -1) {
        switch(opt) {
        case 'i':  // interface
            len = strlen(optarg);
            if (len >= sizeof(s->if_name)) return log_error_rf("ifname len %zu too big", len);
            memcpy(s->if_name, optarg, len);
            break;
        case 'p': s->port   = atoi(optarg); break;
        case 'l': log_level = atoi(optarg); break;
        case 'd': s->daemonize = 1; break;
        case 'h': usage(argv[0]); exit(0); break;
        default: return log_error_rf("Unknown option %c\n", opt);
        }
    }

    // check reqired args
    if (!*s->if_name) return log_error_rf("Missing ifname");

    return 0;
}

static void yamir_init(struct yamir_serv *s)
{
    memset(s, 0, sizeof(*s));

    s->port = DYMO_PORT;

    list_init(&s->requests);
    list_init(&s->free_reqs);
    list_init(&s->routes);
    list_init(&s->free_routes);
}

int main(int argc, char *argv[])
{   
    struct yamir_serv serv;

    util_init();
    yamir_init(&serv);

    if (parse_argv(&serv, argc, argv)) exit(1);
    if (setup_signals())      exit(2);
    if (setup_daemon(&serv))  exit(3);
    if (dymo_init(&serv))     exit(4);
    if (netlink_init(&serv))  exit(5);

    struct pollfd fds[3] = {
        { .fd = serv.dymo_fd,   .events = POLLIN },
        { .fd = serv.kyamir_fd, .events = POLLIN },
        { .fd = serv.route_fd,  .events = POLLIN },
    };
    int mask = POLLIN | POLLHUP | POLLERR;
    int wait_ms;

    while (keep_running) {
        timer_process(&wait_ms);
        int rc = poll(fds, ARR_LEN(fds), wait_ms); 
        if (rc <= 0) {
            if (rc == 0 || errno == EINTR) continue;
            break;
        }
        if ((fds[0].revents & mask) && dymo_recv(&serv)) break;
        if ((fds[1].revents & mask) && kyamir_recv(&serv)) break;
        if ((fds[2].revents & mask) && route_recv(&serv)) break;
    }

    return 0;
}
