/* SPDX-License-Identifier: MIT | (c) 2026 [cof] */

/*
 * Yet Another Manet IP Router (YAMIR)
 * ===================================
 *
 * kyamir - kernel space yamir module
 *
 * Used by YAMIR userspace router to detect route requirements.
 * Module use netfilter hooks to intercept IP packets and netlink
 * to exchange routing messages with userspace.
 *
 * Parameters
 * ----------
 *  ifname   : Interface name to intercept (default: wlan0)
 *  max_qlen : Maximum sk_buff queue capacity (default: 1024)
 *
 * Example usage
 * -------------
 *  insmod kyamir.ko ifname=wlan0 max_qlen=1024
 *
 * Design
 * ======
 * - per network namespace router state
 * - IP packets waiting for route discovery are queued by destination address
 * - each destination has its own packet queue
 * - Route discovery is handled by userspace via Generic Netlink
 * - Uses netfilter hooks to intercept IP packets
 * - Uses pernet subsystem, netdevice and FIB notifiers
 * - Config read/writes protected by seqlock_t
 *
 * Netfilter hooks
 * ---------------
 * NF_INET_PRE_ROUTING  : packet has arrived before routing decision
 * NF_INET_LOCAL_OUT    : local socket sending packet before routing decision
 * NF_INET_POST_ROUTING : packet sent after routing decision
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": %s: " fmt, __func__

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netlink.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inetdevice.h>

#include <net/netns/generic.h>
#include <net/net_namespace.h>
#include <net/genetlink.h>

#include <net/ip.h>
#include <net/icmp.h>

// kyamir/kyamir config
#include "netlink.h"
#include "compat.h"

static int kyamir_netid; // kernel module per-net id

/* linux kernel ./net/ipv4/netfilter/ip_queue.c
 * Note packet timeouts are handled by dymo userspace
 */
#define KYAMIR_MAX_QLEN 1024
#define KYAMIR_HASH_BITS 7
#define KYAMIR_HASH_BKTS (1U << KYAMIR_HASH_BITS)


static inline const char *fib_evt_tostr(unsigned long event)
{
    switch(event) {
    case FIB_EVENT_ENTRY_REPLACE: return "ENTRY_REPLACE";
    case FIB_EVENT_ENTRY_APPEND:  return "ENTRY_APPEND";
    case FIB_EVENT_ENTRY_ADD:     return "ENTRY_ADD";
    case FIB_EVENT_ENTRY_DEL:     return "ENTRY_DEL";
    case FIB_EVENT_RULE_ADD:      return "RULE_ADD";
    case FIB_EVENT_RULE_DEL:      return "RULE_DEL";
    case FIB_EVENT_NH_ADD:        return "NH_ADD";
    case FIB_EVENT_NH_DEL:        return "NH_DEL";
    case FIB_EVENT_VIF_ADD:       return "VIF_ADD";
    case FIB_EVENT_VIF_DEL:       return "VIF_DEL";
    default: return "???";
    }
}

static inline const char *netdev_evt_tostr(unsigned long event)
{
    switch(event) {
    case NETDEV_UP:         return "NETDEV_UP";
    case NETDEV_DOWN:       return "NETDEV_DOWN";
    case NETDEV_REBOOT:     return "NETDEV_REBOOT";
    case NETDEV_CHANGE:     return "NETDEV_CHANGE";
    case NETDEV_REGISTER:   return "NETDEV_REGISTER";
    case NETDEV_UNREGISTER: return "NETDEV_UNREGISTER";
    case NETDEV_CHANGEMTU:  return "NETDEV_CHANGMTU";
    case NETDEV_CHANGEADDR: return "NETDEV_CHANGEADDR";
    case NETDEV_GOING_DOWN: return "NETDEV_GOING_DOWN";
    case NETDEV_CHANGENAME: return "NETDEV_CHANGENAME";
    default: return "NETDEV_???";
    }
}


// packets waiting for route discovery
struct yamir_pending {
    struct hlist_node node;
    struct sk_buff_head packets; // IP packets
    unsigned long ts_added;     // age of oldest packet
    __be32 addr;
};

struct kyamir_config {
    int ifindex;
    __be32 ip4_addr;
    __be32 bcast_addr;
    __be32 addr_mask;
};

// one per namespace
struct kyamir_state {
    // packet queue
    struct hlist_head pending[KYAMIR_HASH_BKTS];
    u32 pending_count;
    spinlock_t pending_lock;
    atomic_t peer_portid; // netlink
    seqlock_t config_lock;
    struct kyamir_config config;
    u64 last_used[YAMIR_MAX_ROUTES];
    struct notifier_block fib_nb;
};

// module parameters
static char *ifname = "wlan0";
static unsigned int max_qlen = KYAMIR_MAX_QLEN;

module_param(ifname, charp, 0444);
module_param(max_qlen, uint, 0444);

MODULE_PARM_DESC(ifname, "Interface name to intercept (e.g. wlan0)");
MODULE_PARM_DESC(max_qlen, "Maximum packets queued waiting for a route");

// route last_used 
static inline u64 *route_slot(struct kyamir_state *ks, u32 flow_id)
{
    if (!flow_id || flow_id > YAMIR_MAX_ROUTES) 
        return NULL;

    return &ks->last_used[flow_id - 1];
}

static inline void route_used(struct kyamir_state *ks, u32 flow_id)
{
    u64 *slot = route_slot(ks, flow_id);
    if (!slot) {
        pr_debug("flowid not found %u\n", flow_id);
        return;
    }

    /* read first so the cache line stays shared
     * store when the coarse clock moved 
     */
    u64 now = ktime_get_coarse_ns();
    if (READ_ONCE(*slot) != now)
        WRITE_ONCE(*slot, now);
}

static void route_restart(struct kyamir_state *ks, u32 flow_id)
{
    u64 *slot = route_slot(ks, flow_id);
    if (slot)
        WRITE_ONCE(*slot, ktime_get_coarse_ns());
}

static inline void route_wipe(struct kyamir_state *ks, u32 flow_id)
{
    u64 *slot = route_slot(ks, flow_id);
    if (slot)
        WRITE_ONCE(*slot, 0);
}

// check route exists and was installed by yamird
static inline bool yamir_lookup(struct net *net, struct flowi4 *fl4, struct fib_result *res)
{
    int rc = fib_lookup(net, fl4, res, FIB_LOOKUP_NOREF);

    return !rc &&
           res->fi &&
           res->fi->fib_protocol == YAMIR_RT_PROTO;
}

static void route_touch_src(struct kyamir_state *ks, struct net *net,
     int ifindex, __be32 saddr, __be32 daddr)
{
    struct flowi4 fl4 = { 
        .saddr = daddr,
        .daddr = saddr, 
        .flowi4_oif = ifindex 
    }; 
    struct fib_result res;

    if (!yamir_lookup(net, &fl4, &res))
        return;

    u32 flow_id = nhc_flow(FIB_RES_NHC(res)) & 0xffff; 
    route_used(ks, flow_id);
}

static bool route_exists(struct net *net, int ifindex, __be32 saddr, __be32 daddr)
{
    struct flowi4 fl4 = {
        .saddr = saddr,
        .daddr = daddr,
        .flowi4_oif = ifindex
    };
    struct fib_result res;

    return yamir_lookup(net, &fl4, &res);
}

static const char *hook_tostr(int hook)
{
    switch (hook) {
    case NF_INET_PRE_ROUTING:  return "PRE_ROUTING";
    case NF_INET_LOCAL_IN:     return "LOCAL_IN";
    case NF_INET_FORWARD:      return "FORWARD";
    case NF_INET_LOCAL_OUT:    return "LOCAL_OUT";
    case NF_INET_POST_ROUTING: return "POST_ROUTING";
    default:                   return "UNKNOWN";
    }
}

static void drop_all(struct net *net, struct sk_buff_head *drop_q)
{
    pr_debug("nsid=%u qlen=%u\n", net->ns.inum, skb_queue_len(drop_q));

    int num_drop = 0;
    struct sk_buff *skb;

    while ((skb = __skb_dequeue(drop_q)) != NULL) {
        // send unreachable message
        if (skb->sk)  {
            // local socket
            kyamir_sk_report_err(skb->sk, EHOSTUNREACH);
        }
        else if (num_drop++ == 0) {
            // remote peer - XXX code no longer used ?
            skb->dev = net->loopback_dev;
            skb_reset_network_header(skb);
            skb_set_transport_header(skb, ip_hdrlen(skb));
            skb_dst_drop(skb);
            icmp_send(skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);
        }
        // free socket buffer
        kfree_skb(skb);
    }
}

static void send_all(struct net *net, struct sk_buff_head *snd_q)
{
    pr_debug("nsid=%u qlen=%u\n", net->ns.inum, skb_queue_len(snd_q));

    struct sk_buff *skb;

    while ((skb = __skb_dequeue(snd_q)) != NULL) {
        int rc = kyamir_ip_route_me_harder(net, skb);
        if (rc == 0) {
            // Reinject packet into stack
            ip_local_out(net, skb->sk, skb);
        }
        else {
            // discard packet
            kfree_skb(skb);
        }
    }
}

// move all pending packets for addr to dst_q
static bool drain_pending(struct kyamir_state *ks, struct sk_buff_head *dst_q, __be32 addr)
{
    pr_debug("addr=%pI4\n",  &addr);

    spin_lock_bh(&ks->pending_lock);

    bool found = false;
    struct yamir_pending *yp;

    hash_for_each_possible(ks->pending, yp, node, addr) {
        if (yp->addr != addr) continue;
        // remove entry
        ks->pending_count -= skb_queue_len(&yp->packets);
        skb_queue_splice_tail_init(&yp->packets, dst_q);
        hash_del(&yp->node);
        kfree(yp);
        found = true;
        break;
    }

    spin_unlock_bh(&ks->pending_lock);

    return found;
}

// move all pending packets to dst_q
static void drain_all(struct kyamir_state *ks, struct sk_buff_head *dst_q)
{
    spin_lock_bh(&ks->pending_lock);

    pr_debug("pending_count=%u\n", ks->pending_count);

    int bkt;
    struct yamir_pending *yp;
    struct hlist_node *next;

    hash_for_each_safe(ks->pending, bkt, next, yp, node) {
        ks->pending_count -= skb_queue_len(&yp->packets);
        skb_queue_splice_tail_init(&yp->packets, dst_q);
        hash_del(&yp->node);
        kfree(yp);
    }

    spin_unlock_bh(&ks->pending_lock);
}

/*
 * Add skb to pending queue if dst addr is not routable.
 * Returns pending count for daddr after enqueue else -errno.
 * Note queue owns skb if pending count > 0.
 */
static int queue_skb(struct kyamir_state *ks,
    struct net *net, struct sk_buff *skb,
    int ifindex, __be32 saddr, __be32 daddr)
{
    int rc;

    spin_lock_bh(&ks->pending_lock);

    // accept if dst is routable
    if (route_exists(net, ifindex, saddr, daddr)) {
        rc = 0;
        goto drop_unlock;
    }

    uint32_t pending = ks->pending_count;
    if (pending >= max_qlen) {
        pr_warn_ratelimited("queue full (%u pkts). Dropping.\n", pending);
        rc = -ENOBUFS;
        goto drop_unlock;
    }

    // lookup pending addr
    struct yamir_pending *yp = NULL;
    hash_for_each_possible(ks->pending, yp, node, daddr) {
        if (yp->addr == daddr) break;
    }

    if (!yp) {
        // new pending entry
        yp = kzalloc(sizeof(*yp), GFP_ATOMIC);
        if (!yp) {
            pr_err("OOM in queue_skb\n");
            rc = -ENOMEM;
            goto drop_unlock;
        }
        yp->addr = daddr;
        __skb_queue_head_init(&yp->packets);
        hash_add(ks->pending, &yp->node, daddr);
    }

    // queue skb
    __skb_queue_tail(&yp->packets, skb);
    rc = skb_queue_len(&yp->packets);
    ks->pending_count++;
    pending = ks->pending_count;
    // skb cant be touched after unlock

drop_unlock:
    spin_unlock_bh(&ks->pending_lock);
    pr_debug("nsid=%u addr=%pI4 pending=%u rc=%d\n",
        net->ns.inum, &daddr,  pending, rc);

    return rc;
}

static void drop_addr(struct kyamir_state *ks, struct net *net, uint32_t addr)
{
    pr_debug("nsid=%u addr=%pI4\n", net->ns.inum, &addr);

    // gather packets
    struct sk_buff_head drop_q;
    __skb_queue_head_init(&drop_q);

    drain_pending(ks, &drop_q, addr);
    drop_all(net, &drop_q);
}

static void flush_all(struct kyamir_state *ks, struct net *net)
{
    // gather packets
    struct sk_buff_head drop_q;
    __skb_queue_head_init(&drop_q);

    drain_all(ks, &drop_q);
    drop_all(net, &drop_q);
}

static void send_addr(struct kyamir_state *ks, struct net *net, __be32 addr)
{
    pr_debug("nsid=%u addr=%pI4\n", net->ns.inum, &addr);

    // gather packets
    struct sk_buff_head send_q;
    __skb_queue_head_init(&send_q);

    drain_pending(ks, &send_q, addr);
    send_all(net, &send_q);
}

static struct genl_family my_gnl_family;

// userspace s registered its netlink portid
static int kyamir_genl_rt_reg(struct sk_buff *skb, struct genl_info *info)
{
    struct net *net = genl_info_net(info);
    struct kyamir_state *ks = net_generic(net, kyamir_netid);

    atomic_set(&ks->peer_portid, info->snd_portid);

    pr_info("userspace registered nsid=%u portid=%d\n", net->ns.inum, info->snd_portid);

    return 0;
}

// route discovery failed
static int kyamir_genl_rt_fail(struct sk_buff *skb, struct genl_info *info)
{
    struct net *net = genl_info_net(info);
    struct kyamir_state *ks = net_generic(net, kyamir_netid);

    if (!info->attrs[YAMIR_ATTR_IP4ADDR] || !info->attrs[YAMIR_ATTR_IFINDEX])
        return -EINVAL;

    if (info->snd_portid != atomic_read(&ks->peer_portid))
        return -EPERM;

    uint32_t ip4_addr = nla_get_u32(info->attrs[YAMIR_ATTR_IP4ADDR]);

    pr_debug("nsid=%u portid=%d addr=%pI4\n",
        net->ns.inum, info->snd_portid, &ip4_addr);

    drop_addr(ks, net, ip4_addr);

    return 0;
} 

// dump route usage
static int kyamir_genl_rt_active(struct sk_buff *skb, struct netlink_callback *cb)
{
    struct net *net = sock_net(skb->sk);
    struct kyamir_state *ks = net_generic(net, kyamir_netid);
    int id = cb->args[0];

    u64 now = ktime_get_coarse_ns();
    u32 portid = NETLINK_CB(cb->skb).portid;
    u32 seq = cb->nlh->nlmsg_seq;

    for (; id < YAMIR_MAX_ROUTES; id++) {

        u64 last_used = READ_ONCE(ks->last_used[id]);
        if (!last_used)
            continue;

        // calc idle time
        u64 idle_ms = 0;
        if (likely(now > last_used)) {
            idle_ms = ktime_to_ms(now - last_used);
            if (idle_ms > U32_MAX) 
                idle_ms = U32_MAX;
        }

        // add YAMIR_RT_ACTIVE attrs
        void *hdr = genlmsg_put(skb, portid, seq, &my_gnl_family, NLM_F_MULTI, YAMIR_RT_ACTIVE);
        if (!hdr)
            // stop - no room
            break;      

        if (nla_put_u32(skb, YAMIR_ATTR_ROUTEID, id + 1) ||
            nla_put_u32(skb, YAMIR_ATTR_IDLEMS, idle_ms)) {
            genlmsg_cancel(skb, hdr);
            break;
        }

        genlmsg_end(skb, hdr);
    }

    pr_debug("nsid=%u portid=%u seq=%u id=%d skb_len=%u\n",
        net->ns.inum, portid, seq, id, skb->len);

    // remember where we stopped
    cb->args[0] = id; 

    // 0 means all done
    return skb->len;
}

static struct genl_family my_gnl_family;

static bool encode_attr(struct sk_buff *skb, int type, struct yamir_attr *ya)
{
    // start
    void *hdr = genlmsg_put(skb, 0, 0, &my_gnl_family, 0, type);
    if (!hdr)
        return false;

    // add attrs
    if (nla_put_u32(skb, YAMIR_ATTR_IP4ADDR, ya->ip4_addr))
        return false;
    if (nla_put_s32(skb, YAMIR_ATTR_IFINDEX, ya->ifindex))
        return false;

    // end
    genlmsg_end(skb, hdr);

    return true;
}

// send msg to userspace
static int yamir_send_msg(struct kyamir_state *ks,
    struct net *net, int cmd, struct yamir_attr *ya)
{
    int portid = atomic_read(&ks->peer_portid);

    pr_debug("nsid=%u portid=%d type=%s(%d) addr=%pI4 ifindex=%d\n",
        net->ns.inum, portid,
        yamir_cmd_tostr(cmd), cmd, &ya->ip4_addr, ya->ifindex);

    // check if userspace connected
    if (portid == 0)
        return -ENOTCONN;

    struct sk_buff *skb = genlmsg_new(YAMIR_MSGSIZE, GFP_ATOMIC);
    if (!skb)
        return -ENOMEM;

    if (!encode_attr(skb, cmd, ya)) {
        kfree_skb(skb);
        return -EMSGSIZE;
    }

    return genlmsg_unicast(net, skb, portid);
}

// Flush state if userspace netlink peer exits
static int kyamir_netlink_notify(struct notifier_block *block,
    unsigned long event,
    void *ptr)
{
    // get netlink state
    struct netlink_notify *n = ptr;
    if (!n || !n->net || n->protocol != NETLINK_GENERIC)
        return NOTIFY_DONE;

    // get state
    struct net *net = n->net;
    struct kyamir_state *ks = net_generic(net, kyamir_netid);
    int portid = n->portid;

    if (!portid || portid != atomic_read(&ks->peer_portid))
        return NOTIFY_DONE;

    pr_debug("portid=%d event=%lu nsid=%u\n", portid, event, net->ns.inum);

    switch(event) {
    case NETLINK_URELEASE:
        // userspace peer exited - flush state
        atomic_set(&ks->peer_portid, 0);
        flush_all(ks, net);
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block my_netlink_notifier = {
    .notifier_call = kyamir_netlink_notify,
};

// netfilter hook - IP packet coming into stack
static unsigned int kyamir_nf_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    int rc = NF_ACCEPT; // default action

    // get our state
    struct kyamir_state *ks = net_generic(state->net, kyamir_netid);
    if (!ks) return rc;

    // atomic load
    int portid = atomic_read(&ks->peer_portid);
    // read config
    struct kyamir_config cfg;
    unsigned int seq;
    do {
        seq = read_seqbegin(&ks->config_lock);
        cfg = ks->config;
    } while (read_seqretry(&ks->config_lock, seq));

    // check ready
    if (!cfg.ifindex || !cfg.ip4_addr) return rc;
    if (portid == 0) return rc;

    // accept if not IPv4 or bcast/mcast addr
    if (!pskb_may_pull(skb, sizeof(struct iphdr))) return rc;
    struct iphdr *iph = ip_hdr(skb);
    __be32 daddr = iph->daddr;
    if (ipv4_is_lbcast(daddr) || ipv4_is_multicast(daddr)) return rc;
    __be32 saddr = iph->saddr;
    u8 ip_proto = iph->protocol;

    // accept if UDP DYMO packet
    if (ip_proto == IPPROTO_UDP && !ip_is_fragment(iph)) {
        struct udphdr _udph;
        int ip_len = iph->ihl * 4;
        const struct udphdr *udph = skb_header_pointer(skb, ip_len, sizeof(_udph), &_udph);
        if (!udph) return rc;
        if (ntohs(udph->dest) == DYMO_PORT || ntohs(udph->source) == DYMO_PORT) {
            // dymo message - allow it to pass to userspace
            return rc;
        }
    }

    // firing
    pr_debug("nsid=%u hook=%s(%d) proto=%d saddr=%pI4 daddr=%pI4 skb_len=%u\n",
        state->net->ns.inum, hook_tostr(state->hook), state->hook,
        ip_proto, &saddr, &daddr, skb->len);

    struct yamir_attr ya;
    const struct net_device *dev;

    switch(state->hook) {
    // incoming packets from net device to host, before routing
    case NF_INET_PRE_ROUTING:
        // only interested in our interface
        dev = state->in;
        if (!dev || dev->ifindex != cfg.ifindex) return rc;

        // ignore broadcasts
        if (daddr == cfg.bcast_addr) return rc;

        if (saddr != cfg.ip4_addr)
            route_touch_src(ks, state->net, cfg.ifindex, saddr, daddr);

        // accept if IP packet sent from or to this node
        if (saddr == cfg.ip4_addr || daddr == cfg.ip4_addr)
            break;

        // accept if incoming packet is routable
        if (route_exists(state->net, cfg.ifindex, saddr, daddr))
            break;

        // drop packets which we cannot route
        ya.ip4_addr = daddr;
        ya.ifindex = dev->ifindex;
        yamir_send_msg(ks, state->net, YAMIR_RT_ERR, &ya);
        rc = NF_DROP;
        break;

    // host originated packets, before routing
    case NF_INET_LOCAL_OUT:
        // only interested in our interface
        dev = state->out;
        if (!dev || dev->ifindex != cfg.ifindex) return rc;

        // ignore broadcasts
        if (daddr == cfg.bcast_addr) return rc;

        // assume first time if dst not already on queue
        rc = queue_skb(ks, state->net, skb, cfg.ifindex, saddr, daddr);
        if (rc == 0) {
            // daddr is routable
            rc = NF_ACCEPT;
            break;
        }

        if (rc < 0) {
            // error
            rc = NF_DROP;
            break;
        }

        if (rc == 1) {
            // first time
            ya.ip4_addr = daddr;
            ya.ifindex = dev->ifindex;
            if (yamir_send_msg(ks, state->net, YAMIR_RT_NEED, &ya))
                // send failed - drop queued skb's
                drop_addr(ks, state->net, daddr);
        }

        // tell netfilter we will take it from here
        rc = NF_STOLEN;
        break;

    // outgoing packets from host to net device, after routing
    case NF_INET_POST_ROUTING:
        // only interested in our interfaces
        dev = state->out;
        if (!dev || dev->ifindex != cfg.ifindex) return rc;
        // ignore broadcasts
        if (daddr == cfg.bcast_addr) return rc;
        // route in use
        route_used(ks, dst_tclassid(skb) & 0xffff);
        break;
    }

    return rc;
}

static const struct nf_hook_ops ipv4_hook_ops[] = {
    // incoming packets from net device to host
    {
     .hook     = kyamir_nf_hook,
     .pf       = NFPROTO_IPV4,
     .hooknum  = NF_INET_PRE_ROUTING,
     .priority = NF_IP_PRI_FIRST,
     },
    // host sending packets, before routing
    {
     .hook     = kyamir_nf_hook,
     .pf       = NFPROTO_IPV4,
     .hooknum  = NF_INET_LOCAL_OUT,
     .priority = NF_IP_PRI_FILTER,
     },
    // after routing, packets from host to net device
    {
     .hook     = kyamir_nf_hook,
     .pf       = NFPROTO_IPV4,
     .hooknum  = NF_INET_POST_ROUTING,
     .priority = NF_IP_PRI_FILTER,
     },
};

/* Called with rcu_read_lock() */
static int kyamir_fib_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
    // check entry event
    switch (event) {
    case FIB_EVENT_ENTRY_ADD:
    case FIB_EVENT_ENTRY_REPLACE:
    case FIB_EVENT_ENTRY_DEL:
        break;
    default:
        return NOTIFY_DONE;
    }

    // get entry info
    struct fib_notifier_info *info = ptr;
    struct fib_entry_notifier_info *fen_info;
    struct fib_info *fi;

    if (info->family != AF_INET)
        return NOTIFY_DONE;

    fen_info = container_of(info, struct fib_entry_notifier_info, info);
    fi = fen_info->fi;
    if (!fi || fi->fib_protocol != YAMIR_RT_PROTO)
        return NOTIFY_DONE;

    struct kyamir_state *ks = container_of(nb, struct kyamir_state, fib_nb); 
    struct net *net = fi->fib_net;

    __be32 dst = cpu_to_be32(fen_info->dst);
    u32 flow_id = fib_flow_id(fi);

    pr_debug("nsid=%u event=%s(%lu) dst=%pI4 flow=%u\n",
        net->ns.inum, fib_evt_tostr(event), event, &dst, flow_id);

    switch (event) {
    case FIB_EVENT_ENTRY_ADD:
    case FIB_EVENT_ENTRY_REPLACE:
        // route added or replaced
        send_addr(ks, net, dst);
        route_restart(ks, flow_id);
        break;
    case FIB_EVENT_ENTRY_DEL:
        // userspace deleted route
        drop_addr(ks, net, dst);
        route_wipe(ks, flow_id);
        break;
    }

    return NOTIFY_DONE;
}

static int kyamir_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
    // get device state
    struct net_device *dev = netdev_notifier_info_to_dev(ptr);
    if (!dev || strcmp(dev->name, ifname))
        return NOTIFY_DONE;

    // get module state
    struct net *net = dev_net(dev);
    if (!net)
        return NOTIFY_DONE;
    struct kyamir_state *ks = net_generic(net, kyamir_netid);
    if (!ks)
        return NOTIFY_DONE;

    pr_debug("nsid=%u event=%s(%ld)\n", net->ns.inum, netdev_evt_tostr(event), event);

    struct kyamir_config cfg = { 0 };

    switch(event) {
    case NETDEV_REGISTER:
    case NETDEV_CHANGENAME:
    case NETDEV_UP:
        // update config
        cfg.ifindex = dev->ifindex;
        struct in_device *in_dev = __in_dev_get_rtnl(dev);
        if (in_dev && in_dev->ifa_list) {
            struct in_ifaddr *ifa = in_dev->ifa_list;
            cfg.ip4_addr   = ifa->ifa_local;
            cfg.bcast_addr = ifa->ifa_broadcast;
            cfg.addr_mask  = ifa->ifa_mask;
        }
        break;
    case NETDEV_DOWN:
    case NETDEV_UNREGISTER:
        // clear config
        break;
    default:
        // preserve config
        return NOTIFY_DONE;
    }

    // write config
    write_seqlock_bh(&ks->config_lock);
    ks->config = cfg;
    write_sequnlock_bh(&ks->config_lock);

    // discard queues
    if (event == NETDEV_DOWN || event == NETDEV_UNREGISTER)
        flush_all(ks, net);

    return NOTIFY_DONE;
}

static struct notifier_block my_netdev_nb = {
    .notifier_call = kyamir_netdev_event,
};

static void __net_exit kyamir_net_exit(struct net *net)
{
    pr_debug("nsid=%u\n", net->ns.inum);

    struct kyamir_state *ks = net_generic(net, kyamir_netid);
    if (!ks) return;

    nf_unregister_net_hooks(net, ipv4_hook_ops, ARRAY_SIZE(ipv4_hook_ops));
    unregister_fib_notifier(net, &ks->fib_nb);

    flush_all(ks, net);

    return;
}

static int __net_init kyamir_net_init(struct net *net)
{
    pr_debug("nsid=%u\n", net->ns.inum);

    struct kyamir_state *ks = net_generic(net, kyamir_netid);
    if (!ks)
        return -ENOMEM;

    // init packet queue
    hash_init(ks->pending);
    spin_lock_init(&ks->pending_lock);

    // init netlink
    atomic_set(&ks->peer_portid, 0);

    // init config
    seqlock_init(&ks->config_lock);

    // add fib event tracker
    pr_debug("add fib-notifer nsid=%u\n", net->ns.inum);
    ks->fib_nb.notifier_call = kyamir_fib_event;
    int rc = register_fib_notifier(net, &ks->fib_nb, NULL, NULL);
    if (rc < 0) {
        pr_err("register-fib failed");
        return rc;
    }

    // add netfilter hooks
    pr_debug("add nf-hooks nsid=%u\n", net->ns.inum);
    rc = nf_register_net_hooks(net, ipv4_hook_ops, ARRAY_SIZE(ipv4_hook_ops));
    if (rc) {
        pr_err("register-net-hooks failed");
        unregister_fib_notifier(net, &ks->fib_nb);
        return rc;
    }

    // all done
    return 0;
}

static struct pernet_operations my_net_ops = {
    .init = kyamir_net_init,
    .exit = kyamir_net_exit,
    .id   = &kyamir_netid,
    .size = sizeof(struct kyamir_state),
};

// netlink cmds sent to kyamir

static const struct genl_multicast_group my_groups[] = {
    { .name = "events", },
};

static const struct nla_policy my_policy[YAMIR_ATTR_MAX + 1] = {
    [YAMIR_ATTR_IP4ADDR] = { .type = NLA_U32 },
    [YAMIR_ATTR_IFINDEX] = { .type = NLA_S32 },
    [YAMIR_ATTR_ROUTEID] = { .type = NLA_U32 },
    [YAMIR_ATTR_IDLEMS] =   { .type = NLA_U32 },
};

static const struct genl_small_ops my_genl_ops[] = {
    {
        .cmd     = YAMIR_RT_REG,
        .doit    = kyamir_genl_rt_reg,
        .flags   = GENL_ADMIN_PERM,
    },
    {
        .cmd     = YAMIR_RT_FAIL,
        .doit    = kyamir_genl_rt_fail,
        .flags   = GENL_ADMIN_PERM,
    },
    {
        .cmd     = YAMIR_RT_ACTIVE,
        .dumpit  = kyamir_genl_rt_active,
        .flags   = GENL_ADMIN_PERM,
    },
};

static struct genl_family my_gnl_family = {
    .name     = YAMIR_NL_NAME,
    .version  = 1,
    .maxattr  = YAMIR_ATTR_MAX,
    .policy  = my_policy,
    .netnsok  = true,
    .module   = THIS_MODULE,
    .small_ops = my_genl_ops,
    .n_small_ops = ARRAY_SIZE(my_genl_ops),
    .mcgrps   = my_groups,
    .n_mcgrps = ARRAY_SIZE(my_groups),
};

static void __exit kyamir_exit(void)
{
    pr_info("unloading netid=%d\n", kyamir_netid);

    genl_unregister_family(&my_gnl_family);
    netlink_unregister_notifier(&my_netlink_notifier);
    unregister_netdevice_notifier(&my_netdev_nb);
    unregister_pernet_subsys(&my_net_ops);

    pr_info("unloaded netid=%d\n", kyamir_netid);
}

static int __init kyamir_init(void)
{
    int rc;

    rc = register_pernet_subsys(&my_net_ops);
    if (rc < 0) {
        pr_err("register pernet failed");
        goto done;
    }

    rc = register_netdevice_notifier(&my_netdev_nb);
    if (rc < 0)  {
        pr_err("register netdevice failed");
        goto err_unreg_pernet;
    }

    rc = netlink_register_notifier(&my_netlink_notifier);
    if (rc < 0 ) {
        pr_err("register netlink notifier failed");
        goto err_unreg_netdev;
    }

    rc = genl_register_family(&my_gnl_family);
    if (rc < 0) {
        pr_err("register netlink failed");
        goto err_unreg_netlink;
    }

    pr_info("loaded netid=%d\n", kyamir_netid);

    return 0;

// cleanup
err_unreg_netlink:
    netlink_unregister_notifier(&my_netlink_notifier);
err_unreg_netdev:
    unregister_netdevice_notifier(&my_netdev_nb);
err_unreg_pernet:
    unregister_pernet_subsys(&my_net_ops);
done:
    return rc;
}

module_init(kyamir_init);
module_exit(kyamir_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cof");
MODULE_DESCRIPTION("YAMIR netfilter packet interceptor for userspace route discovery");
