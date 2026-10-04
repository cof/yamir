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
    case FIB_EVENT_ENTRY_ADD: return "ADD";
    case FIB_EVENT_ENTRY_DEL: return "DEL";
    case FIB_EVENT_ENTRY_REPLACE: return "UPD";
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

struct kyamir_state {
    // packet queue
    struct hlist_head pending[KYAMIR_HASH_BKTS];
    u32 pending_count;
    spinlock_t pending_lock;
    atomic_t peer_portid; // netlink
    seqlock_t config_lock;
    struct kyamir_config config;
};

// module parameters
static char *ifname = "wlan0";
static unsigned int max_qlen = KYAMIR_MAX_QLEN;

module_param(ifname, charp, 0444);
module_param(max_qlen, uint, 0444);

MODULE_PARM_DESC(ifname, "Interface name to intercept (e.g. wlan0)");
MODULE_PARM_DESC(max_qlen, "Maximum packets queued waiting for a route");

static bool route_exists(int ifindex, struct net *net, __be32 saddr, __be32 daddr)
{
    struct flowi4 fl4 = {
        .saddr = saddr,
        .daddr = daddr,
        .flowi4_tos = 0,
        .flowi4_oif = ifindex,
    };
    struct fib_result res;

    int rc = fib_lookup(net, &fl4, &res, 0);
    if (rc) return false;

    // routable if fi exists and was installed by yamird
    return res.fi && res.fi->fib_protocol == YAMIR_RT_PROTO;
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
            // remote peer
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
 * Add skb to pending queue.
 * On success returns pending count for addr after enqueue else -errno.
 */
static int queue_skb(struct kyamir_state *ks,
    struct net *net, struct sk_buff *skb,
    __be32 addr)
{
    spin_lock_bh(&ks->pending_lock);
    
    int rc = 0;
    uint32_t pending = ks->pending_count;
    if (pending >= max_qlen) {
        pr_warn_ratelimited("queue full (%u pkts). Dropping.\n", pending);
        rc = -ENOBUFS;
        goto drop_unlock;
    }

    // lookup pending addr
    struct yamir_pending *yp = NULL;
    hash_for_each_possible(ks->pending, yp, node, addr) {
        if (yp->addr == addr) break;
    }

    if (!yp) {
        // new pending entry
        yp = kzalloc(sizeof(*yp), GFP_ATOMIC);
        if (!yp) {
            pr_err("OOM in queue_skb\n");
            rc = -ENOMEM;
            goto drop_unlock;
        }
        yp->addr = addr;
        __skb_queue_head_init(&yp->packets);
        hash_add(ks->pending, &yp->node, addr);
    }

    // add packet
    __skb_queue_tail(&yp->packets, skb);
    rc = skb_queue_len(&yp->packets);
    ks->pending_count++;
    pending = ks->pending_count;

drop_unlock:
    spin_unlock_bh(&ks->pending_lock);
    pr_debug("nsid=%u addr=%pI4 len=%u pending=%u rc=%d\n",
        net->ns.inum, &addr, skb->len, pending, rc);

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

// receive yamir_msg from userspace
static int yamir_recv_msg(struct kyamir_state *ks,
    struct net *net, int portid,
    int cmd, struct yamir_msg *msg)
{
    pr_debug("nsid=%u portid=%d msg(type=%s(%d) addr=%pI4 ifindex=%d)\n",
        net->ns.inum, portid,
        yamir_cmd_tostr(cmd), cmd, &msg->ip4_addr, msg->ifindex);

    switch(cmd) {
    case YAMIR_RT_REG:
        // userspace has registered its netlink portid
        atomic_set(&ks->peer_portid, portid);
        pr_info("userspace registered nsid=%u portid=%d\n", net->ns.inum, portid);
        return 0;
    case YAMIR_RT_FAIL:
        // userspace reports route discovery failed for addr
        if (portid != atomic_read(&ks->peer_portid))
            return -EPERM;
        drop_addr(ks, net, msg->ip4_addr);
        return 0;
    default:
       return -EINVAL;
    }
}

static bool decode_msg(struct yamir_msg *msg, struct genl_info *info)
{
    unsigned int fields = 0;

    if (info->attrs[YAMIR_ATTR_IP4ADDR]) {
        msg->ip4_addr = nla_get_u32(info->attrs[YAMIR_ATTR_IP4ADDR]);
        fields++;
    }

    if (info->attrs[YAMIR_ATTR_IFINDEX]) {
        msg->ifindex = nla_get_u32(info->attrs[YAMIR_ATTR_IFINDEX]);
        fields++;
    }

    return fields == 2;
}

static int kyamir_netlink_recv(struct sk_buff *skb, struct genl_info *info)
{
    struct net *net = genl_info_net(info);
    struct kyamir_state *ks = net_generic(net, kyamir_netid);
    if (unlikely(!ks))
        return -ENOENT;

    struct yamir_msg msg;
    int portid = info->snd_portid;
    int cmd = info->genlhdr->cmd;

    pr_debug("nsid=%u portid=%d cmd=%d\n", net->ns.inum, portid, cmd);

    if (!decode_msg(&msg, info))
        return -EINVAL;

    return yamir_recv_msg(ks, net, portid, cmd, &msg);
}

static struct genl_family my_gnl_family;

static bool encode_msg(struct sk_buff *skb, int type, struct yamir_msg *msg)
{
    // start
    void *hdr = genlmsg_put(skb, 0, 0, &my_gnl_family, 0, type);
    if (!hdr)
        return false;

    // add attrs
    if (nla_put_u32(skb, YAMIR_ATTR_IP4ADDR, msg->ip4_addr))
        return false;
    if (nla_put_s32(skb, YAMIR_ATTR_IFINDEX, msg->ifindex))
        return false;

    // end
    genlmsg_end(skb, hdr);

    return true;
}

// send msg to userspace
static int yamir_send_msg(struct kyamir_state *ks,
    struct net *net, int cmd, struct yamir_msg *msg)
{
    int portid = atomic_read(&ks->peer_portid);

    pr_debug("nsid=%u portid=%d type=%s(%d) addr=%pI4 ifindex=%d\n",
        net->ns.inum, portid,
        yamir_cmd_tostr(cmd), cmd, &msg->ip4_addr, msg->ifindex);

    // check if userspace connected
    if (portid == 0) 
        return -ENOTCONN;

    struct sk_buff *skb = genlmsg_new(YAMIR_MSG_SIZE, GFP_ATOMIC);
    if (!skb)
        return -ENOMEM;

    if (!encode_msg(skb, cmd, msg)) {
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
    // accept if not skb
    int rc = NF_ACCEPT;
    if (!skb) return rc;

    // accept if state not found
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
    struct iphdr *iph;
    if (!pskb_may_pull(skb, sizeof(struct iphdr))) return rc;
    iph = ip_hdr(skb);
    if (iph->version != 4 || iph->ihl < 5) return rc;
    if (iph->daddr == INADDR_BROADCAST || IN_MULTICAST(ntohl(iph->daddr))) return rc;
    if (!pskb_may_pull(skb, iph->ihl * 4)) return rc;
    iph = ip_hdr(skb);

    // accept if UDP DYMO packet
    if (iph->protocol == IPPROTO_UDP) {
        int ip_len = iph->ihl * 4;
        if (!pskb_may_pull(skb, ip_len + sizeof(struct udphdr))) return rc;
        struct udphdr *udph = (struct udphdr *) ((uint8_t *)ip_hdr(skb) + ip_len);
        if (ntohs(udph->dest) == DYMO_PORT || ntohs(udph->source) == DYMO_PORT) {
            // dymo message - allow it to pass to userspace
            return rc;
        }
    }

    // firing
    pr_debug("nsid=%u hook=%s(%d) proto=%d saddr=%pI4 daddr=%pI4\n",
        state->net->ns.inum, hook_tostr(state->hook), state->hook,
        iph->protocol, &iph->saddr, &iph->daddr);

    struct yamir_msg msg;
    const struct net_device *dev;

    switch(state->hook) {
    // incoming packets from net device to host, before routing
    case NF_INET_PRE_ROUTING:
        // only interested in our interface
        dev = state->in;
        if (!dev || dev->ifindex != cfg.ifindex) return rc;
        // ignore broadcasts
        if (iph->daddr == cfg.bcast_addr) return rc;

        // tell userspace this route is active
        msg.ip4_addr = iph->saddr;
        msg.ifindex = dev->ifindex;
        yamir_send_msg(ks, state->net, YAMIR_RT_INUSE, &msg);

        // accept if IP packet sent from or to this node
        if (iph->saddr == cfg.ip4_addr || iph->daddr == cfg.ip4_addr) break;

        // accept if incoming packet is routable
        if (route_exists(cfg.ifindex, state->net, iph->saddr, iph->daddr)) break;

        // drop packets which we cannot route
        msg.ip4_addr = iph->daddr;
        msg.ifindex = dev->ifindex;
        yamir_send_msg(ks, state->net, YAMIR_RT_ERR, &msg);
        rc = NF_DROP;
        break;

    // host originated packets, before routing
    case NF_INET_LOCAL_OUT:
        // only interested in our interface
        dev = state->out;
        if (!dev || dev->ifindex != cfg.ifindex) return rc;
        // ignore broadcasts
        if (iph->daddr == cfg.bcast_addr) return rc;

        // accept if dst is routable
        if (route_exists(cfg.ifindex, state->net, iph->saddr, iph->daddr)) break;

        // assume first time if dst not already on queue
        rc = queue_skb(ks, state->net, skb, iph->daddr);
        if (rc <= 0) {
            // limit exceeded ?
            rc = NF_DROP;
            break;
        }

        if (rc == 1) {
            // first time
            msg.ip4_addr = iph->daddr;
            msg.ifindex = dev->ifindex;
            yamir_send_msg(ks, state->net, YAMIR_RT_NEED, &msg);
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
        if (iph->daddr == cfg.bcast_addr) return rc;

        // tell userspace that this route is in use
        msg.ip4_addr = iph->daddr;
        msg.ifindex = dev->ifindex;
        yamir_send_msg(ks, state->net, YAMIR_RT_INUSE, &msg);
        break;
    }

    return rc;
}


static const struct nf_hook_ops kyamir_hook_ops[] = {
    // incoming packets from net device to host
    {
     .hook     = kyamir_nf_hook,
     .pf       = PF_INET,
     .hooknum  = NF_INET_PRE_ROUTING,
     .priority = NF_IP_PRI_FIRST,
     },
    // host sending packets, before routing 
    {
     .hook     = kyamir_nf_hook,
     .pf       = PF_INET,
     .hooknum  = NF_INET_LOCAL_OUT,
     .priority = NF_IP_PRI_FILTER,
     },
    // after routing, packets from host to net device
    {
     .hook     = kyamir_nf_hook,
     .pf       = PF_INET,
     .hooknum  = NF_INET_POST_ROUTING,
     .priority = NF_IP_PRI_FILTER,
     },
};

static int kyamir_fib_event(struct notifier_block *nb, unsigned long event, void *ptr) 
{
    // accept only route entry events
    switch(event) {
    case FIB_EVENT_ENTRY_ADD:
    case FIB_EVENT_ENTRY_DEL:
    case FIB_EVENT_ENTRY_REPLACE:
        break;
    default:
        return NOTIFY_DONE;
    }

    // get kyamir state
    if (((struct fib_notifier_info *) ptr)->family != AF_INET)
        return NOTIFY_DONE;
    struct fib_entry_notifier_info *info = ptr;
    if (!info || !info->fi)
        return NOTIFY_DONE;
    if (info->fi->fib_protocol != YAMIR_RT_PROTO)
        return NOTIFY_DONE;

    struct net *net = info->fi->fib_net;
    struct kyamir_state *ks = net_generic(net, kyamir_netid);
    if (!ks)
        return NOTIFY_DONE;

    // fib dst is host-order
    __be32 dst = cpu_to_be32(info->dst);
    pr_debug("nsid=%u event=%s(%lu) dst=%pI4\n",
        net->ns.inum, fib_evt_tostr(event), event, &dst);

    switch (event) {
    case FIB_EVENT_ENTRY_ADD:
    case FIB_EVENT_ENTRY_REPLACE:
        // route added or replaced
        send_addr(ks, net, dst);
        break;
    case FIB_EVENT_ENTRY_DEL:
        // userspace deleted route
        drop_addr(ks, net, dst);
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block my_fib_nb = {
    .notifier_call = kyamir_fib_event,
};


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
        cfg.ifindex = dev->ifindex;
        struct in_device *in_dev = __in_dev_get_rtnl(dev);
        if (in_dev && in_dev->ifa_list) {
            struct in_ifaddr *ifa = in_dev->ifa_list;
            cfg.ip4_addr   = ifa->ifa_local;
            cfg.bcast_addr = ifa->ifa_broadcast;
            cfg.addr_mask  = ifa->ifa_mask;
        }
        break;
    }

    // write config
    write_seqlock_bh(&ks->config_lock);
    ks->config = cfg;
    write_sequnlock_bh(&ks->config_lock);

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

    nf_unregister_net_hooks(net, kyamir_hook_ops, ARRAY_SIZE(kyamir_hook_ops));
    unregister_fib_notifier(net, &my_fib_nb);

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
    ks->pending_count = 0;

    // init netlink
    atomic_set(&ks->peer_portid, 0);

    // init config
    seqlock_init(&ks->config_lock);
    memset(&ks->config, 0, sizeof(ks->config));

    // add fib event tracker
    int rc = register_fib_notifier(net, &my_fib_nb, NULL, NULL);
    if (rc < 0) {
        pr_err("register-fib failed");
        return rc;
    }

    // add netfilter hooks
    rc = nf_register_net_hooks(net, kyamir_hook_ops, ARRAY_SIZE(kyamir_hook_ops));
    if (rc) {
        pr_err("register-net-hooks failed");
        unregister_fib_notifier(net, &my_fib_nb);
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
};

static const struct genl_ops my_ops[] = {
    {
        .cmd     = YAMIR_RT_REG,
        .flags   = 0,
        .doit    = kyamir_netlink_recv,
        .flags   = GENL_ADMIN_PERM,
        .policy  = my_policy,
    },
    {
        .cmd     = YAMIR_RT_FAIL,
        .flags   = 0,
        .doit    = kyamir_netlink_recv,
        .flags   = GENL_ADMIN_PERM,
        .policy  = my_policy,
    },
};

static struct genl_family my_gnl_family = {
    .name     = YAMIR_NL_NAME,
    .version  = 1,
    .maxattr  = YAMIR_ATTR_MAX,
    .netnsok  = true,
    .module   = THIS_MODULE,
    .ops      = my_ops,
    .n_ops    = ARRAY_SIZE(my_ops),
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
