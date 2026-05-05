/* SPDX-License-Identifier: MIT | (c) 2026 [cof] */

/*
 * Yet Another Manet IP Router (YAMIR)
 *
 * kyamir - kernel space yamir module
 *
 * Used by YAMIR userspace router to detect route requirements.
 * Module use netfilter hooks to intercept IP packets and netlink
 * to exchange routing messages with userspace.
 *
 * Uses
 * ====
 * - generic netlink
 * - pernet subsystem
 * - netdevice notifier
 * - inetaddr notifier
 * - netlink notfier
 * - netfilter hooks
 * - mutex for netlink messages
 * - spinlock/RCU for route list changes
 * - spinlock for packet list changes
 * - atomic read/wrie for netlink pid changes
 *
 * netfilter
 * =========
 * NF_INET_PRE_ROUTING  : packet has arrived before routing decision
 * NF_INET_LOCAL_OUT    : local socket sending packet before routing decision
 * NF_INET_POST_ROUTING : packet sent after routing decision
 */
#include <linux/version.h>
//#define DEBUG
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netlink.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inetdevice.h>

#include <net/netns/generic.h>
#include <net/net_namespace.h>
#include <net/genetlink.h>

#include <net/icmp.h>

// kyamir/kyamir config
#include "netlink.h"
#include "compat.h"

static int kyamir_netid; // namespace id
static int kyamir_exiting = false;
//static int kyamir_release = false;

// linux kernel ./net/ipv4/netfilter/ip_queue.c
// TODO make these module parameters + provide proc view
#define ROUTE_MAX_LEN 1024
#define QUEUE_MAX_LEN 2048

struct yamir_route {
    struct list_head list;
    struct rcu_head rcu;
    __be32 ip4_addr;
    uint32_t flags;
};

// packets queue waiting
struct yamir_packet {
    struct list_head list;
    struct sk_buff   *skb;
    struct net *net; // namespace pkt came from
    __be32 ip4_addr;
    unsigned long ts_added;
};

// flags
#define KSF_IFNAME 0x1
#define KSF_IPADDR 0x2
#define KSF_NFHOOK 0x4

struct kyamir_state {
    uint32_t flags;
    // routes
    struct list_head routes;
    spinlock_t route_lock;
    uint32_t route_count;
    // packet queue
    struct list_head packets;
    spinlock_t packet_lock;
    uint32_t packet_count;
    // netlink
    atomic_t peer_pid;
    // interface
    char ifname[IFNAMSIZ];
    int ifindex;
    int vaddr;
    __be32 ip4_addr;
    __be32 bcast_addr;
    __be32 addr_mask;
};

static char *ifname = "wlan0";
module_param(ifname, charp, 0444);
MODULE_PARM_DESC(ifname, "Interface name to intercept (e.g. wlan0)");

/*
static bool route_exists(struct net *net, __be32 ip4_addr)
{
    struct rtable *rt;
    struct flowi4 fl4 = { .daddr = ip4_addr };

    rt = ip_route_output_key(net, &fl4);
    if (IS_ERR(rt)) return false;
    ip_rt_put(rt);

    return true;
}
*/

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

static void flush_routes(struct kyamir_state *ks)
{
    struct yamir_route *yr, *tmp;

    spin_lock(&ks->route_lock);

    list_for_each_entry_safe(yr, tmp, &ks->routes, list) {
        list_del_rcu(&yr->list);
        kfree_rcu(yr, rcu);
    }

    ks->route_count = 0;
    spin_unlock(&ks->route_lock);
}

static int add_route(struct kyamir_state *ks, __be32 ip4_addr)
{
    struct yamir_route *yr = kmalloc(sizeof(*yr), GFP_KERNEL);
    if (!yr) return -ENOMEM;

    yr->ip4_addr = ip4_addr;
    yr->flags = 0;

    spin_lock(&ks->route_lock);
    list_add_rcu(&yr->list, &ks->routes);
    ks->route_count++;
    spin_unlock(&ks->route_lock);

    return 0;
}

static void del_route(struct kyamir_state *ks, __be32 ip4_addr)
{
    struct yamir_route *yr;

    spin_lock(&ks->route_lock);

    list_for_each_entry(yr, &ks->routes, list) {
        if (yr->ip4_addr == ip4_addr) {
            list_del_rcu(&yr->list);
            ks->route_count--;
            spin_unlock(&ks->route_lock);
            kfree_rcu(yr, rcu);
            return;
        }
    }

    spin_unlock(&ks->route_lock);
}

static struct yamir_route *find_route(struct kyamir_state *ks, __be32 addr)
{
    pr_debug("kyamir: find_route netid=%d addr=%pI4\n",  kyamir_netid, &addr);

    struct yamir_route *yr;

    rcu_read_lock();
    list_for_each_entry_rcu(yr, &ks->routes, list) {
        if (yr->ip4_addr == addr) {
            rcu_read_unlock();
            return yr;
        }
    }
    rcu_read_unlock();
    return NULL;
}

static void flush_packets(struct kyamir_state *ks)
{
    pr_debug("kyamir: flush_packets ENTRY\n");

    struct yamir_packet *yp, *tmp;
    LIST_HEAD(free_list);

    // move all packets to free list
    spin_lock_bh(&ks->packet_lock);
    list_replace_init(&ks->packets, &free_list);
    ks->packet_count = 0;
    spin_unlock_bh(&ks->packet_lock);

    // free them
    list_for_each_entry_safe(yp, tmp, &free_list, list)  {
        list_del(&yp->list);
        if (yp->skb) kfree_skb(yp->skb);
        kfree(yp);
    }

    pr_debug("kyamir: flush_packets EXIT_\n");
}

static int add_packet(struct kyamir_state *ks,
    struct net *net, struct sk_buff *skb,
    __be32 addr)
{
    pr_debug("kyamir: add_packet netid=%d addr=%pI4\n", kyamir_netid, &addr);

    struct yamir_packet *yp = kzalloc(sizeof(*yp), GFP_ATOMIC);

    if (!yp) {
        pr_err("kyamir: OOM in add_packet\n");
        return -ENOMEM;
    }

    // save packet data
    yp->skb = skb;
    yp->net = net;
    yp->ip4_addr = addr;
    yp->ts_added = jiffies;

    spin_lock_bh(&ks->packet_lock);

    int rc = 0;
    struct yamir_packet *tmp;

    // check if first time for addr
    list_for_each_entry(tmp, &ks->packets, list) {
        if (tmp->ip4_addr == addr) {
            pr_debug("kyamir: add_packet found netid=%d addr=%pI4\n", kyamir_netid, &addr);
            rc = 1;
            break;
        }
    }

    // add packet to list
    list_add_tail(&yp->list, &ks->packets);
    ks->packet_count++;

    spin_unlock_bh(&ks->packet_lock);

    return rc;
}

static void drop_packets(struct kyamir_state *ks, uint32_t addr)
{
    pr_debug("kyamir: drop_packets netid=%d addr=%pI4\n", kyamir_netid, &addr);

    struct yamir_packet *yp, *tmp;
    LIST_HEAD(drop_list);
    int num_drop = 0;

    // gather packets
    spin_lock_bh(&ks->packet_lock);
    list_for_each_entry_safe(yp, tmp, &ks->packets, list) {
        if (yp->ip4_addr == addr) {
            list_move_tail(&yp->list, &drop_list);
        }
    }
    spin_unlock_bh(&ks->packet_lock);

    list_for_each_entry_safe(yp, tmp, &drop_list, list) {
        if (yp->skb) {
            // send unreachable message
            if (yp->skb->sk)  {
                // local socket
                yp->skb->sk->sk_err = EHOSTUNREACH;
                yp->skb->sk->sk_error_report(yp->skb->sk);
            }
            else if (num_drop++ == 0) {
                // remote peer
                if (yp->net) yp->skb->dev = yp->net->loopback_dev;
                skb_reset_network_header(yp->skb);
                skb_set_transport_header(yp->skb, ip_hdrlen(yp->skb));
                skb_dst_drop(yp->skb);
                icmp_send(yp->skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);
            }
            kfree_skb(yp->skb);
        }
        kfree(yp);
    }
}

static void send_packets(struct kyamir_state *ks, struct net *net, __be32 addr)
{
    pr_debug("kyamir: send_packets netid=%d addr=%pI4\n", kyamir_netid, &addr);

    struct yamir_packet *yp, *tmp;
    LIST_HEAD(send_list);

    // gather packets for addr
    spin_lock_bh(&ks->packet_lock);
    list_for_each_entry_safe(yp, tmp, &ks->packets, list) {
        if (yp->ip4_addr == addr) {
            list_move_tail(&yp->list, &send_list);
        }
    }
    spin_unlock_bh(&ks->packet_lock);

    // send packets
    list_for_each_entry_safe(yp, tmp, &send_list, list) {
        if (yp->skb) {
            int rc = kyamir_ip_route_me_harder(yp->net, yp->skb, RTN_LOCAL);
            if (rc == 0) {
                // Reinject packet into stack
                ip_local_out(yp->net, yp->skb->sk, yp->skb);
                yp->skb = NULL;
            }
        }
        if (yp->skb) kfree_skb(yp->skb);
        kfree(yp);
    }
}

// receive msg from userspace
static int yamir_recv_msg(struct kyamir_state *ks,
    struct net *net, int pid,
    int cmd, struct yamir_msg *msg)
{
    pr_debug("kyamir: yamir_recv_msg pid=%d cmd=%d msg(addr=%pI4 ifindex=%d)\n",
        pid, cmd, &msg->ip4_addr, msg->ifindex);

    int rc = 0;

    switch(cmd) {
    case YAMIR_RT_REG:
        // userspace has registered
        atomic_set(&ks->peer_pid, pid);
        pr_info("kyamir: netlink userspace pid=%d\n", pid);
        break;
    case YAMIR_RT_NONE:
        // userspace reports no route for addr
        if (pid != atomic_read(&ks->peer_pid)) return -EPERM;
        drop_packets(ks, msg->ip4_addr);
        break;
    case YAMIR_RT_ADD:
        // userspace added route
        if (pid != atomic_read(&ks->peer_pid)) return -EPERM;
        add_route(ks, msg->ip4_addr);
        send_packets(ks, net, msg->ip4_addr);
        break;
    case YAMIR_RT_DEL:
        // userspace deleted route
        if (pid != atomic_read(&ks->peer_pid)) return -EPERM;
        del_route(ks, msg->ip4_addr);
        drop_packets(ks, msg->ip4_addr);
        break;
    default:
       rc = -EINVAL;
    }

    return rc;
}

static bool load_msg(struct yamir_msg *msg, struct genl_info *info)
{
    int fields = 0;

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

static int netlink_recv_skb(struct sk_buff *skb, struct genl_info *info)
{
    pr_debug("kyamir: nl-recv ENTRY netid=%d\n", kyamir_netid);

    struct net *net = genl_info_net(info);
    struct kyamir_state *ks = net_generic(net, kyamir_netid);
    if (unlikely(!ks)) return -ENOENT;

    struct yamir_msg msg;
    int pid = info->snd_portid;
    int cmd = info->genlhdr->cmd;

    pr_debug("kyamir: nl-recv netid=%d nsid=%u pid=%d cmd=%d\n", kyamir_netid, net->ns.inum, pid, cmd);

    int rc = -EINVAL;
    if (load_msg(&msg, info)) {
        rc = yamir_recv_msg(ks, net, pid, cmd, &msg);
    }

    return rc;
}

static struct genl_family my_gnl_family;

static bool build_msg(struct sk_buff *skb, int type, struct yamir_msg *msg)
{
    // start
    void *hdr = genlmsg_put(skb, 0, 0, &my_gnl_family, 0, type);
    if (!hdr) return false;

    // attrs
    if (nla_put_u32(skb, YAMIR_ATTR_IP4ADDR, msg->ip4_addr)) return false;
    if (nla_put_s32(skb, YAMIR_ATTR_IFINDEX, msg->ifindex))  return false;

    // end
    genlmsg_end(skb, hdr);

    return true;
}

// send msg to userspace
static int yamir_send_msg(struct kyamir_state *ks, struct net *net, int type, struct yamir_msg *msg)
{
    pr_debug("kyamir: yamir_send_msg netid=%d pid=%d type=%d addr=%pI4 ifindex=%d\n",
        kyamir_netid, atomic_read(&ks->peer_pid), type, &msg->ip4_addr, msg->ifindex);

    struct sk_buff *skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
    if (!skb) return -ENOMEM;

    if (!build_msg(skb, type, msg)) {
        kfree(skb);
        return -EMSGSIZE;
    }

    int pid = atomic_read(&ks->peer_pid);
    if (!pid) {
        kfree(skb);
        return -ENOTCONN;
    }

    int rc = genlmsg_unicast(net, skb, pid);
    if (rc != 0) {
        kfree(skb);
    }

    return rc;
}

static void flush_all(struct kyamir_state *ks)
{
    pr_debug("kyamir: flush_all routes=%d packets=%d\n", ks->route_count, ks->packet_count);
    flush_routes(ks);
    flush_packets(ks);
}

static int kyamir_netlink_notify(struct notifier_block *block,
    unsigned long event,
    void *ptr)
{
    if (kyamir_exiting) return NOTIFY_DONE;

    // get state
    struct netlink_notify *n = ptr;
    if (!n || !n->net || n->protocol != NETLINK_GENERIC) return NOTIFY_DONE;
    struct net *net = n->net;
    struct kyamir_state *ks = net_generic(net, kyamir_netid);
    int pid = NOTIFY_ID(n);

    if (!pid || pid != atomic_read(&ks->peer_pid)) return NOTIFY_DONE;

    pr_debug("kyamir: nl-notify event=%lu netid=%d nsid=%u\n", event, kyamir_netid, net->ns.inum);

    switch(event) {
    case NETLINK_URELEASE:
        // userspace exited - flush state
        pr_info("kyamir: netlink-flush netid=%d pid=%d\n", kyamir_netid, pid);
        atomic_set(&ks->peer_pid, 0);
        flush_all(ks);
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block kyamir_netlink_notifier = {
    .notifier_call = kyamir_netlink_notify,
};


// netfilter hook - IP packet coming into stack
static unsigned int do_kyamir_nf(struct net *net,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int hook,
    void *okfn)
{
    int rc = NF_ACCEPT;
    struct kyamir_state *ks;
    struct yamir_msg msg;

    pr_debug("kyamir: nf-hook netid=%d nsid=%u hook=%d/%s in=%d out=%d\n",
        kyamir_netid, net->ns.inum,
        hook, hook_tostr(hook),
        in  ? in->ifindex  : -1,
        out ? out->ifindex : -1);

    // accept if not skb
    if (kyamir_exiting) return rc;
    if (!skb) return rc;

    // accept if state not found
    ks = net_generic(net, kyamir_netid);
    if (!ks) return rc;

    pr_debug("kyamir: nf-hook netid=%d state: flags=0x%x pid=%d ifindex=%d\n",
        kyamir_netid, ks->flags, atomic_read(&ks->peer_pid), ks->ifindex);

    // accept if state not ready
    if ((ks->flags & KSF_IFNAME) == 0) return rc;
    if ((ks->flags & KSF_IPADDR) == 0) return rc;
    if (atomic_read(&ks->peer_pid) == 0) return rc;

    // accept if not IPv4 packet
    if (!pskb_may_pull(skb, sizeof(struct iphdr))) return rc;
    struct iphdr *iph = ip_hdr(skb);
    if (iph->version != 4 || iph->ihl < 5) return rc;

    pr_debug("kyamir: nf-hook netid=%d pkt: saddr=%pI4 daddr=%pI4\n",
        kyamir_netid,  &iph->saddr, &iph->daddr);

    if (iph->daddr == INADDR_BROADCAST || IN_MULTICAST(ntohl(iph->daddr))) return rc;
    if (!pskb_may_pull(skb, iph->ihl * 4)) return rc;

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

    pr_debug("kyamir: nf-hook netid=%d fire: saddr=%pI4 daddr=%pI4\n",
        kyamir_netid, &iph->saddr, &iph->daddr);

    switch(hook) {
    // incoming packets from net device to host, before routing
    case NF_INET_PRE_ROUTING:
        // only interested in our interface
        if (!in || in->ifindex != ks->ifindex) return rc;
        // ignore broadcasts
        if (iph->daddr == ks->bcast_addr) return rc;

        // tell usersppce route is active
        msg.ip4_addr = iph->saddr;
        msg.ifindex = in->ifindex;
        yamir_send_msg(ks, net, YAMIR_RT_INUSE, &msg);

        // always accept if IP packet sent from or to this node
        if (iph->saddr == ks->ip4_addr || iph->daddr == ks->ip4_addr) break;

        // accept if incoming packet is routable
        if (find_route(ks, iph->daddr)) break;

        // drop packets which we cannot route
        msg.ip4_addr = iph->daddr;
        msg.ifindex = in->ifindex;
        yamir_send_msg(ks, net, YAMIR_RT_ERR, &msg);
        rc = NF_DROP;
        break;

    // host originated packets, before routing
    case NF_INET_LOCAL_OUT:
        // only interested in our interface
        if (!out || out->ifindex != ks->ifindex) return rc;
        // ignore broadcasts
        if (iph->daddr == ks->bcast_addr) return rc;

        // accept if dst is routable
        if (find_route(ks, iph->daddr)) break;

        // assume first time if dst not already on queue
        rc = add_packet(ks, net, skb, iph->daddr);
        if (rc < 0) {
            // limit exceeded ?
            rc = NF_ACCEPT;
            break;
        }

        if (rc == 0) {
            // first time
            msg.ip4_addr = iph->daddr;
            msg.ifindex = out->ifindex;
            yamir_send_msg(ks, net, YAMIR_RT_NEED, &msg);
        }

        // tell netfilter we will take it from here
        rc = NF_STOLEN;
        break;

    // outgoing packets from host to net device, after routing
    case NF_INET_POST_ROUTING:
        // only interested in our interfaces
        if (!out || out->ifindex != ks->ifindex) return rc;
        // ignore broadcasts
        if (iph->daddr == ks->bcast_addr) return rc;

        // tell userspace that this route is in use
        msg.ip4_addr = iph->daddr;
        msg.ifindex = out->ifindex;
        yamir_send_msg(ks, net, YAMIR_RT_INUSE, &msg);
        break;
    }

    return rc;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
static unsigned int kyamir_nf_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    return do_kyamir_nf(state->net, skb, state->in, state->out, state->hook, state->okfn);
}
#else
static unsigned int kyamir_nf_hook(
    unsigned int hooknum, struct sk_buff *skb,
    const struct net_device *in, const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{
    struct net *net = dev_net(in ? in : out);
    return do_kyamir_nf(net, skb, in, out, hooknum, okfn);
}
#endif


static struct nf_hook_ops kyamir_hook_ops[] = {
    /* incoming packets from net device to host */
    {
     .hook     = KYAMIR_HOOK_CAST kyamir_nf_hook,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
     .owner    = THIS_MODULE,
#endif
     .pf       = PF_INET,
     .hooknum  = NF_INET_PRE_ROUTING,
     .priority = NF_IP_PRI_FIRST,
     },
    /* host sending packets, before routing */
    {
     .hook     = KYAMIR_HOOK_CAST kyamir_nf_hook,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
     .owner    = THIS_MODULE,
#endif
     .pf       = PF_INET,
     .hooknum  = NF_INET_LOCAL_OUT,
     .priority = NF_IP_PRI_FILTER,
     },
    /* after routing, packets from host to net device */
    {
     .hook     = KYAMIR_HOOK_CAST kyamir_nf_hook,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
     .owner    = THIS_MODULE,
#endif
     .pf       = PF_INET,
     .hooknum  = NF_INET_POST_ROUTING,
     .priority = NF_IP_PRI_FILTER,
     },
};

static void kyamir_netfilter_deinit(struct kyamir_state *ks, struct net *net)
{
    pr_debug("kyamir: nf-deinit ENTRY netid=%d nsid=%u\n", kyamir_netid,  net->ns.inum);

    int i = ARRAY_SIZE(kyamir_hook_ops);
    while (i > 0) {
        i--;
        kyamir_unregister_nf_hook(net, &kyamir_hook_ops[i]);
    }

    ks->flags &= ~KSF_NFHOOK;

    pr_debug("kyamir: nf-deinit EXIT_ netid=%d nsid=%u\n", kyamir_netid, net->ns.inum);
}

// register netfilter hooks
static int kyamir_netfilter_init(struct kyamir_state *ks, struct net *net)
{
    pr_debug("kyamir: nf-init ENTRY netid=%d nsid=%u\n", kyamir_netid, net->ns.inum);

    int rc = 0, i;
    for (i = 0; i < ARRAY_SIZE(kyamir_hook_ops); i++) {
        rc = kyamir_register_nf_hook(net, &kyamir_hook_ops[i]);
        if (rc < 0) {
            pr_err("kyamir: nf-register failed netid=%d i=%d\n", kyamir_netid, i);
            break;
        }
    }

    if (i == ARRAY_SIZE(kyamir_hook_ops)) {
        ks->flags |= KSF_NFHOOK;
        pr_info("kyamir: nf-added netid=%d i=%d\n", kyamir_netid, i);
        return 0;
    }

    // register failed - must cleanup
    while (i > 0) {
        i--;
        kyamir_unregister_nf_hook(net, &kyamir_hook_ops[i]);
    }

    return rc;
}

static void load_addr(struct kyamir_state *ks, struct in_ifaddr *ifa)
{
    ks->ip4_addr   = ifa->ifa_local;
    ks->bcast_addr = ifa->ifa_broadcast;
    ks->addr_mask  = ifa->ifa_mask;
    ks->flags |= KSF_IPADDR;

    pr_info("kyamir: add-addr ifname=%s ip4=%pI4\n", ks->ifname, &ks->ip4_addr);
}

static int my_inet_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
    struct in_ifaddr *ifa = (struct in_ifaddr *) ptr;
    struct net_device *dev = ifa->ifa_dev->dev;
    struct kyamir_state *ks = net_generic(dev_net(dev), kyamir_netid);
    if (!ks) return NOTIFY_DONE;

    bool addr_add = event == NETDEV_UP || event == NETDEV_CHANGE;

    if (addr_add && !strcmp(dev->name, ifname)) {
        load_addr(ks, ifa);
    }

    return NOTIFY_DONE;
}

static struct notifier_block my_inet_nb = {
    .notifier_call = my_inet_event,
};

static void unload_device(struct kyamir_state *ks,
    struct net_device *dev, struct net *net)
{
    ks->flags &= ~(KSF_IFNAME | KSF_IPADDR);
    ks->ifindex = -1;

    if (ks->flags & KSF_NFHOOK) {
        kyamir_netfilter_deinit(ks, net);
    }
}

static void load_device(struct kyamir_state *ks,
    struct net_device *dev, struct net *net)
{
    strscpy(ks->ifname, dev->name, sizeof(ks->ifname));
    ks->ifindex = dev->ifindex;
    ks->flags |= KSF_IFNAME;

    pr_info("kyamir: add-if netid=%d ifname=%s ifindex=%d\n",
        kyamir_netid, ks->ifname, ks->ifindex);

    kyamir_netfilter_init(ks, net);

    // load ip4_addr
    struct in_device *in_dev = in_dev_get(dev);
    if (in_dev) {
        if (in_dev->ifa_list) {
            load_addr(ks, in_dev->ifa_list);
        }
        in_dev_put(in_dev);
    }
}

static int my_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
    // get state
    struct net_device *dev = netdev_notifier_info_to_dev(ptr);
    if (!dev) return NOTIFY_DONE;
    struct net *net = dev_net(dev);
    if (!net) return NOTIFY_DONE;
    struct kyamir_state *ks = net_generic(net, kyamir_netid);
    if (!ks) return NOTIFY_DONE;
    if (strcmp(dev->name, ifname)) return NOTIFY_DONE;

    pr_debug("kyamir: netdev event=%ld netid=%d nsid=%u\n", event, kyamir_netid, net->ns.inum);

    switch(event) {
    case NETDEV_REGISTER:
    case NETDEV_CHANGENAME:
        load_device(ks, dev, net);
        break;
    case NETDEV_UNREGISTER:
        unload_device(ks, dev, net);
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block my_netdev_nb = {
    .notifier_call = my_netdev_event,
};

static void __net_exit my_exit_net(struct net *net)
{
    pr_debug("kyamir: exit-net ENTRY netid=%d nsid=%u\n", kyamir_netid, net->ns.inum);

    struct kyamir_state *ks = net_generic(net, kyamir_netid);
    if (!ks) return;

    if (ks->flags & KSF_NFHOOK) {
        kyamir_netfilter_deinit(ks, net);
    }
    flush_all(ks);

    pr_debug("kyamir: exit-net EXIT_ netid=%d nsid=%u\n", kyamir_netid, net->ns.inum);

    return;
}

static int __net_init my_init_net(struct net *net)
{
    struct kyamir_state *ks = net_generic(net, kyamir_netid);

    pr_debug("kyamir: init-net ENTRY netid=%d nsid=%u\n", kyamir_netid, net->ns.inum);

    // init routes
    INIT_LIST_HEAD(&ks->routes);
    spin_lock_init(&ks->route_lock);
    ks->route_count = 0;

    // init packet queue
    INIT_LIST_HEAD(&ks->packets);
    spin_lock_init(&ks->packet_lock);
    ks->packet_count = 0;

    // init netlink
    atomic_set(&ks->peer_pid, 0);

    // init interface
    ks->ifindex = -1;
    ks->ifname[0] = '\0';
    ks->flags = 0;

    pr_debug("kyamir: init-net EXIT_ netid=%d nsid=%u\n", kyamir_netid, net->ns.inum);

    return 0;
}

static struct pernet_operations my_net_ops = {
    .init = my_init_net,
    .exit = my_exit_net,
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
        .doit    = netlink_recv_skb,
        .flags   = GENL_ADMIN_PERM,
        .policy  = my_policy,
    },
    {
        .cmd     = YAMIR_RT_NONE,
        .flags   = 0,
        .doit    = netlink_recv_skb,
        .flags   = GENL_ADMIN_PERM,
        .policy  = my_policy,
    },
    {
        .cmd     = YAMIR_RT_ADD,
        .flags   = 0,
        .doit    = netlink_recv_skb,
        .flags   = GENL_ADMIN_PERM,
        .policy  = my_policy,
    },
    {
        .cmd     = YAMIR_RT_DEL,
        .flags   = 0,
        .doit    = netlink_recv_skb,
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

static void __exit dymo_exit(void)
{
    pr_info("kyamir: stopping netid=%d\n", kyamir_netid);

    // set stopping
    kyamir_exiting = true;
    smp_wmb();

    // unregiser notifiers
    unregister_inetaddr_notifier(&my_inet_nb);
    unregister_netdevice_notifier(&my_netdev_nb);
    netlink_unregister_notifier(&kyamir_netlink_notifier);

    // free state
    unregister_pernet_subsys(&my_net_ops);

    // stop netlink API
    genl_unregister_family(&my_gnl_family);

    pr_info("kyamir: unloaded netid=%d\n", kyamir_netid);
}

static int __init dymo_init(void)
{
    int rc;

    pr_info("kyamir: starting\n");

    rc = genl_register_family(&my_gnl_family);
    if (rc < 0) {
        pr_err("kyamir: register netlink failed");
        return rc;
    }

    rc = register_pernet_subsys(&my_net_ops);
    if (rc < 0) {
        pr_err("kyamir: register pernet failed");
        goto err_unreg_gnl;
    }

    rc = register_netdevice_notifier(&my_netdev_nb);
    if (rc < 0)  {
        pr_err("kyamir: register netdevice failed");
        goto err_unreg_pernet;
    }

    rc = register_inetaddr_notifier(&my_inet_nb);
    if (rc < 0) {
        pr_err("kyamir: register inet_addr failed");
        goto err_unreg_netdev;
    }

    rc = netlink_register_notifier(&kyamir_netlink_notifier);
    if (rc < 0 ) {
        pr_err("kyamir: register netlink notifier failed");
        goto err_unreg_inet;
    }

    pr_info("kyamir: loaded netid=%d\n", kyamir_netid);
    return 0;

// cleanup
err_unreg_inet:
    unregister_inetaddr_notifier(&my_inet_nb);
err_unreg_netdev:
    unregister_netdevice_notifier(&my_netdev_nb);
err_unreg_pernet:
    unregister_pernet_subsys(&my_net_ops);
err_unreg_gnl:
    genl_unregister_family(&my_gnl_family);

    return rc;
}

module_init(dymo_init);
module_exit(dymo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cof");
MODULE_DESCRIPTION("YAMIR netfilter packet interceptor for userspace route discovery");
