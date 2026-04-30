/*
 * Yet Another Manet IP Router (YAMIR)
 * kyamir - kernel space yamir module
 * ----------------------------------
 * Intercepts IP packets via netfilter hooks for userspace route discovery.
 *
 * NF_INET_PRE_ROUTING  : packet has arrived before routing decision
 * NF_INET_LOCAL_OUT    : local socket sending packet before routing decision
 * NF_INET_POST_ROUTING : packet sent after routing decision
 */
#include <linux/version.h>
#define DEBUG
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

static int yamir_netid; // namespace id

// linux kernel ./net/ipv4/netfilter/ip_queue.c 
// TODO make these module parameters + provide proc view
#define ROUTE_MAX_LEN 1024
#define QUEUE_MAX_LEN 2048

struct route_entry {
    struct list_head list;
    __be32 addr;
};

// packets queue waiting
// based on nf_queue_packet
struct queue_packet {
    struct list_head list;
    struct sk_buff   *skb;
    struct net *net; // namespace pkt came from
    __be32 addr;
    int  (*okfn)(struct sk_buff *);
};

// flags
#define KSF_IFNAME 0x1
#define KSF_IPADDR 0x2
#define KSF_NFHOOK 0x4

struct kyamir_state {
    uint32_t flags;
    // packet queue
    rwlock_t queue_lock;
    struct list_head queue_list;
    unsigned int queue_total;
    // routes
    rwlock_t route_lock;
    struct list_head route_list;
    unsigned int route_total;
    // netlink 
    int peer_pid;
    struct mutex kyamirnl_mutex;
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

static void route_flush(struct kyamir_state *ks)
{
    struct list_head *ptr, *next;
    struct route_entry *entry;

    write_lock_bh(&ks->route_lock); 

    list_for_each_safe(ptr, next, &ks->route_list)  {
        entry = list_entry(ptr, struct route_entry, list);
        list_del(ptr);
        ks->route_total--;
        kfree(entry);
    }

    write_unlock_bh(&ks->route_lock);
}

static int route_exists(struct kyamir_state *ks, uint32_t addr)
{
    struct route_entry *entry, *found;
    struct list_head *ptr;

    pr_debug("kyamir: route_exists netid=%d addr=%pI4\n", yamir_netid, &addr);

    read_lock_bh(&ks->route_lock);

    found = NULL;

    list_for_each(ptr, &ks->route_list) {
        entry = list_entry(ptr, struct route_entry, list);
        if (entry->addr == addr) {
            found = entry;
            break;
        }
    }

    read_unlock_bh(&ks->route_lock);

    return found != NULL;
}

static void route_del(struct kyamir_state *ks, uint32_t addr)
{
    struct route_entry *entry, *found;
    struct list_head *ptr;
    
    write_lock_bh(&ks->route_lock); 

    found = NULL; 
    list_for_each(ptr, &ks->route_list) {
        entry = list_entry(ptr, struct route_entry, list);
        if (entry->addr == addr) {
            found = entry;
            break;
        }
    }

    if (found) {
        list_del(&entry->list);
        ks->route_total--;
        kfree(entry);
    }
    
    write_unlock_bh(&ks->route_lock);
}

static int route_add(struct kyamir_state *ks, uint32_t addr)
{
    int rc;

    if (route_exists(ks, addr)) return 0;

    write_lock_bh(&ks->route_lock);

    if (ks->route_total >= ROUTE_MAX_LEN) {
        pr_warn("kyamir: max list length reached\n");
        rc = -ENOSPC;
        goto end;
    }

    struct route_entry *entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        pr_err("kyamir: OOM in route_add()\n");
        rc = -ENOMEM;
        goto end;
    }

    // save entry data
    entry->addr = addr;
    list_add(&entry->list, &ks->route_list);
    ks->route_total++;
    rc = 0;

end:
    write_unlock_bh(&ks->route_lock);

    return rc;
}

static void route_deinit(struct kyamir_state *ks)
{
    route_flush(ks);
}

static void queue_flush(struct kyamir_state *ks)
{
    struct list_head *ptr;
    struct list_head *next;
    struct queue_packet *packet;

    write_lock_bh(&ks->queue_lock); 

    list_for_each_safe(ptr, next, &ks->queue_list)  {
        packet = list_entry(ptr, struct queue_packet, list);
        // remove from list
        list_del(ptr);
        ks->queue_total--;
        // release mem
        kfree_skb(packet->skb);
        packet->skb = NULL;
        kfree(packet);
    }

    write_unlock_bh(&ks->queue_lock);
}

static struct queue_packet *dequeue_packet(struct kyamir_state *ks, uint32_t addr)
{
    struct queue_packet *packet,*found;
    struct list_head *ptr;

    write_lock_bh(&ks->queue_lock);

    found = NULL;
    list_for_each_prev(ptr, &ks->queue_list) {
        packet = list_entry(ptr, struct queue_packet, list);
        if (packet->addr == addr) {
            found = packet;
            break;
        }
    }

    if (found) {
        list_del(&found->list);
        ks->queue_total--;
    }

    write_unlock_bh(&ks->queue_lock);

    return found;
}

static int enqueue_packet(
    struct kyamir_state *ks,
    struct net *net, struct sk_buff *skb,
    __be32 addr, int (*okfn) (struct sk_buff *))
{
    struct queue_packet *pkt = kmalloc(sizeof(*pkt), GFP_ATOMIC);

    if (!pkt) {
        pr_err("kyamir: OOM in enqueue_packet()\n");
        return -ENOMEM;
    }

    // save packet data
    pkt->skb = skb;
    pkt->net = net;
    pkt->addr = addr;
    pkt->okfn = okfn;

    write_lock_bh(&ks->queue_lock);

    int rc = 0;
    if (ks->queue_total >= QUEUE_MAX_LEN) {
        pr_warn("kyamir: max packet queue length reached\n");
        kfree(pkt);
        pkt = NULL;
        rc = -ENOSPC;
    }
    else {
        list_add(&pkt->list, &ks->queue_list);
        ks->queue_total++;
    }

    write_unlock_bh(&ks->queue_lock);

    return rc;
}

static void queue_drop(struct kyamir_state *ks, uint32_t addr)
{
    struct queue_packet *pkt;
    int num_drop = 0;

    pr_debug("kyamir: queue_drop netid=%d addr=%pI4\n", yamir_netid, &addr);

    while ( (pkt = dequeue_packet(ks, addr)) != NULL) {
        // tell application that dest unreachable
        if (pkt->skb) {
            if (pkt->skb->sk)  {
                // local socket
                pkt->skb->sk->sk_err = EHOSTUNREACH;
                pkt->skb->sk->sk_error_report(pkt->skb->sk);
            }
            else if (num_drop++ == 0) { 
                // send ICMP message
                if (pkt->net) pkt->skb->dev = pkt->net->loopback_dev;
                skb_reset_network_header(pkt->skb);
                skb_set_transport_header(pkt->skb, ip_hdrlen(pkt->skb));
                skb_dst_drop(pkt->skb);
                icmp_send(pkt->skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);
            }
            kfree_skb(pkt->skb);
            pkt->skb = NULL;
        }
        kfree(pkt);
    }
}

static void queue_send(struct kyamir_state *ks, uint32_t addr)
{
    struct queue_packet *pkt;

    pr_debug("kyamir: queue_send netid=%d addr=%pI4\n", yamir_netid, &addr);

    while ( (pkt = dequeue_packet(ks, addr)) != NULL) {
        if (route_exists(ks, addr)) {
            kyamir_ip_route_me_harder(pkt->net, pkt->skb, RTN_LOCAL);
            // Reinject packet
            pkt->okfn(pkt->skb);
            pkt->okfn = NULL;
        }
        else {
            kfree_skb(pkt->skb);
            pkt->skb = NULL;
        }
        kfree(pkt);
    }
}

static int queue_exists(struct kyamir_state *ks, uint32_t addr)
{
    struct queue_packet *pkt, *found;
    struct list_head *ptr;

    pr_debug("kyamir: queue_exists netid=%d addr=%pI4\n", yamir_netid, &addr);

    read_lock_bh(&ks->queue_lock);

    found = NULL;

    list_for_each_prev(ptr, &ks->queue_list) {
        pkt = list_entry(ptr, struct queue_packet, list);
        if (pkt->addr == addr) {
            found = pkt;
            break;
        }
    }

    read_unlock_bh(&ks->queue_lock);

    return found != NULL;
}

static void queue_deinit(struct kyamir_state *ks)
{
    synchronize_net();
    queue_flush(ks);
}

// receive msg from userpace
static int yamir_recv_msg(struct kyamir_state *ks, 
    struct net *net, int type, struct yamir_msg *msg)
{
    int rc = 0;

    pr_debug("kyamir: recv_msg type=%d addr=%pI4 ifindex=%d\n", type, &msg->ip4_addr, msg->ifindex);

    switch(type) {
    case YAMIR_RT_REG:
        break;
    case YAMIR_RT_NONE:
        // no route for addr
        queue_drop(ks, msg->ip4_addr);
        break;
    case YAMIR_RT_ADD:
        route_add(ks, msg->ip4_addr);
        queue_send(ks, msg->ip4_addr);
        break;
    case YAMIR_RT_DEL:  
        route_del(ks, msg->ip4_addr);
        queue_drop(ks, msg->ip4_addr);
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
    if (!skb || !skb->sk) return 0;

    struct net *net = sock_net(skb->sk);
    struct kyamir_state *ks = net_generic(net, yamir_netid);

    struct yamir_msg msg;
    int pid = info->snd_portid;
    int cmd = info->genlhdr->cmd;
    int rc;
	
    mutex_lock(&ks->kyamirnl_mutex);

    if (!ks->peer_pid) {
        ks->peer_pid = pid;
        pr_info("kyamir: netlink-bound pid=%d\n", pid);
    }

    if (ks->peer_pid != pid) {
        rc = -EBUSY;
    }
    else if (!load_msg(&msg, info)) {
        rc = -EINVAL;
    }
    else {
        rc = yamir_recv_msg(ks, net, cmd, &msg);
    }

    mutex_unlock(&ks->kyamirnl_mutex);

    return rc;
}

static struct genl_family my_gnl_family;

static bool build_msg(struct sk_buff *skb, int type, struct yamir_msg *msg)
{
    pr_debug("kyamir: build_msg-init netid=%d type=%d\n", yamir_netid, type);

    // start
    void *hdr = genlmsg_put(skb, 0, 0, &my_gnl_family, 0, type);
    if (!hdr) return false;

    // attrs
    if (nla_put_u32(skb, YAMIR_ATTR_IP4ADDR, msg->ip4_addr)) return false;
    if (nla_put_s32(skb, YAMIR_ATTR_IFINDEX, msg->ifindex))  return false;

    // end
    genlmsg_end(skb, hdr);

    pr_debug("kyamir: build_msg-done netid=%d type=%d\n", yamir_netid, type);

    return true;
}

// send msg to userspace
static int yamir_send_msg(struct kyamir_state *ks, struct net *net, int type, struct yamir_msg *msg)
{
    pr_debug("kyamir: send_msg netid=%d pid=%d type=%d addr=%pI4 ifindex=%d\n", 
        yamir_netid, ks->peer_pid, type, &msg->ip4_addr, msg->ifindex);

    int rc;
    struct sk_buff *skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
    if (!skb) {
        rc = -ENOMEM;
    }
    else if (!build_msg(skb, type, msg)) {
        rc = -EMSGSIZE;
    }
    else if (ks->peer_pid) {
        rc = genlmsg_unicast(net, skb, ks->peer_pid);
    }
    else {
        kfree(skb);
        rc = -ENOTCONN;
    }

    return rc;
}

// if userspace yamir exits -> flush IP packets+routes
static int kyamir_netlink_notify(struct notifier_block *block, 
    unsigned long event,
    void *ptr)
{
    struct netlink_notify *n = ptr;
    if (!n || !n->net || n->protocol != NETLINK_GENERIC) return NOTIFY_DONE;

    struct net *net = n->net;
    struct kyamir_state *ks = net_generic(net, yamir_netid);

    if (!NOTIFY_ID(n) || NOTIFY_ID(n) != ks->peer_pid) return NOTIFY_DONE;

    switch(event) {
    case NETLINK_URELEASE:
        mutex_lock(&ks->kyamirnl_mutex);
        ks->peer_pid = 0;
        queue_flush(ks);
        route_flush(ks);
        mutex_unlock(&ks->kyamirnl_mutex);
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
    int entry_found;
    struct kyamir_state *ks;
    struct yamir_msg msg;

    pr_debug("kyamir: nf-hook netid=%d nsid=%u hook=%d in=%d out=%d\n",
        yamir_netid, net->ns.inum, 
        hook,
        in  ? in->ifindex  : -1,
        out ? out->ifindex : -1);

    // accept if not skb
    if (!skb) return rc;

    // accept if state not found
    ks = net_generic(net, yamir_netid);
    if (!ks) return rc;

    if ((ks->flags & KSF_IFNAME) == 0) return rc;
    if ((ks->flags & KSF_IPADDR) == 0) return rc;
    if (!ks->peer_pid) return rc;

    // accept if not valid IPv4 packet, broadcast/multicast
    if (!pskb_may_pull(skb, sizeof(struct iphdr))) return rc;
    struct iphdr *iph = ip_hdr(skb);
    if (iph->version != 4 || iph->ihl < 5) return rc;
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

    pr_debug("kyamir: nf-pkt netid=%d saddr=%pI4 daddr=%pI4\n",
        yamir_netid, &iph->saddr, &iph->daddr);

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
        if (route_exists(ks, iph->daddr)) break;

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
        if (route_exists(ks, iph->daddr)) break;

        // assume first time if dst not already on queue
        entry_found = queue_exists(ks, iph->daddr);
        if (enqueue_packet(ks, net, skb, iph->daddr, okfn) != 0) {
            // limits exceeded - accept or drop ?
            break;
        }

        if (!entry_found) {
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
    int i = ARRAY_SIZE(kyamir_hook_ops);
    while (i > 0) {
        i--;
        kyamir_unregister_nf_hook(net, &kyamir_hook_ops[i]);
    }

    ks->flags &= ~KSF_NFHOOK;
}

// register netfilter hooks
static int kyamir_netfilter_init(struct kyamir_state *ks, struct net *net)
{
    pr_debug("kyamir: nf-init netid=%d\n", yamir_netid);

    int rc = 0, i;
    for (i = 0; i < ARRAY_SIZE(kyamir_hook_ops); i++) {
        rc = kyamir_register_nf_hook(net, &kyamir_hook_ops[i]);
        if (rc < 0) {
            pr_err("kyamir: nf-register failed netid=%d i=%d\n", yamir_netid, i);
            break;
        }
    }

    if (i == ARRAY_SIZE(kyamir_hook_ops)) {
        ks->flags |= KSF_NFHOOK;
        pr_info("kyamir: nf-added netid=%d i=%d\n", yamir_netid, i);
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
    struct kyamir_state *ks = net_generic(dev_net(dev), yamir_netid);
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
        yamir_netid, ks->ifname, ks->ifindex);

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
    struct kyamir_state *ks = net_generic(net, yamir_netid);
	if (!ks) return NOTIFY_DONE;
    if (strcmp(dev->name, ifname)) return NOTIFY_DONE;

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
    pr_debug("kyamir: exit_net netid=%d nsid=%u\n", yamir_netid, net->ns.inum);

    struct kyamir_state *ks = net_generic(net, yamir_netid);

	if (!ks) return;

	route_deinit(ks);
   	queue_deinit(ks);

    if (ks->flags & KSF_NFHOOK) {
	    kyamir_netfilter_deinit(ks, net);
    }

	return;
}

static int __net_init my_init_net(struct net *net) 
{
    struct kyamir_state *ks = net_generic(net, yamir_netid);

    pr_debug("kyamir: init_net netid=%d nsid=%u\n", yamir_netid, net->ns.inum);

    // init packet queue
    rwlock_init(&ks->queue_lock); 
    INIT_LIST_HEAD(&ks->queue_list);
    ks->queue_total = 0;

    // init route list
    rwlock_init(&ks->route_lock); 
    INIT_LIST_HEAD(&ks->route_list);
    ks->route_total = 0;

	// init interface
    ks->ifindex = -1; 
	ks->ifname[0] = '\0';
    ks->flags = 0;
    ks->peer_pid = 0;

    return 0;
}

static struct pernet_operations my_net_ops = {
    .init = my_init_net,
    .exit = my_exit_net, 
    .id   = &yamir_netid,
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
    netlink_unregister_notifier(&kyamir_netlink_notifier);
    unregister_inetaddr_notifier(&my_inet_nb); 
    unregister_netdevice_notifier(&my_netdev_nb);
    unregister_pernet_subsys(&my_net_ops);
    genl_unregister_family(&my_gnl_family);

    pr_info("kyamir: ko-unloaded netid=%d\n", yamir_netid);
}

static int __init dymo_init(void)
{
    int rc;

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

    pr_info("kyamir: ko-loaded netid=%d\n", yamir_netid);
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
MODULE_AUTHOR("Cyril O'Floinn");
MODULE_DESCRIPTION("Intercepts IP packets via Nefilter hooks for userspace route discovery");
