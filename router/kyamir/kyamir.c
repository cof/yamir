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

#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include <net/icmp.h>

// kyamir/kyamir config
#include "netlink.h"
#include "compat.h"

static int yamir_net_id; // namespace id

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


#define HAVE_IFNAME 0x1
#define HAVE_IPADDR 0x2

struct kyamir_state {
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
    struct sock *netlink_sock;
    struct mutex kyamirnl_mutex;
    // interface
    uint32_t flags;
    char ifname[IFNAMSIZ];
    int ifindex;
    int vaddr;
    __be32 ip4_addr;
    __be32 bcast_addr;
    __be32 addr_mask;
};

static char *ifname = "wlan0"; 
module_param(ifname, charp, 0444);
MODULE_PARM_DESC(ifname, "Interface name to intercept (e.g., eth0)");

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

    pr_debug("kyamir:drop addr=%pI4\n", &addr);

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
static int yamir_recv_msg(struct kyamir_state *ks, int type, void *data, int len)
{
    struct yamir_msg *msg = (struct yamir_msg *) data;
    if (len < sizeof(*msg)) return -EINVAL;
    int rc = 0;

    pr_debug("kyamir:recv type=%d addr=%pI4 ifindex=%d\n", type, &msg->addr, msg->ifindex);

    switch(type) {
    case YAMIR_RT_NONE:
        // no route for addr
        queue_drop(ks, msg->addr);
        break;
    case YAMIR_RT_ADD:
        route_add(ks, msg->addr);
        queue_send(ks, msg->addr);
        break;
    case YAMIR_RT_DEL:  
        route_del(ks, msg->addr);
        queue_drop(ks, msg->addr);
        break;
    default:
        rc = -EINVAL;
    } 
    
    return rc;
}

// note this code assumes only one netlink message in buffer
// linux_kernel/net/ipv4/netfilter/ip_queue.c
#define RCV_SKB_FAIL(err) do { \
    kyamir_netlink_ack(skb, nlh, (err));\
    return; \
} while (0)

static void netlink_recv_skb(struct kyamir_state *ks, struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    int pid, type, flags, rc;

    // chech nlh
    if (skb->len < nlmsg_total_size(0)) return;
    nlh = nlmsg_hdr(skb);
    if (nlh->nlmsg_len < NLMSG_HDRLEN || skb->len < nlh->nlmsg_len) return;

    pid   = NETLINK_SENDER_ID(nlh);
    flags = nlh->nlmsg_flags;
    type  =  nlh->nlmsg_type;

    if (pid <= 0 || !(flags & NLM_F_REQUEST) || flags & NLM_F_MULTI)
        RCV_SKB_FAIL(-EINVAL);

    // permission check
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0))
    if (security_netlink_recv(skb, CAP_NET_ADMIN))
#else
    if (!capable(CAP_NET_ADMIN))
#endif
        RCV_SKB_FAIL(-EPERM);

    // peer binding check
    if (ks->peer_pid && ks->peer_pid != pid) {
        RCV_SKB_FAIL(-EBUSY);
    }
    ks->peer_pid = pid;

    rc = yamir_recv_msg(ks, type, nlmsg_data(nlh), nlmsg_len(nlh));
    if (rc < 0) RCV_SKB_FAIL(rc);

    // final ack
    if (flags & NLM_F_ACK) {
        kyamir_netlink_ack(skb, nlh, 0);
    }
}

static void kyamir_recv_skb(struct sk_buff *skb)
{
    struct net *net;
    struct kyamir_state *ks;

    if (!skb || !skb->sk) return;

    net = sock_net(skb->sk);
    ks = net_generic(net, yamir_net_id);

    mutex_lock(&ks->kyamirnl_mutex);
    netlink_recv_skb(ks, skb); 
    mutex_unlock(&ks->kyamirnl_mutex);
}

// based on dnrmg_send_peer & dnrmg_build_message found in
// in linux_kernel/net/decnet/netfilter/dn_rtmsg.c
//
static struct sk_buff *netlink_build_msg(int type, struct yamir_msg *msg)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;

    /* 1. Allocation (Safe for both 2.6.35 and 6.8) */
    skb = alloc_skb(NLMSG_SPACE(sizeof(*msg)), GFP_ATOMIC);
    if (!skb) return NULL;

    /* 2. Critical: Portability Fix for HTC Desire (2.6) and modern (6.8)
       This zeroes out 'pid' OR 'portid' and 'dst_group' simultaneously */
    memset(&NETLINK_CB(skb), 0, sizeof(struct netlink_skb_parms));

    /* 3. Build message header */
    nlh = nlmsg_put(skb, 0, 0, type, sizeof(*msg), 0);
    if (!nlh) {
        kfree_skb(skb);
        return NULL;
    }

    /* 4. Copy payload */
    memcpy(nlmsg_data(nlh), msg, sizeof(*msg));

    return skb;
}

// send msg to userspace
static int yamir_send_msg(struct kyamir_state *ks, int type, __be32 addr, int ifindex)
{
    pr_debug("kyamir:send type=%d addr=%pI4 ifindex=%d\n", type, &addr, ifindex);

    struct yamir_msg msg = { 
        .addr = addr,
        .ifindex = ifindex
    };

    struct sk_buff *skb = netlink_build_msg(type, &msg);
    if (!skb) return -ENOMEM;

    return netlink_broadcast(ks->netlink_sock, skb, 0, NETLINK_YAMIR_GROUP, GFP_USER);
}

// if userspace yamir exits -> flush IP packets+routes
static int kyamir_netlink_notify(struct notifier_block *block, 
    unsigned long event,
    void *ptr)
{
    struct netlink_notify *n = ptr;
    if (!n || !n->net) return NOTIFY_DONE;

    struct net *net = n->net;
    struct kyamir_state *ks = net_generic(net, yamir_net_id);
    if (n->protocol != NETLINK_YAMIR) return NOTIFY_DONE;
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

static void kyamir_netlink_deinit(struct kyamir_state *ks)
{
    mutex_lock(&ks->kyamirnl_mutex);
    netlink_kernel_release(ks->netlink_sock);
    mutex_unlock(&ks->kyamirnl_mutex);
}

static int kyamir_netlink_init(struct kyamir_state *ks)
{
    ks->netlink_sock = kyamir_netlink_kernel_create(kyamir_recv_skb);
    if (!ks->netlink_sock) {
        pr_err("kyamir: netlink socket create failed\n");
        return -1;
    }

    return 0;
}

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

    // accept if not skb
    if (!skb) return rc;

    // acccept if state not found
    ks = net_generic(net, yamir_net_id);
    if (!ks) return rc;

    if ((ks->flags & HAVE_IFNAME) == 0) return rc;
    if ((ks->flags & HAVE_IPADDR) == 0) return rc;

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

    switch(hook) {
    // incoming packets from net device to host, before routing
    case NF_INET_PRE_ROUTING:
        // only interested in our interface
        if (!in || in->ifindex != ks->ifindex) return rc;
        // ignore broadcasts
        if (iph->daddr == ks->bcast_addr) return rc;

        // tell usersppce route is active
        yamir_send_msg(ks, YAMIR_RT_INUSE, iph->saddr, in->ifindex);

        // always accept if IP packet sent from or to this node
        if (iph->saddr == ks->ip4_addr || iph->daddr == ks->ip4_addr) break;

        // accept if incoming packet is routable 
        if (route_exists(ks, iph->daddr)) break;

        // drop packets which we cannot route
        yamir_send_msg(ks, YAMIR_RT_ERR, iph->daddr, in->ifindex);
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
            yamir_send_msg(ks, YAMIR_RT_NEED, iph->daddr, out->ifindex);
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
        yamir_send_msg(ks, YAMIR_RT_INUSE, iph->daddr, out->ifindex);
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

static void kyamir_netfilter_deinit(struct kyamir_state *ks)
{
    struct net *net = kyamir_get_net();
    int i = ARRAY_SIZE(kyamir_hook_ops);
    while (i > 0) {
        i--;
        kyamir_unregister_nf_hook(net, &kyamir_hook_ops[i]);
    }
}

static int kyamir_netfilter_init(struct kyamir_state *ks)
{
    struct net *net = kyamir_get_net();
    int rc = 0, i;
    for (i = 0; i < ARRAY_SIZE(kyamir_hook_ops); i++) {
        rc = kyamir_register_nf_hook(net, &kyamir_hook_ops[i]);
        if (rc < 0) {
            pr_err("kyamir: Failed to register hook %d\n", i);
            break;
        }
    }
    if (i == ARRAY_SIZE(kyamir_hook_ops)) return 0;

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
    ks->flags |= HAVE_IPADDR;

    pr_info("kyamir: add-addr ifname=%s ip4=%pI4\n", ks->ifname, &ks->ip4_addr);
}

static int my_inet_event(struct notifier_block *nb, unsigned long event, void *ptr) 
{
    struct in_ifaddr *ifa = (struct in_ifaddr *) ptr;
    struct net_device *dev = ifa->ifa_dev->dev;
    struct kyamir_state *ks = net_generic(dev_net(dev), yamir_net_id);
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

static void load_device(struct kyamir_state *ks, struct net_device *dev)
{
    strscpy(ks->ifname, dev->name, sizeof(ks->ifname));
    ks->ifindex = dev->ifindex;
    ks->flags |= HAVE_IFNAME;

    pr_info("kyamir add-if ifname=%s ifindex=%d\n", ks->ifname, ks->ifindex);
}

static int my_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr) 
{
	// get state
    struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	if (!dev) return NOTIFY_DONE;
    struct net *net = dev_net(dev);
	if (!net) return NOTIFY_DONE;
    struct kyamir_state *ks = net_generic(net, yamir_net_id);
	if (!ks) return NOTIFY_DONE;

	bool dev_add = event == NETDEV_REGISTER || event == NETDEV_CHANGENAME;

    if (dev_add && !strcmp(dev->name, ifname)) {
        load_device(ks, dev);
        struct in_device *in_dev = in_dev_get(dev);
        if (in_dev) {
            if (in_dev->ifa_list) {
                load_addr(ks, in_dev->ifa_list);
            }
            in_dev_put(in_dev);
        }
	}

    return NOTIFY_DONE;
}

static struct notifier_block my_netdev_nb = {
    .notifier_call = my_netdev_event,
};

static void __net_exit my_exit_net(struct net *net)
{
    struct kyamir_state *dymo = net_generic(net, yamir_net_id);

	if (!dymo) return;

	route_deinit(dymo);
   	queue_deinit(dymo);
   	kyamir_netlink_deinit(dymo);
	kyamir_netfilter_deinit(dymo);

	return;
}

static int __net_init my_init_net(struct net *net) 
{
    struct kyamir_state *ks = net_generic(net, yamir_net_id);

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

	if (kyamir_netlink_init(ks)) return -1;
	if (kyamir_netfilter_init(ks)) return -1;

    return 0;
}

static struct pernet_operations my_net_ops = {
    .init = my_init_net,
    .exit = my_exit_net, 
    .id   = &yamir_net_id,
    .size = sizeof(struct kyamir_state),
};

static int __init dymo_init(void)
{
    int rc = register_pernet_subsys(&my_net_ops);
    if (rc < 0) {
        pr_err("kyamir: egister pernet failed");
        return rc;
    }

    rc = register_netdevice_notifier(&my_netdev_nb);
    if (rc < 0)  {
        pr_err("kyamir: register netdevice failed");
        unregister_pernet_subsys(&my_net_ops);
    }

    rc = register_inetaddr_notifier(&my_inet_nb); 
    if (rc < 0) {
        pr_err("kyamir: register inet_addr failed");
        unregister_netdevice_notifier(&my_netdev_nb);
        unregister_pernet_subsys(&my_net_ops);
    }

    rc = netlink_register_notifier(&kyamir_netlink_notifier);
    if (rc < 0 ) {
        unregister_inetaddr_notifier(&my_inet_nb); 
        unregister_netdevice_notifier(&my_netdev_nb);
        unregister_pernet_subsys(&my_net_ops);
    }

    pr_info("kyamir: module loaded. NET ID:%d\n", yamir_net_id);
    return 0;
}

static void __exit dymo_exit(void)
{
    netlink_unregister_notifier(&kyamir_netlink_notifier);
    unregister_inetaddr_notifier(&my_inet_nb); 
    unregister_netdevice_notifier(&my_netdev_nb);
    unregister_pernet_subsys(&my_net_ops);

    pr_info("kyamir: DYMO module unloaded!\n");
}

module_init(dymo_init);
module_exit(dymo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cyril O'Floinn");
MODULE_DESCRIPTION("Intercepts IP packets via Nefilter hooks for userspace route discovery");
