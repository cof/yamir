/*
 * Yet Another Manet IP Router (YAMIR)
 * kyamir - kernel space yamir module
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

#include <net/icmp.h>

// kyamir/kyamir config
#include "netlink.h"
#include "compat.h"

// who we send messges to
static int peer_pid;
static struct sock *netlink_sock;
static DEFINE_MUTEX(kyamirnl_mutex);

// linux kernel ./net/ipv4/netfilter/ip_queue.c 
// TODO make these module parameters + provide proc view
#define ROUTE_MAX_LEN 1024
#define QUEUE_MAX_LEN 2048

struct route_entry {
    struct list_head list;
    __be32 addr;
};

static DEFINE_RWLOCK(route_lock);
static LIST_HEAD(route_list);
static unsigned int route_total;

// packets queue waiting
// based on nf_queue_packet
struct queue_packet {
    struct list_head list;
    struct sk_buff   *skb;
    struct net *net; // namesapce pkt came from
    __be32 addr;
    int  (*okfn)(struct sk_buff *);
};

static DEFINE_RWLOCK(queue_lock);
static LIST_HEAD(queue_list);
static unsigned int queue_total;

struct dymo_device {
    char ifname[IFNAMSIZ];
    int vaddr;
    int ifindex;
    __be32 address;
    __be32 mask;
    __be32 broadcast;
};

#define MAX_DEVICE 8
static int num_device;
static struct dymo_device dymo_devices[MAX_DEVICE];
static char *ifnames[MAX_DEVICE] = {
    DYMO_INTERFACE
};

MODULE_PARM_DESC(ifnames, "Interface names");
module_param_array(ifnames, charp, NULL, 0); 

static void route_flush(void)
{
    struct list_head *ptr;
    struct list_head *next;
    struct route_entry *entry;

    write_lock_bh(&route_lock); 

    list_for_each_safe(ptr, next, &route_list)  {
        entry = list_entry(ptr, struct route_entry, list);
        list_del(ptr);
        route_total--;
        kfree(entry);
    }

    write_unlock_bh(&route_lock);
}

static int route_exists(uint32_t addr)
{
    struct route_entry *entry, *found;
    struct list_head *ptr;

    read_lock_bh(&route_lock);

    found = NULL;

    list_for_each(ptr, &route_list) {
        entry = list_entry(ptr, struct route_entry, list);
        if (entry->addr == addr) {
            found = entry;
            break;
        }
    }

    read_unlock_bh(&route_lock);

    return found != NULL;
}

static void route_del(uint32_t addr)
{
    struct route_entry *entry, *found;
    struct list_head *ptr;
    
    write_lock_bh(&route_lock); 

    found = NULL; 
    list_for_each(ptr, &route_list) {
        entry = list_entry(ptr, struct route_entry, list);
        if (entry->addr == addr) {
            found = entry;
            break;
        }
    }

    if (found) {
        list_del(&entry->list);
        route_total--;
        kfree(entry);
    }
    
    write_unlock_bh(&route_lock);
}

static int route_add(uint32_t addr)
{
    if (route_exists(addr)) return 0;

    struct route_entry *entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        printk(KERN_ERR "kyamir: OOM in route_add()\n");
        return -ENOMEM;
    }

    // save entry data
    entry->addr = addr;

    // now add to list
    write_lock_bh(&route_lock);

    int rc = 0;
    if (route_total >= ROUTE_MAX_LEN) {
        printk(KERN_WARNING "kyamir: max list length reached\n");
        kfree(entry);
        rc = -ENOSPC;
    }
    else {
        list_add(&entry->list, &route_list);
        route_total++;
    }

    write_unlock_bh(&route_lock);

    return rc;
}

static void route_deinit(void)
{
    route_flush();
}

static int route_init(void)
{
    route_total = 0;
    
    return 0;
}

static void queue_flush(void)
{
    struct list_head *ptr;
    struct list_head *next;
    struct queue_packet *packet;

    write_lock_bh(&queue_lock); 

    list_for_each_safe(ptr, next, &queue_list)  {
        packet = list_entry(ptr, struct queue_packet, list);
        // remove from list
        list_del(ptr);
        queue_total--;
        // release mem
        kfree_skb(packet->skb);
        packet->skb = NULL;
        kfree(packet);
    }

    write_unlock_bh(&queue_lock);
}

static struct queue_packet *dequeue_packet(uint32_t addr)
{
    struct queue_packet *packet,*found;
    struct list_head *ptr;

    write_lock_bh(&queue_lock);

    found = NULL;
    list_for_each_prev(ptr, &queue_list) {
        packet = list_entry(ptr, struct queue_packet, list);
        if (packet->addr == addr) {
            found = packet;
            break;
        }
    }

    if (found) {
        list_del(&found->list);
        queue_total--;
    }

    write_unlock_bh(&queue_lock);

    return found;
}

static int enqueue_packet(
    struct net *net, struct sk_buff *skb,
    __be32 addr, int (*okfn) (struct sk_buff *))
{
    struct queue_packet *pkt = kmalloc(sizeof(*pkt), GFP_ATOMIC);

    if (!pkt) {
        printk(KERN_ERR "kyamir: OOM in enqueue_packet()\n");
        return -ENOMEM;
    }

    // save packet data
    pkt->skb = skb;
    pkt->net = net;
    pkt->addr = addr;
    pkt->okfn = okfn;

    write_lock_bh(&queue_lock);

    int rc = 0;
    if (queue_total >= QUEUE_MAX_LEN) {
        printk(KERN_WARNING "kyamir: max packet queue length reached\n");
        kfree(pkt);
        pkt = NULL;
        rc = -ENOSPC;
    }
    else {
        list_add(&pkt->list, &queue_list);
        queue_total++;
    }

    write_unlock_bh(&queue_lock);

    return rc;
}

static void queue_drop(uint32_t addr)
{
    struct queue_packet *pkt;
    int num_drop = 0;

    while ( (pkt = dequeue_packet(addr)) != NULL) {
        if (num_drop++ == 0) {
            // tell application that dest unreachable
            icmp_send(pkt->skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);
        }
        if (pkt->skb) {
            kfree_skb(pkt->skb);
            pkt->skb = NULL;
        }
        kfree(pkt);
    }
}

static void queue_send(uint32_t addr)
{
    struct queue_packet *pkt;

    while ( (pkt=dequeue_packet(addr)) != NULL) {
        if (route_exists(addr)) {
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

static int queue_exists(uint32_t addr)
{
    struct queue_packet *pkt, *found;
    struct list_head *ptr;

    read_lock_bh(&queue_lock);

    found = NULL;

    list_for_each_prev(ptr, &queue_list) {
        pkt = list_entry(ptr, struct queue_packet, list);
        if (pkt->addr == addr) {
            found = pkt;
            break;
        }
    }

    read_unlock_bh(&queue_lock);

    return found != NULL;
}

static void queue_deinit(void)
{
    synchronize_net();
    queue_flush();
}

static int queue_init(void)
{
    queue_total = 0;

    return 0;
}


// recv msg from userpace router
static int netlink_recv_msg(int type, void *data, int len)
{
    struct yamir_msg *msg = (struct yamir_msg *) data;
    if (len < sizeof(*msg)) return -EINVAL;
    int rc = 0;

    switch(type) {
    case YAMIR_ROUTE_NOTFOUND:
        queue_drop(msg->addr);
        break;
    case YAMIR_ROUTE_ADD:
        route_add(msg->addr);
        queue_send(msg->addr);
        break;
    case YAMIR_ROUTE_DEL:  
        route_del(msg->addr);
        queue_drop(msg->addr);
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

static void netlink_recv_skb(struct sk_buff *skb)
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
    if (peer_pid && peer_pid != pid) {
        RCV_SKB_FAIL(-EBUSY);
    }
    peer_pid = pid;

    rc = netlink_recv_msg(type, nlmsg_data(nlh), nlmsg_len(nlh));
    if (rc < 0) RCV_SKB_FAIL(rc);

    // final ack
    if (flags & NLM_F_ACK) {
        kyamir_netlink_ack(skb, nlh, 0);
    }
}

static void kyamir_recv_skb(struct sk_buff *buf)
{
    mutex_lock(&kyamirnl_mutex);
    netlink_recv_skb(buf); 
    mutex_unlock(&kyamirnl_mutex);
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

static int netlink_send_msg(int type, __be32 addr, int ifindex)
{
    struct yamir_msg msg = { 
        .addr = addr,
        .ifindex = ifindex
    };

    struct sk_buff *skb = netlink_build_msg(type, &msg);
    if (!skb) return -ENOMEM;

    return netlink_broadcast(netlink_sock, skb, 0, NETLINK_YAMIR_GROUP, GFP_USER);
}

// if userspace yamir exits -> flush IP packets+routes
static int kyamir_netlink_notify(struct notifier_block *block, 
    unsigned long event,
    void *ptr)
{
    struct netlink_notify *notify = ptr;

    if (event == NETLINK_URELEASE && notify->protocol == NETLINK_YAMIR && NOTIFY_ID(notify)) {
        if (NOTIFY_ID(notify) == peer_pid) {
            peer_pid = 0;
            queue_flush();
            route_flush();
        }
    }

    return NOTIFY_DONE;
}

static struct notifier_block kyamir_netlink_notifier = {
    .notifier_call = kyamir_netlink_notify, 
};

static void kyamir_netlink_deinit(void)
{
    netlink_kernel_release(netlink_sock);

    mutex_lock(&kyamirnl_mutex);
    mutex_unlock(&kyamirnl_mutex);

    netlink_unregister_notifier(&kyamir_netlink_notifier);
}

static int kyamir_netlink_init(void)
{
    netlink_register_notifier(&kyamir_netlink_notifier);

    netlink_sock = kyamir_netlink_kernel_create(kyamir_recv_skb);
    if (netlink_sock == NULL) {
        printk(KERN_ERR "kyamir: netlink_init() failed to create netlink socket\n");
        netlink_unregister_notifier(&kyamir_netlink_notifier);
        return -1;
    }

    return 0;
}

static struct dymo_device *find_device(const struct net_device *ndev)
{
    if (!ndev) return NULL;
    int ifindex = ndev->ifindex;

    for (int i = 0; i < num_device; i++) {
        if (dymo_devices[i].ifindex == ifindex) {
            return &dymo_devices[i];
        }
    }

    // not found
    return NULL;
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
    struct dymo_device *device;

    // accept if not skb
    if (!skb) return rc;

    // accept if not an ip packet or broadcast/multicast or udp dymo packet
    if (!pskb_may_pull(skb, sizeof(struct iphdr))) return rc;
    struct iphdr *iph = ip_hdr(skb);
    if (iph->version != 4) return rc;
    if (iph->daddr == INADDR_BROADCAST || IN_MULTICAST(ntohl(iph->daddr))) {
        return rc;
    }

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
        // only interested in our interfaces 
        device = find_device(in);   
        if (!device) return rc;
        // ignore broadcasts
        if (iph->daddr == device->broadcast) return rc;

        // tell userpace that this route is in use
        netlink_send_msg(YAMIR_ROUTE_INUSE, iph->saddr, in->ifindex);
        // accept if ip packet sent from or to this node
        if (iph->saddr == device->address || iph->daddr == device->address) break;
        // accept if incoming packet is routable 
        if (route_exists(iph->daddr)) break;

        // drop packets which we cannot route
        netlink_send_msg(YAMIR_ROUTE_ERR, iph->daddr, in->ifindex);
        rc = NF_DROP;
        break;

    // host originated packets, before routing
    case NF_INET_LOCAL_OUT:
        // only interested in our interfaces 
        device = find_device(out);   
        if (!device) return rc;
        // ignore broadcasts
        if (iph->daddr == device->broadcast) return rc;

        // accept if dst is routable 
        if (route_exists(iph->daddr)) break;

        // assume first time if dst not already on queue
        entry_found = queue_exists(iph->daddr);
        if (enqueue_packet(net, skb, iph->daddr, okfn) != 0) {
            // limits exceeded - accept or drop ?
            break;
        }

        if (!entry_found) {
            netlink_send_msg(YAMIR_ROUTE_NEED, iph->daddr, out->ifindex);
        }

        // tell netfilter we will take it from here
        rc = NF_STOLEN;
        break;

    // outgoing packets from host to net device, after routing
    case NF_INET_POST_ROUTING:
        // only interested in our interfaces 
        device = find_device(out);   
        if (!device) return rc;
        // ignore broadcasts
        if (iph->daddr == device->broadcast) return rc;

        // tell userspace that this route is in use
        netlink_send_msg(YAMIR_ROUTE_INUSE, iph->daddr, out->ifindex);
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

static void load_devices(void)
{
    struct net_device *ndev;
    struct in_device *idev;

    char name[IFNAMSIZ];

    for (int i = 0; ifnames[i]; i++) {

        if (num_device >= ARRAY_SIZE(dymo_devices)) {
            printk(KERN_INFO "kyamir: Reached device limit %d\n", MAX_DEVICE);
            break;
        }

        // alias hack
        kyamir_strlcpy(name, ifnames[i], sizeof(name));
        char *cp = strchr(name, ':');
        if (cp) *cp = '\0';

        ndev = dev_get_by_name(&init_net, name);
        if (!ndev) {
            printk(KERN_INFO "kyamir: No such network device %s\n", name);
            continue;
        }
        if (cp) *cp = ':';

        // now look for ipv4 address bound to that name
        idev = in_dev_get(ndev);
        if (idev) {
            struct in_ifaddr *ifa;
            rcu_read_lock();
            for (ifa = idev->ifa_list; ifa; ifa = ifa->ifa_next) {
                if (!strcmp(name, ifa->ifa_label)) {
                    struct dymo_device *ddev= &dymo_devices[num_device++];
                    ddev->vaddr = cp ? 1 : 0;
                    ddev->ifindex = ndev->ifindex;
                    ddev->address = ifa->ifa_address;
                    ddev->mask = ifa->ifa_mask;
                    ddev->broadcast = ifa->ifa_broadcast;
                    strscpy(ddev->ifname, name, sizeof(ddev->ifname));
                    printk(KERN_INFO "kyamir: Adding device %s idx=%d\n", name, ddev->ifindex);
                    break;
                }
            }
            rcu_read_unlock();
            in_dev_put(idev);
        }
        dev_put(ndev);
    }
}

static void kyamir_netfilter_deinit(void)
{
    struct net *net = kyamir_get_net();
    int i = ARRAY_SIZE(kyamir_hook_ops);
    while (i > 0) {
        i--;
        kyamir_unregister_nf_hook(net, &kyamir_hook_ops[i]);
    }
}

static int kyamir_netfilter_init(void)
{
    load_devices();
    if (num_device == 0) {
        printk(KERN_ERR "kyamir: No valid interfaces found. Aborting.\n");
        return -ENODEV;
    }

    struct net *net = kyamir_get_net();
    int rc = 0, i;
    for (i = 0; i < ARRAY_SIZE(kyamir_hook_ops); i++) {
        rc = kyamir_register_nf_hook(net, &kyamir_hook_ops[i]);
        if (rc < 0) {
            printk(KERN_ERR "kyamir: Failed to register hook %d\n", i);
            break;
        }
    }
    if (i == ARRAY_SIZE(kyamir_hook_ops)) return rc;

    // register failed - must cleanup
    while (i > 0) {
        i--;
        kyamir_unregister_nf_hook(net, &kyamir_hook_ops[i]);
    }

    return rc;
}

struct {
    int (*init_fn) (void);
    void (*deinit_fn) (void);
} inits[] = {
    { route_init, route_deinit },
    { queue_init, queue_deinit },
    { kyamir_netlink_init, kyamir_netlink_deinit },
    { kyamir_netfilter_init, kyamir_netfilter_deinit }
};

static int __init dymo_init(void)
{
    int rc = 0;
    int i;

    for (i = 0; i < ARRAY_SIZE(inits); i++) {
        rc = inits[i].init_fn();
        if (rc < 0) break;
    }

    if (i == ARRAY_SIZE(inits)) {
        printk(KERN_INFO "kyamir: DYMO module loaded!\n");
        return rc;
    }

    // init failed - must cleanup
    while (i > 0) {
        i--;
        inits[i].deinit_fn();
    }

    return rc;
}

static void __exit dymo_exit(void)
{
    int i = ARRAY_SIZE(inits);
    while (i > 0) {
        i--;
        inits[i].deinit_fn();
    }

    printk(KERN_INFO "kyamir: DYMO module unloaded!\n");
}

module_init(dymo_init);
module_exit(dymo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cyril O'Floinn");
MODULE_DESCRIPTION("Supports yamir routing");
