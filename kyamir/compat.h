#include <linux/version.h>
#include <linux/string.h>
#include <net/net_namespace.h>

#ifndef pr_err
#define pr_err(fmt, ...) printk(KERN_ERR fmt, ##__VA_ARGS__)
#endif

#ifndef pr_info
#define pr_info(fmt, ...) printk(KERN_INFO fmt, ##__VA_ARGS__)
#endif

/**
 * kyamir_get_net - Safely retrieves the net pointer.
 */
static inline struct net *kyamir_get_net(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
    /* Network namespaces were introduced in 2.6.24 */
    return &init_net; 
#else
    /* For even older kernels, namespaces didn't exist */
    return NULL; 
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
    #define KYAMIR_HOOK_CAST (nf_hookfn *)
#else
    #define KYAMIR_HOOK_CAST (void *)
#endif

/* struct netlink_notify pid/portiid field rename */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#  define NOTIFY_ID(n) ((n)->portid)
#else
#  define NOTIFY_ID(n) ((n)->pid)
#endif

static inline int kyamir_register_nf_hook(struct net *net, struct nf_hook_ops *ops)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
    // Modern: Requires namespace pointer
    return nf_register_net_hook(net, ops);
#else
    // S2/Desire: Global registration
    return nf_register_hook(ops);
#endif
}

static inline void kyamir_unregister_nf_hook(struct net *net, struct nf_hook_ops *ops)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
    nf_unregister_net_hook(net, ops);
#else
    nf_unregister_hook(ops);
#endif
}

static inline struct sock *kyamir_netlink_kernel_create(void (*recv_cb)(struct sk_buff *skb))
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0))
    return netlink_kernel_create(&init_net, 
        NETLINK_YAMIR,
        NETLINK_YAMIR_GROUP,
        recv_cb, 
        NULL, 
        THIS_MODULE
    );
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0))
	struct netlink_kernel_cfg cfg = {
        .groups = NETLINK_YAMIR_GROUP,
        .input = recv_cb,
        .owner = THIS_MODULE
    };
    return netlink_kernel_create(&init_net, NETLINK_YAMIR &cfg);
#else
	struct netlink_kernel_cfg cfg = {
        .groups = NETLINK_YAMIR_GROUP,
        .input  = recv_cb,
    };
    return netlink_kernel_create(&init_net, NETLINK_YAMIR, &cfg);
#endif
}

// assign new route to packet
static inline int kyamir_ip_route_me_harder(struct net *net, struct sk_buff *skb, unsigned addr_type) 
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
    /* Modern kernels (4 args) */
    return ip_route_me_harder(net, skb->sk, skb, addr_type);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
    return ip_route_me_harder(net, skb, addr_type);
#else
    /* Samsung S2 / HTC Desire era */
    return ip_route_me_harder(skb, addr_type);
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
    #define kyamir_strlcpy(dest, src, size) strscpy(dest, src, size)
#else
    #define kyamir_strlcpy(dest, src, size) strlcpy(dest, src, size)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    /* versions between 3.7 and 3.10 used portid  */
    #define NETLINK_SENDER_ID(nlh) ((nlh)->nlmsg_portid)
#else
    /* Most versions use pid */
    #define NETLINK_SENDER_ID(nlh) ((nlh)->nlmsg_pid)
#endif


static inline void kyamir_netlink_ack(struct sk_buff *skb, struct nlmsghdr *nlh, int err) 
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,16,0)
    netlink_ack(skb, nlh, err, NULL);
#else
    netlink_ack(skb, nlh, err);
#endif
}

