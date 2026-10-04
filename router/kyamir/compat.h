/* SPDX-License-Identifier: MIT | (c) 2026 [cof] */

/*
 * macros to support kernel api changes
 */
#ifndef _COMPAT_H_
#define _COMPAT_H_

#include <linux/string.h>

static inline struct sock *kyamir_netlink_kernel_create(void (*recv_cb)(struct sk_buff *skb))
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0))
    struct netlink_kernel_cfg cfg = {
        .groups = NETLINK_YAMIR_GROUP,
        .input = recv_cb,
        .owner = THIS_MODULE
    };
    return netlink_kernel_create(&init_net, NELINK_YAMIR, &cfg);
#else
    struct netlink_kernel_cfg cfg = {
        .groups = NETLINK_YAMIR_GROUP,
        .input  = recv_cb,
    };
    return netlink_kernel_create(&init_net, NETLINK_YAMIR, &cfg);
#endif
}

// assign new route to packet
static inline int kyamir_ip_route_me_harder(struct net *net, struct sk_buff *skb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
    /* Modern kernels (4 args) */
    return ip_route_me_harder(net, skb->sk, skb, RTN_UNICAST);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
    return ip_route_me_harder(net, skb, RTN_UNICAST);
#else
    /* Samsung S2 / HTC Desire era */
    return ip_route_me_harder(skb, RTN_UNICAST);
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
    #define kyamir_strlcpy(dest, src, size) strscpy(dest, src, size)
#else
    #define kyamir_strlcpy(dest, src, size) strlcpy(dest, src, size)
#endif


static inline void kyamir_netlink_ack(struct sk_buff *skb, struct nlmsghdr *nlh, int err)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,16,0)
    netlink_ack(skb, nlh, err, NULL);
#else
    netlink_ack(skb, nlh, err);
#endif
}

#endif

/*
 * kyamir_sk_report_err - report a hard error to a local socket
 *
 * Note: skb->sk may be a request_sock or timewait sock rather than a full sock
 * which have no sk_err field and nobody to notify, so we skip them.
 */
static inline void kyamir_sk_report_err(struct sock *sk, int err)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
    if (!sk_fullsock(sk))
        return;
#endif

#ifdef WRITE_ONCE
    WRITE_ONCE(sk->sk_err, err);
#else
    sk->sk_err = err;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0)
    sk_error_report(sk);
#else
    sk->sk_error_report(sk);
#endif
}
