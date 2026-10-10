/* SPDX-License-Identifier: MIT | (c) 2026 [cof] */

/*
 * macros to support kernel api changes
 */
#ifndef _COMPAT_H_
#define _COMPAT_H_

#include <linux/string.h>

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
    if (!sk_fullsock(sk))
        return;

    WRITE_ONCE(sk->sk_err, err);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0)
    sk_error_report(sk);
#else
    sk->sk_error_report(sk);
#endif
}

#ifdef CONFIG_IP_ROUTE_CLASSID
static inline u32 nhc_flow(const struct fib_nh_common *nhc)
{
    if (nhc->nhc_family != AF_INET)
        return 0;
    return container_of(nhc, struct fib_nh, nh_common)->nh_tclassid;
}
static inline u32 fib_flow_id(const struct fib_info *fi)
{
    return fi->fib_nh[0].nh_tclassid;
}

#else
static inline u32 nhc_flow(const struct fib_nh_common *nhc) {
    return 0;
}
static inline u32 fib_flow_id(const struct fib_info *fi)
{
    return 0;
}
#endif
