#ifndef _NETLINK_H_
#define _NETLINK_H_

// settings common both to both user/kernel space
// default settings from draft-ietf-manet-dymo-21.txt
#define DYMO_INTERFACE "wlan0"
#define DYMO_PORT  269

// rtm_protocol - See /usr/include/linux/rtnetlink.h
#define YAMIR_NL_NAME "yamir_netlink"
#define YAMIR_NL_GROUP 0

// private routing protocol
#define YAMIR_RT_PROTO 253

// TODO remove these
#define NETLINK_YAMIR NETLINK_USERSOCK
#define NETLINK_YAMIR_GROUP 0

struct yamir_msg {
    uint32_t ip4_addr;
    int ifindex;
};

struct genl_request {
    struct nlmsghdr n;
    struct genlmsghdr g;
    // Space for: (attr_hdr + u32) + (attr_hdr + int)
    char buf[64] __attribute__((aligned(4)));
};

enum {
    YAMIR_ATTR_UNSPEC,
    YAMIR_ATTR_IP4ADDR,
    YAMIR_ATTR_IFINDEX,
    _YAMIR_ATTR_MAX
};

#define YAMIR_ATTR_MAX (_YAMIR_ATTR_MAX - 1)

enum {
    // sent to kaymir
    YAMIR_RT_REG   = 0, // register
    YAMIR_RT_NONE  = 1, // no-route
    // recv from kyamir
    YAMIR_RT_NEED  = 4, // need-route
    YAMIR_RT_INUSE = 5, // route-inuse
    YAMIR_RT_ERR   = 6, // route-err
    // end
    _YAMIR_RT_MAX
};

#define YAIMR_RT_MAX (_YAMIR_RT_MAX - 1)

#endif
