#ifndef _NETLINK_H_
#define _NETLINK_H_

// settings common both to both user/kernel space
// default settings from draft-ietf-manet-dymo-21.txt
#define DYMO_INTERFACE "wlan0"
#define DYMO_PORT  269

// rtm_protocol - See /usr/include/linux/rtnetlink.h
#define YAMIR_NL_NAME "yamir_netlink"

// routing protocol - reuse MANET AODV protocol ID
#define YAMIR_RT_PROTO 200

// spaced needded fo yamir_msg genlmsg_new
#define YAMIR_MSGSIZE (nla_total_size(sizeof(u32)) + nla_total_size(sizeof(s32)))

struct yamir_msg {
    uint32_t ip4_addr;
    int ifindex;
};

// generic netlink message - wire format
struct genl_req {
    struct nlmsghdr n;
    struct genlmsghdr g;
    char buf[64] __attribute__((aligned(4)));
};

enum {
    YAMIR_ATTR_UNSPEC,
    YAMIR_ATTR_IP4ADDR,
    YAMIR_ATTR_IFINDEX,
    _YAMIR_ATTR_MAX
};

#define YAMIR_ATTR_MAX (_YAMIR_ATTR_MAX - 1)

// yamir cmd codes
enum {
    // send to kyamir
    YAMIR_RT_REG   = 0, // register
    YAMIR_RT_FAIL  = 1, // route discovery failed
    // recv from kyamir
    YAMIR_RT_NEED  = 4, // need-route
    YAMIR_RT_INUSE = 5, // route-inuse
    YAMIR_RT_ERR   = 6, // route-err
    // end
    _YAMIR_RT_MAX
};

static inline const char *yamir_cmd_tostr(uint32_t cmd)
{
    static char *names[] = {
        [YAMIR_RT_REG]   = "RT_REG",
        [YAMIR_RT_FAIL]  = "RT_FAIL",
        [YAMIR_RT_NEED]  = "RT_NEED",
        [YAMIR_RT_INUSE] = "RT_INUSE",
        [YAMIR_RT_ERR]   = "RT_ERR"
    };

    return cmd < sizeof(names)/ sizeof(names[0]) ? names[cmd] : "RT_???";
}

#define YAIMR_RT_MAX (_YAMIR_RT_MAX - 1)

#endif
