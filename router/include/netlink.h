#ifndef _NETLINK_H_
#define _NETLINK_H_

// TODO (settings common both to both user/kernel space)
// default settings from draft-ietf-manet-dymo-21.txt
#define DYMO_INTERFACE "wlan0"
#define DYMO_PORT  269

#define NETLINK_YAMIR NETLINK_USERSOCK
#define NETLINK_YAMIR_GROUP 1

// recv from kyamir
#define YAMIR_RT_NEED  0
#define YAMIR_RT_INUSE 1
#define YAMIR_RT_ERR   2
// sent to kyamir
#define YAMIR_RT_NONE 3
#define YAMIR_RT_ADD  4
#define YAMIR_RT_DEL  5

// rtm_protocol - See /usr/include/linux/rtnetlink.h
#define YAMIR_RTNETLINK 30

// addess taken from iphdr 
struct yamir_msg {
    uint32_t addr;
    int ifindex;
};

#endif
