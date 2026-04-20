#ifndef _NETLINK_H_
#define _NETLINK_H_

// TODO (settings common both to both user/kernel space)
// default settings from draft-ietf-manet-dymo-21.txt
#define DYMO_INTERFACE "wlan0"
#define DYMO_PORT  269

#define NETLINK_YAMIR NETLINK_USERSOCK
#define NETLINK_YAMIR_GROUP 1

// messages kernel sends to us
#define YAMIR_ROUTE_NEED 0
#define YAMIR_ROUTE_INUSE 1
#define YAMIR_ROUTE_ERR 2

// message we send to kernel
#define YAMIR_ROUTE_NOTFOUND 3
#define YAMIR_ROUTE_ADD 4
#define YAMIR_ROUTE_DEL 5

// addess taken from iphdr 
struct yamir_msg {
    uint32_t addr;
    int ifindex;
};

#endif
