#!/bin/bash

# script to manage MANET
#
# Topology:
#
#      ns1             ns2
#     yamird          yamird
#       |               |
#     wlan0           wlan0
#   172.0.0.10/24   172.0.0.20/24
#       |              |
#    macvlan        macvlan
#       |              |
#       +--- bridge ---+

RUN_DIR=/home/alpine
KYAMIR=$RUN_DIR/kyamir/kyamir.ko
YAMIRD=$RUN_DIR/yamird

# config
IFNAME=wlan0
MAX_QLEN=1024
BRIDGE=mac-wlan0
NS1=yamir1
NS2=yamir2
ADDR_NS1=172.0.0.10
ADDR_NS2=172.0.0.20
ADDR_MASK=24
LOG_LEVEL=3
VIRT_LINK=mv1
PING_TIMES=10

start()
{
    # trace commands
    set -x

    # create bridge interface
    ip link add $BRIDGE type dummy
    ip link set $BRIDGE up

    # create ns1 - attach macvlan link to bridge
    ip netns add $NS1
    ip link add link $BRIDGE name $VIRT_LINK type macvlan mode bridge
    ip link set $VIRT_LINK netns $NS1
    ip netns exec $NS1 ip link set $VIRT_LINK name $IFNAME
    ip netns exec $NS1 ip addr add $ADDR_NS1/$ADDR_MASK dev wlan0
    ip netns exec $NS1 ip link set $IFNAME up

    # create ns2 - attach macvlan link to bridge
    ip netns add $NS2
    ip link add link $BRIDGE name $VIRT_LINK type macvlan mode bridge
    ip link set $VIRT_LINK netns $NS2
    ip netns exec $NS2 ip link set $VIRT_LINK name $IFNAME
    ip netns exec $NS2 ip addr add $ADDR_NS2/$ADDR_MASK dev wlan0
    ip netns exec $NS2 ip link set $IFNAME up

    # load kernel module
    insmod $KYAMIR ifname=$IFNAME max_qlen=$MAX_QLEN

    # launch userspace
    ip netns exec $NS1 $YAMIRD -d -i $IFNAME -f /var/log/$NS1.log -l $LOG_LEVEL
    ip netns exec $NS2 $YAMIRD -d -i $IFNAME -f /var/log/$NS2.log -l $LOG_LEVEL
}

stop()
{
    # trace commands
    set -x

    # stop yamird instances across all namespaces
    pkill -f $YAMIRD

    # unload kernel module
    rmmod $KYAMIR

    # remove namespaces
    ip netns del $NS2
    ip netns del $NS1

    # remove bridge
    ip link del $BRIDGE
}

status() {
    pgrep -af $YAMIRD
    dmesg | grep -E 'kyamir.*loaded|kymair.*unloaded'
}

# reset logs
reset() {
    > /var/log/$NS1.log
    > /var/log/$NS2.log
}

# start route discovery
ping() {
    set -x
    ip netns exec $NS1 ping -I wlan0 -c $PING_TIMES -i 0.1 -W 1 $ADDR_NS2
    set +x
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "ping test failed"
        exit "$rc"
    fi
}

case "$1" in
    start)  start ;;
    stop)   stop ;;
    status) status ;;
    ping)   ping ;;
    reset)  reset ;;
    *) echo "Usage: $0 {start|stop|status|ping|reset}" ;;
esac

