#!/bin/bash

# script to manage MANET

RUN_DIR=/home/alpine
KYAMIR=$RUN_DIR/kyamir/kyamir.ko
YAMIRD=$RUN_DIR/yamird

# config
IFNAME=wlan0
BRIDGE=mac-wlan0
NS1=yamir1
NS2=yamir2
ADDR_NS1=172.0.0.10
ADDR_NS2=172.0.0.20
ADDR_MASK=24
LOG_LEVEL=3
TMP_NAME=mv1

start()
{
    set -x
    # need interface for MACVLAN master
    ip link add $BRIDGE type dummy
    ip link set $BRIDGE up

    # add ns1 network
    ip netns add $NS1
    ip link add link $BRIDGE name $TMP_NAME type macvlan mode bridge
    ip link set mv1 netns $NS1
    ip netns exec $NS1 ip link set $TMP_NAME name $IFNAME
    ip netns exec $NS1 ip addr add $ADDR_NS1/$ADDR_MASK dev wlan0
    ip netns exec $NS1 ip link set $IFNAME up

    # add ns2 network
    ip netns add $NS2
    ip link add link $BRIDGE name $TMP_NAME type macvlan mode bridge
    ip link set mv1 netns $NS2
    ip netns exec $NS2 ip link set $TMP_NAME name $IFNAME
    ip netns exec $NS2 ip addr add $ADDR_NS2/$ADDR_MASK dev wlan0
    ip netns exec $NS2 ip link set $IFNAME up

    # load kernel module
    insmod $KYAMIR ifname=$IFNAME

    # launch userspace
    ip netns exec $NS1 $YAMIRD -d -i $IFNAME -f /var/log/$NS1.log -l $LOG_LEVEL
    ip netns exec $NS2 $YAMIRD -d -i $IFNAME -f /var/log/$NS2.log -l $LOG_LEVEL
}

stop()
{
    set -x

    # stop router
    pkill -f $YAMIRD
    rmmod $KYAMIR

    # delete network
    ip netns del $NS2
    ip netns del $NS1
    ip link del  $BRIDGE
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
   ip netns exec $NS1 ping -I wlan0 $ADDR_NS2
}

case "$1" in
    start)  start ;;
    stop)   stop ;;
    status) status ;;
    ping)   ping ;;
    reset)  reset ;;
    *) echo "Usage: $0 {start|stop|status|ping|reset}" ;;
esac

