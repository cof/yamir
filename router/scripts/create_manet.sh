#!/bin/bash

# script to manage MANET

KYAMIR=/home/alpine/kyamir/kyamir.ko
YAMIRD=/home/alpine/yamird

# config 
NS1=yamir1
NS2=yamir2
ADDR_NS1=172.0.0.10
ADDR_NS2=172.0.0.20
ADDR_MASK=24
BRIDGE=mac-wlan0
LOG_LEVEL=4

start() 
{
    set -x
    # need interface for MACVLAN Master
    ip link add $BRIDGE type dummy
    ip link set $BRIDGE up

    # add ns1 network
    ip netns add $NS1
    ip link add link $BRIDGE name mv1 type macvlan mode bridge
    ip link set mv1 netns $NS1
    ip netns exec $NS1 ip link set mv1 name wlan0
    ip netns exec $NS1 ip addr add $ADDR_NS1/$ADDR_MASK dev wlan0
    ip netns exec $NS1 ip link set wlan0 up

    # add ns2 network
    ip netns add $NS2
    ip link add link $BRIDGE name mv1 type macvlan mode bridge
    ip link set mv1 netns $NS2
    ip netns exec $NS2 ip link set mv1 name wlan0
    ip netns exec $NS2 ip addr add $ADDR_NS2/$ADDR_MASK dev wlan0
    ip netns exec $NS2 ip link set wlan0 up

    # load kernel module
    insmod $KYAMIR ifname=wlan0

    # launch userspace
    ip netns exec $NS1 $YAMIRD -d -i wlan0 -f /var/log/$NS1.log -l $LOG_LEVEL
    ip netns exec $NS2 $YAMIRD -d -i wlan0 -f /var/log/$NS2.log -l $LOG_LEVEL
}

stop() 
{
    set -x

    # stop router
    pkill yamird
    rmmod $KYAMIR 

    # delete network
    ip netns del $NS2
    ip netns del $NS1
    ip link del  $BRIDGE
}

status() {
    pgrep -a yamird
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

