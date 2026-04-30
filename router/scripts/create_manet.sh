#!/bin/bash

KYAMIR=/home/alpine/kyamir/kyamir.ko
YAMIRD=/home/alpine/yamird

# network config 
NS1="yamir1"
NS2="yamir2"
NS1_ADDR="172.0.0.10/24"
NS2_ADDR="172.0.0.20/24"
BRIDGE="mac-wlan0"
LOG_LEVEL=4

set -x

# need interface for MACVLAN Master
ip link add $BRIDGE type dummy
ip link set $BRIDGE up

ip netns add $NS1
ip link add link $BRIDGE name mv1 type macvlan mode bridge
ip link set mv1 netns $NS1
ip netns exec $NS1 ip link set mv1 name wlan0
ip netns exec $NS1 ip addr add $NS1_ADDR dev wlan0
ip netns exec $NS1 ip link set wlan0 up

ip netns add $NS2
ip link add link $BRIDGE name mv1 type macvlan mode bridge
ip link set mv1 netns $NS2
ip netns exec $NS2 ip link set mv1 name wlan0
ip netns exec $NS2 ip addr add $NS2_ADDR dev wlan0
ip netns exec $NS2 ip link set wlan0 up

#echo "$NS1 and $NS2 are up"
#> /var/log/$NS1.log
#> /var/log/$NS2.log 

# load kernel module
insmod $KYAMIR ifname=wlan0

# launch userspace
ip netns exec $NS1 $YAMIRD -d -i wlan0 -f /var/log/$NS1.log -l $LOG_LEVEL
ip netns exec $NS2 $YAMIRD -d -i wlan0 -f /var/log/$NS2.log -l $LOG_LEVEL
