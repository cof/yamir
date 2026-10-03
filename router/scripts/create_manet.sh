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

# network
IFNAME=wlan0
MAX_QLEN=1024
BRIDGE=mac-wlan0
NS1=yamir1
NS2=yamir2
ADDR_NS1=172.0.0.10
ADDR_NS2=172.0.0.20
ADDR_MASK=24
LOG_LEVEL=4
VIRT_LINK=mv1
RTM_PROTO=200
# ping
PING_TIMES=10
PING_INTERVAL=0.1
# tcp
TEST_FILE=/tmp/manet_test.txt
FILE_SIZE=$((10 * 1024 * 1024))
TCP_OUT=/tmp/$NS2-tcp.out
TCP_PORT=5001
TCP_TIMOUT=5

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

	# generate test file
	head -c "$FILE_SIZE" /dev/zero > "$TEST_FILE"
}

stop()
{
    # trace commands
    set -x

	rm -f "$TEST_FILE"

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
	echo "== namespaces =="
	ip netns list | grep -E "^($NS1|$NS2)\b"
	echo "== yamird =="
    pgrep -af $YAMIRD
	echo "== kyamir =="
    dmesg | grep -E 'kyamir.*(loaded|unloaded)'
	yamir_routes
}

# reset debug logs
reset() {
    set -x
    > /var/log/$NS1.log
    > /var/log/$NS2.log
    dmesg -C
}

yamir_routes() {
    for ns in "$NS1" "$NS2"; do
        echo "== $ns: route proto $RTM_PROTO =="
        ip -n "$ns" route show proto $RTM_PROTO
    done
}

# list routes
routes() {
    for ns in "$NS1" "$NS2"; do
        echo "== $ns: routes =="
        ip -n "$ns" route 
    done
}

# start route discovery
ping() {
	# run ping in NS1 for addr in NS2
    ip netns exec $NS1 ping -I $IFNAME -c $PING_TIMES -i $PING_INTERVAL -W 1 $ADDR_NS2

    # check ping worked
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "ping test failed"
        exit "$rc"
    fi
}

tcp()
{
    # start TCP server in NS2
    echo "Starting TCP server"
    rm -f "$TCP_OUT"

    ip netns exec $NS2 nc -l -w 2 -p $TCP_PORT > "$TCP_OUT" &
    SERVER_PID=$!
    sleep 1
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "TCP test failed: nc server not running"
        # clean up
        rm -f "$TCP_OUT"
        return 1
    fi

    # client sends file from NS1
    echo "Sending file"
	ip netns exec "$NS1" nc -w 2 "$ADDR_NS2" "$TCP_PORT" < "$TEST_FILE"
	rc=$?

    # Check send result
    if [ "$rc" -ne 0 ]; then
        echo "TCP test failed: nc returned $rc"
		# clean up
		kill "$SERVER_PID" 2>/dev/null
		wait "$SERVER_PID" 2>/dev/null
        rm -f "$TCP_OUT"
		# report error
        return "$rc"
    fi

	# wait for server to finish
	sleep 1

    # verify rx byte count
	if ! cmp -s "$TCP_OUT" "$TEST_FILE"; then
        echo "TCP test failed : file mistmatch"
		# clean up
		kill "$SERVER_PID" 2>/dev/null
		wait "$SERVER_PID" 2>/dev/null
        rm -f "$TCP_OUT"
		# report error
        return 1
    fi

    echo "TCP test passed"

	# clean up
	kill "$SERVER_PID" 2>/dev/null
	wait "$SERVER_PID" 2>/dev/null
    rm -f "$TCP_OUT"

    return 0
}

case "$1" in
    start)  start ;;
    stop)   stop ;;
    status) status ;;
    reset)  reset ;;
    routes) routes ;; 
    ping)   ping ;;
    tcp)    tcp ;; 
    *) echo "Usage: $0 {start|stop|status|route|ping|tcp|reset}" ;;
esac

