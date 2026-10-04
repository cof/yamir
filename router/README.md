# YAMIR - Yet Another MANET IP Router

YAMIR is a reactive IP router designed for **Mobile Ad-hoc Networks (MANET)**. 

Uses a kernel module to detect route requirements and a userspace daemon for route discovery and maintenance.

- `kyamir` - linux kernel module using netfilter hooks to intercept IP packets
- `yamird` - userspace daemon uses DYMO protocol for route discovery and rtnetlink for route maintenance

## Prerequisites

### Required
- **GCC**: Version 9.0 or higher
- **make**: Version 4.0 or higher
- Linux kernel headers

### Optional
- **ctags**: Version 5.9 or higher
- **wget**: Version 1.21 or higher
- **qemu-img**: Version 6.2 or higher
- **virt-install**: Version 4.0 or higher
- **virsh**  : Version 8.0 or higher

## Building the Project

- **make all** (Default): Compiles yamird, kyamir
- **make test** : Compiles and runs test_runner
- **make test-yamir** : create/install VM for router testing
- **make clean**: remove all compiled binaries, object files
- **make spotless**: removes VMs and all compiled binaries, object files

## Design

yamir in 2012 was originally built to run on a linux 2.6 kernel and used global
state, select() driven I/O, user-mode netlink socket, rwlocks and a mutex.

Code was rewritten to run on modern Linux kernel as shown below.

kyamir uses

- generic netlink for message exchange between yamird and kyamir
- netfilter hooks (PRE_ROUTING, LOCAL_OUT, POST_ROUTING)
- fib_lookup to check if route exists
- pernet subsystem with non global state storage
- netdevice notifier to detect interface changes
- inetaddr notifier to detect IP address changes
- spinlocks, seqlock_t and atomic for state changes

yamird uses

- draft-ietf-manet-dymo-21 (DYMO) routing protocol implementation
- PacketBB API codec with full address compression support
- Timer API with ms resolution for DYMO timeouts
- levels-based logging subsystem (FATAL, ERROR, INFO, DEBUG)
- poll driven I/O
- rtnetlink socket to install routes, tagged with proto 200
- generic netlink socket to send/recv kernel messages
- UDP socket for send/recv dymo messages 
- recvmmsg for batched reads with IP_PKTINFO info

## Testing

A VM `test-yamir` can be used to test the router.
Simply run the following.

    $ make test-yamir

This will build and install the VM as follows

- creates the `test-yamir` VM based based on Alpine Linux 
- copies kyamir source, yamird and create_manet.sh to VM /home/alpine
- build kyamir kernel module for VM
- run setcap on yamird for VM
- ssh to VM as alpine@test-yamir

To control the MANET use create_manet.sh script

- start: starts the MANET
- stop: stops the MANET
- route: show manet routes
- ping: run ping test
- tcp: run tcp test
- status: report yamird,kyamir status
- reset: clears log files

**Example: Starting the MANET**

    $ doas ./create_manet.sh start
    + ip link add mac-wlan0 type dummy
    + ip link set mac-wlan0 up
    + ip netns add yamir1
    + ip link add link mac-wlan0 name mv1 type macvlan mode bridge
    + ip link set mv1 netns yamir1
    + ip netns exec yamir1 ip link set mv1 name wlan0
    + ip netns exec yamir1 ip addr add 172.0.0.10/24 dev wlan0
    + ip netns exec yamir1 ip link set wlan0 up
    + ip netns add yamir2
    + ip link add link mac-wlan0 name mv1 type macvlan mode bridge
    + ip link set mv1 netns yamir2
    + ip netns exec yamir2 ip link set mv1 name wlan0
    + ip netns exec yamir2 ip addr add 172.0.0.20/24 dev wlan0
    + ip netns exec yamir2 ip link set wlan0 up
    + insmod /home/alpine/kyamir/kyamir.ko ifname=wlan0 max_qlen=1024
    + ip netns exec yamir1 /home/alpine/yamird -d -i wlan0 -f /var/log/yamir1.log -l 4
    + ip netns exec yamir2 /home/alpine/yamird -d -i wlan0 -f /var/log/yamir2.log -l 4


**Example: Checking status**

	$ doas ./create_manet.sh status
	== namespaces ==
	yamir2 (id: 1)
	yamir1 (id: 0)
	== yamird ==
	11361 /home/alpine/yamird -d -i wlan0 -f /var/log/yamir1.log -l 4
	11363 /home/alpine/yamird -d -i wlan0 -f /var/log/yamir2.log -l 4
	== kyamir ==
	[19080.775474] kyamir: kyamir_init: loaded netid=11
	== yamir1: route proto 200 ==
	== yamir2: route proto 200 ==

**Example: Ping test**

    $ doas ./create_manet.sh ping
    + ip netns exec yamir1 ping -I wlan0 -c 10 -i 0.1 -W 1 172.0.0.20
    PING 172.0.0.20 (172.0.0.20): 56 data bytes
    64 bytes from 172.0.0.20: seq=0 ttl=64 time=0.470 ms
    64 bytes from 172.0.0.20: seq=1 ttl=64 time=0.440 ms
    64 bytes from 172.0.0.20: seq=2 ttl=64 time=0.331 ms
    64 bytes from 172.0.0.20: seq=3 ttl=64 time=0.421 ms
    64 bytes from 172.0.0.20: seq=4 ttl=64 time=0.239 ms
    64 bytes from 172.0.0.20: seq=5 ttl=64 time=0.421 ms
    64 bytes from 172.0.0.20: seq=6 ttl=64 time=0.457 ms
    64 bytes from 172.0.0.20: seq=7 ttl=64 time=0.289 ms
    64 bytes from 172.0.0.20: seq=8 ttl=64 time=0.447 ms
    64 bytes from 172.0.0.20: seq=9 ttl=64 time=0.460 ms

    --- 172.0.0.20 ping statistics ---
    10 packets transmitted, 10 packets received, 0% packet loss
    round-trip min/avg/max = 0.239/0.397/0.470 ms

**Example: Stopping the MANET**

    $ doas ./create_manet.sh stop
    + pkill yamird
    + rmmod /home/alpine/kyamir/kyamir.ko
    + ip netns del yamir2
    + ip netns del yamir1
    + ip link del mac-wlan0




