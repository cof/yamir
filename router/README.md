# YAMIR - Yet Another MANET IP Router

YAMIR is a reactive IP router designed for **Mobile Ad-hoc Networks (MANET)**. 

Uses a kernel module to detect route requirements and a userspace daemon for route discovery and maintenance.

- `kyamir` - linux kernel module using netfilter hooks to intercept IP packets
- `yamird` - userpace daemon uses DYMO protocol for route discovery and rtnetlink for route maintenace

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

## Testing

A VM `test-yamir` can be used to test the router.
Simply run the following.

    $ make test-yamir

This will build and install the VM as follows

- creates the `test-yamir` VM based based on Alpine Linux 
- copies kyamir source, yamird and create_manet.sh to VM /home/alpine
- build kyamird kernel module for VM
- run setcap on yamird for VM
- ssh to VM as alpine@test-yamir

To control the MANET use create_manet.sh script

- start: starts the MANET
- stop: stops the MANET
- ping: starts route discovery
- status: report yamir,kyamird status
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
    + insmod /home/alpine/kyamir/kyamir.ko ifname=wlan0
    + ip netns exec yamir1 /home/alpine/yamird -d -i wlan0 -f /var/log/yamir1.log -l 4
    + ip netns exec yamir2 /home/alpine/yamird -d -i wlan0 -f /var/log/yamir2.log -l 4

**Example: Start route discovery**

    $ doas ./create_manet.sh ping
    + ip netns exec yamir1 ping -I wlan0 172.0.0.20
    PING 172.0.0.20 (172.0.0.20): 56 data bytes
    64 bytes from 172.0.0.20: seq=1 ttl=64 time=7.599 ms
    64 bytes from 172.0.0.20: seq=2 ttl=64 time=7.727 ms
    64 bytes from 172.0.0.20: seq=3 ttl=64 time=7.659 ms
    64 bytes from 172.0.0.20: seq=4 ttl=64 time=7.956 ms

**Example: Stopping the MANET**

    $ doas ./create_manet.sh stop
    + pkill yamird
    + rmmod /home/alpine/kyamir/kyamir.ko
    + ip netns del yamir2
    + ip netns del yamir1
    + ip link del mac-wlan0




