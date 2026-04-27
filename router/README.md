# YAMIR - Yet Another MANET IP Router

YAMIR is a reactive IP router designed for **Mobile Ad-hoc Networks (MANET)**. 

It uses a hybrid design where a kernel module detects route requirements and a userspace daemon performs route discovery and maintenace.

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

## Background & History

YAMIR was originally part of final year college project on mesh comms.
It showed how sim-free voice and video calls could be made using telco networks built out of household applicanses suchs as laptops and smartphones.

The idea of mesh-network infrastructure has been at the back of my mind since the early 2000s, sparked by the rise of smartphones and the works of authors like Cory Doctorow, Neal Stephenson, and Charles Stross. When Android arrived in 2008 —running the Linux kernel under the hood—it really piqued my interest. That interest finally saw the light of day as my final year college project back in 2012. The project resulted in YAMIR and a MANET infrastructure built using some Fedora laptops, HTC Desires and a Samsung S2.

The name YAMIR (Yet Another MANET IP Router) also had 2 other meanings. One was 'yammer' which came to represent the constant chatter between moving DYMO nodes during SIP video calls. The other was the Indian word for the Moon, a reminder of all the late nights spent debugging the code.

