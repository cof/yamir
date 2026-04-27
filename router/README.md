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

## Testing


