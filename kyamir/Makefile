#
# Yet Another Manet IP Router
#
# kernel module
#
.PHONY : all clean doc

# If KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language.
#

ifneq ($(KERNELRELEASE),)
  obj-m = kyamir.o
  ccflags-y += -I$(src)/../include
# Otherwise we were called directly from the command
# line; invoke the kernel build system.
else
  KERNELDIR ?= /lib/modules/$(shell uname -r)/build
  PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

endif
