obj-m += qks.o

qks-objs := \
    qks_sigverify.o \
    qks_syscalls.o \
    qks_netlink.o \
    qks_netfilter.o \
    qks_main.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean