# SPDX-License-Identifier: GPL-2.0

# Name of the module
obj-m := qks.o

# Object files that form the module
qks-objs := \
	qks_log.o \
	qks_sigverify.o \
	qks_syscalls.o \
	qks_netlink.o \
	qks_netfilter.o \
	qks_main.o \
	qks_pqc_glue.o \
	qks_ids.o \
	qks_enforce.o \
    third-party/pqclean/ml-dsa-44/clean/keccak_kern.o \
    third-party/pqclean/ml-dsa-44/clean/shake_inc_kern.o \
    third-party/pqclean/ml-dsa-44/clean/stream_kern.o \
    third-party/pqclean/ml-dsa-44/clean/pqc_verify_only.o \
	third-party/pqclean/ml-dsa-44/clean/packing.o \
	third-party/pqclean/ml-dsa-44/clean/poly.o \
	third-party/pqclean/ml-dsa-44/clean/polyvec.o \
	third-party/pqclean/ml-dsa-44/clean/ntt.o \
	third-party/pqclean/ml-dsa-44/clean/reduce.o \
	third-party/pqclean/ml-dsa-44/clean/rounding.o


# Include paths
ccflags-y += -I$(PWD)
ccflags-y += -I$(PWD)/third-party/compat
ccflags-y += -I$(PWD)/third-party/pqclean/ml-dsa-44/clean

# Force-include kernel‑safe PQClean compat shim
ccflags-y += -include $(PWD)/third-party/compat/qks_pqclean_compat.h

# Silence some warnings from PQClean
ccflags-y += -Wno-declaration-after-statement
ccflags-y += -Wno-sign-compare
ccflags-y += -Wno-unused-parameter

# ===========================
# Build targets
# ===========================

KDIR := /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean