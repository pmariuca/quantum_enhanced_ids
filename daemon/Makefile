APP := qks_daemon

CC      := gcc
WARN    := -Wall -Wextra -Wno-unused-parameter
OPT     := -O2 -g -std=c11

PQ_DIR      := pqclean/ml-dsa-44/clean

CFLAGS  := $(OPT) $(WARN)
CFLAGS  += $(shell pkg-config --cflags libnl-3.0 libnl-genl-3.0)

# include order: local → pqclean → compat
CFLAGS  += -I. -I$(PQ_DIR)

LDFLAGS := $(shell pkg-config --libs libnl-3.0 libnl-genl-3.0)
LDFLAGS += -lcrypto -ldl -lpthread

# PQClean sources (DO NOT include shake_wrapper_user.c)
PQ_SRCS := \
  $(PQ_DIR)/sign.c \
  $(PQ_DIR)/packing.c \
  $(PQ_DIR)/poly.c \
  $(PQ_DIR)/polyvec.c \
  $(PQ_DIR)/ntt.c \
  $(PQ_DIR)/reduce.c \
  $(PQ_DIR)/rounding.c \
  $(PQ_DIR)/fips202.c \
  $(PQ_DIR)/symmetric-shake.c

RNG_SRC := randombytes.c

.PHONY: all clean

all: qks_daemon

qks_daemon: qks_daemon.c $(PQ_SRCS) $(RNG_SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f qks_daemon *.o