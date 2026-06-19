APP := qks_daemon

CC      := gcc
WARN    := -Wall -Wextra -Wno-unused-parameter
OPT     := -O2 -g -std=c11

PQ_DIR      := pqclean/ml-dsa-44/clean
ML_DIR      := ml_service

CFLAGS  := $(OPT) $(WARN)
CFLAGS  += $(shell pkg-config --cflags libnl-3.0 libnl-genl-3.0)

CFLAGS  += -I. -I$(PQ_DIR)

LDFLAGS := $(shell pkg-config --libs libnl-3.0 libnl-genl-3.0)
LDFLAGS += -lcrypto -ldl -lpthread

# PQClean sources
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

RNG_SRC := randombytes.c \
  queue.c

POLICY_SRCS := policy.c cJSON.c

ML_SRCS := $(ML_DIR)/ml_buffer.c $(ML_DIR)/ml_client.c


.PHONY: all clean

all: qks_daemon

qks_daemon: qks_daemon.c $(PQ_SRCS) $(RNG_SRC) $(POLICY_SRCS) $(ML_SRCS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)


clean:
	rm -f qks_daemon *.o