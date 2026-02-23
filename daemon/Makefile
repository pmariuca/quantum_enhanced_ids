# Build the minimal QKS daemon (requires libnl-3 + libnl-genl-3)
#   sudo apt install libnl-3-dev libnl-genl-3-dev
# If pkg-config is missing, install: sudo apt install pkg-config

APP := qks_daemon
SRC := qks_daemon.c

CFLAGS  ?= -O2 -g -Wall -Wextra -std=c11
CFLAGS  += $(shell pkg-config --cflags libnl-3.0 libnl-genl-3.0)
CFLAGS  += -I../kernel
LDFLAGS += $(shell pkg-config --libs   libnl-3.0 libnl-genl-3.0)

.PHONY: all clean
all: $(APP)

$(APP): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(APP)