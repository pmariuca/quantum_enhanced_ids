# Build the minimal QKS daemon (requires libnl-3 + libnl-genl-3 + liboqs)
APP := qks_daemon
SRC := qks_daemon.c

CC      := gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -std=c11
CFLAGS  += $(shell pkg-config --cflags libnl-3.0 libnl-genl-3.0)
CFLAGS  += -I. -I../kernel

LDFLAGS += $(shell pkg-config --libs libnl-3.0 libnl-genl-3.0)
LDFLAGS += -loqs -lcrypto

.PHONY: all clean keygen

# Build qks_keygen (liboqs)
keygen: qks_keygen.c
	$(CC) -O2 -Wall -Wextra -std=c11 qks_keygen.c \
	    -o qks_keygen \
	    -L/usr/local/lib -I/usr/local/include \
	    -loqs -lcrypto -lpthread -ldl


all: $(APP)

$(APP): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(APP) qks_keygen