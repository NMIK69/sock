CC=gcc
CFLAGS=-Wall -pedantic -std=c99 -Wextra -Wmissing-prototypes
OPTI=-O3

CLIENT=client
SERVER=server

DEBUG=0
ifeq ($(DEBUG),1)
CFLAGS+=-ggdb
OPTI=-O0
endif

all: $(SERVER) $(CLIENT)

.PHONY: ser
ser: $(SERVER)

.PHONY: cli
cli: $(CLIENT)


$(CLIENT): client.c
	$(CC) $(CFLAGS) $(OPTI) $^ -o $@

$(SERVER): server.c sockserv.c
	$(CC) $(CFLAGS) $(OPTI) $^ -o $@


.PHONY: clean
clean:
	rm -f $(SERVER)
	rm -f $(CLIENT)
