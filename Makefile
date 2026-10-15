CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=gnu11
LDFLAGS = -lcrypto
SRC     = src/main.c src/crypto.c src/registry.c src/chain.c src/ledger.c src/pool.c src/mining.c src/persist.c
OBJ     = $(SRC:.c=.o)

libchain: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

src/%.o: src/%.c src/libchain.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) libchain chain.dat chain.dat.tmp wallet.dat

.PHONY: clean
