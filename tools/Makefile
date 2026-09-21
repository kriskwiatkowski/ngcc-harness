# Reproducers for the reported NGCC Round 1 defects. See tools/README.md.
ROOT := ..
CC ?= gcc
CFLAGS ?= -O2 -std=gnu11 -Wall -Wextra -Wno-unused-parameter

.PHONY: all clean
all: ngcc_attack

ngcc_attack: ngcc_attack.c $(ROOT)/api/link_common.h $(ROOT)/api/link_hash.h \
             $(ROOT)/api/link_kem.h $(ROOT)/api/link_sig.h
	$(CC) $(CFLAGS) -I$(ROOT)/api -o $@ ngcc_attack.c -ldl

clean:
	rm -f ngcc_attack
