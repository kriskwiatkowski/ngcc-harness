# NGCC uniform build: sign-03 CEDRUS+C (reference implementation)
NGCC_ID   := sign-03
NGCC_TYPE := sig
NGCC_ALG  := CEDRUS+C
include ../api/link_rules.mk

REF := Implementations/Reference_Implementation
NGCC_KAT_DIR := Test_Vectors

# SPHINCS+-style hash-based scheme, one directory per parameter set. The
# candidate Makefile compiles every listed .c plus sign.c (= default glob minus
# KAT_SIG.c); params.h hard-includes params/params-cedrusc-sm3-<set>.h, so the
# -DPARAMS=<name> of the candidate Makefile is not needed. randombytes.c is
# already the DRNG wrapper (drng_algorithm), no /dev/urandom.
$(eval $(call ngcc_instance,CEDRUSC-160f,$(REF)/CEDRUSC-160f))
$(eval $(call ngcc_instance,CEDRUSC-160s,$(REF)/CEDRUSC-160s))
$(eval $(call ngcc_instance,CEDRUSC-256f,$(REF)/CEDRUSC-256f))
$(eval $(call ngcc_instance,CEDRUSC-256s,$(REF)/CEDRUSC-256s))
$(eval $(call ngcc_instance,CEDRUSC-384f,$(REF)/CEDRUSC-384f))
$(eval $(call ngcc_instance,CEDRUSC-384s,$(REF)/CEDRUSC-384s))
$(eval $(call ngcc_instance,CEDRUSC-512f,$(REF)/CEDRUSC-512f))
$(eval $(call ngcc_instance,CEDRUSC-512s,$(REF)/CEDRUSC-512s))

FORGE_SRC := $(REF)/CEDRUSC-160f

.PHONY: exploit clean-exploit
all: reproduce_forgery
exploit: reproduce_forgery

reproduce_forgery: reproduce_forgery.c ../api/link_common.h ../api/link_sig.h \
                   $(FORGE_SRC)/auxfunc.c $(FORGE_SRC)/auxfunc.h
	$(CC) -O2 -std=gnu11 -Wall -Wextra -Wno-unused-parameter \
		-I../api -I$(FORGE_SRC) -o $@ reproduce_forgery.c \
		$(FORGE_SRC)/auxfunc.c -ldl -lm

clean-exploit:
	rm -f reproduce_forgery
clean: clean-exploit

include ../api/link_finish.mk
