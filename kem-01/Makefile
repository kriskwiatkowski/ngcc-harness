# NGCC uniform build: kem-01 Aigis-Enc+ (reference implementation)
NGCC_ID   := kem-01
NGCC_TYPE := kem
NGCC_ALG  := Aigis-Enc+
include ../api/link_rules.mk

REF := Implementations/Reference_Implementation
NGCC_KAT_DIR := Test_Vectors

# Per the candidate Makefile: -DPARAMS=N -DUSE_NICCS_API; kat_test/rng.c maps
# randombytes() onto the shared drng_algorithm (randombytes.c reads /dev/urandom
# and is excluded); speed_test/ and keccak4x/ (AVX2) are not needed.
AIGIS_SRCS := cbd.c fips202.c poly.c reduce.c precomp.c ntt.c polyvec.c owcpa.c kem.c verify.c \
              hashkdf.c gen_a.c pack.c kat_test/auxfunc.c kat_test/KEM_AlgorithmInstance.c \
              kat_test/drng.c kat_test/rng.c

define AIGIS
SRCS_$(1) := $(AIGIS_SRCS)
INC_$(1)  := -Isrc/$(1)/kat_test
DEFS_$(1) := -DPARAMS=$(3) -DUSE_NICCS_API
SHIMDEFS_$(1) := -DNGCC_INSTANCE_HEADER='"kat_test/KEM_AlgorithmInstance.h"'
$$(eval $$(call ngcc_instance,$(1),$(REF)/$(2),$(3)))
endef

$(eval $(call AIGIS,Aigis-enc1,Aigis-Enc+-I,1))
$(eval $(call AIGIS,Aigis-enc2,Aigis-Enc+-II,2))
$(eval $(call AIGIS,Aigis-enc3,Aigis-Enc+-III,3))

include ../api/link_finish.mk
