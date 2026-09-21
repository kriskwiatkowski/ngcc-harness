# NGCC uniform build: kex-07 NEV-AKE (reference implementation)
NGCC_ID   := kex-07
NGCC_TYPE := kex
NGCC_ALG  := NEV-AKE
include ../api/link_rules.mk

REF := Implementations and Test_Vectors/Implementations/Reference_Implementation
NGCC_KAT_DIR := Implementations and Test_Vectors/Test_Vectors

# Each directory selects one parameter set via -DPARAMS=N -DUSE_ICCS (see its
# Makefile). randombytes.c (/dev/urandom) is replaced by kat_test/rng.c which
# draws from the shared drng_algorithm; symmetrics/ and kat_test/ hold the
# hash backends, DRNG and the ICCS API implementation.
NEV_SRCS := poly.c ntt.c owpke.c owkem.c verify.c sample.c pack.c cca.c cpa.c ake.c \
            symmetrics/hashkdf.c symmetrics/fips202.c symmetrics/auxfunc.c \
            kat_test/rng.c kat_test/drng.c kat_test/KEX_AlgorithmInstance.c

# label, dir, PARAMS
define NEV
SRCS_$(1) := $(NEV_SRCS)
INC_$(1)  := -Isrc/$(1)/symmetrics -Isrc/$(1)/kat_test
DEFS_$(1) := -DPARAMS=$(3) -DUSE_ICCS
SHIMDEFS_$(1) := -DNGCC_INSTANCE_HEADER='"kat_test/KEX_AlgorithmInstance.h"'
$$(eval $$(call ngcc_instance,$(1),$(REF)/$(2)))
endef

$(eval $(call NEV,NEV_AKE_512_769_C,NEV-AKE-C1-c,1))
$(eval $(call NEV,NEV_AKE_1024_769_C,NEV-AKE-C2-c,2))
$(eval $(call NEV,NEV_AKE_2048_769_C,NEV-AKE-C3-c,3))
$(eval $(call NEV,NEV_AKE_512_1409,NEV-AKE-R1,4))
$(eval $(call NEV,NEV_AKE_1024_1409,NEV-AKE-R2,5))
$(eval $(call NEV,NEV_AKE_2048_1409,NEV-AKE-R3,6))
$(eval $(call NEV,NEV_AKE_512_769,NEV-AKE-C1,7))
$(eval $(call NEV,NEV_AKE_1024_769,NEV-AKE-C2,8))
$(eval $(call NEV,NEV_AKE_2048_769,NEV-AKE-C3,9))

include ../api/link_finish.mk
