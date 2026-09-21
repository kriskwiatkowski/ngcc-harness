# NGCC uniform build: kem-32 QCTM (Quasi-Cyclic Twisted McEliece KEM, reference implementation)
NGCC_ID   := kem-32
NGCC_TYPE := kem
NGCC_ALG  := QCTM
include ../api/link_rules.mk

REF := Implementations/Reference_Implementation
NGCC_KAT_DIR := Test_Vectors

# Source list from the candidate Makefile's api-pkc-kat target: OBJECTS
# (keccak kem m2e permutation gf poly goppa seeded_keygen qctmNNN_kem_api
# decode roots) + rng.c + KEM_AlgorithmInstance.c built with
# -DAPI_PKC_KAT_DRNG_BRIDGE + .api-pkc-kat/drng.c (official copy, identical to
# api/). Their build does not link auxfunc.c, so NOAUX.
# Randomness: the scheme's core calls the NIST AES256-CTR-DRBG in rng.c
# (OpenSSL EVP, hence -lcrypto). With API_PKC_KAT_DRNG_BRIDGE the adapter
# seeds that DRBG with 48 bytes drawn from drng_algorithm at every kem_keygen
# (and lazily before kem_enc if not yet seeded), so all randomness is
# ultimately derived from the official DRNG. The many *_kat.c / *_speed.c /
# *_experiment.c / audit_* / verify_* / hybrid_roundtrip.c / recompute_* files
# are standalone tools and are not linked.
define QCTM
SRCS_$(1) := keccak.c kem.c m2e.c permutation.c gf.c poly.c goppa.c seeded_keygen.c $(2)_kem_api.c \
             decode.c roots.c rng.c KEM_AlgorithmInstance.c .api-pkc-kat/drng.c
INC_$(1)  := -Isrc/$(1)/.api-pkc-kat
DEFS_$(1) := -DAPI_PKC_KAT_DRNG_BRIDGE
# gf.h holds tentative definitions (gf_exp, gf_log, ...) in every TU -> -fcommon
CFLAGS_$(1) := -fcommon
LDLIBS_$(1) := -lcrypto
NOAUX_$(1) := 1
# McEliece-style keygen with multi-MB keys is slow (QCTM128 ~4 min, QCTM256
# ~15 min for 10 records here; the candidate's own KAT timestamps suggest
# ~45 min for QCTM512): raise the wall-clock limit, and for QCTM512 verify
# only the first 3 records (README: TESTFLAGS --count 3 for very slow code).
TESTFLAGS_$(1) := $(3)
$$(eval $$(call ngcc_instance,$(1),$(REF)/$(1)))
endef

$(eval $(call QCTM,QCTM128,qctm128,))
$(eval $(call QCTM,QCTM256,qctm256,--timeout 3600))
$(eval $(call QCTM,QCTM512,qctm512,--count 3 --timeout 3600))

include ../api/link_finish.mk
