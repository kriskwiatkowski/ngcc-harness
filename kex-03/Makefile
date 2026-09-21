# NGCC uniform build: kex-03 CreTAKE (reference implementation)
NGCC_ID   := kex-03
NGCC_TYPE := kex
NGCC_ALG  := CreTAKE
include ../api/link_rules.mk

REF := Implementations/Reference_Implementation
NGCC_KAT_DIR := Test_Vectors/Reference_Test_Vector

# Every instance directory holds the protocol layer (KEX_AlgorithmInstance.c,
# twokem.c/twopke.c for K2K, auxfunc.c, drng.c, secure_bzero.c) and links one
# KEM backend (ZEN_* or POLARLAC-*) and, for K2S/S2K/S2S, the BiT-* signature
# backend from Common/primitives. The candidate builds those as static
# archives (.a); we compile their sources directly instead (lists from each
# primitive's Makefile: ZEN KEM_LIB_SOURCES, POLARLAC COMMON_SOURCES with
# -DBIT_USE_SHAKE=0 -DRL_KEM_USE_CONJ_NTT_REJECTION=0, BiT = all *.c but the
# KAT driver). Primitive symbols are namespaced (bit_*, zen_*, pqcrystals_*),
# so KEM+SIG can share one library. Each primitive ships its own drng.c and
# auxfunc.c; only the protocol directory's copies are compiled (all copies are
# the official files up to CRLF, a trailing newline and a parameter rename).
# primitive_interfaces.h reaches the backends via ../../Common/..., which
# resolves through the src/<label> symlink. Optimized_Test_Vector is ignored.
PRIM := ../../Common/primitives
PROTO_SRCS := KEX_AlgorithmInstance.c auxfunc.c drng.c secure_bzero.c
ZEN_SRCS   := sample.c ntt.c poly.c symmetric.c pke.c KEM_AlgorithmInstance.c
PLAC_SRCS  := fips202.c symmetric.c sample.c poly.c pke.c polar.c ntt.c fft.c KEM_AlgorithmInstance.c
BIT_SRCS   := SIG_AlgorithmInstance.c fips202.c ntt.c packing.c poly.c polyvec.c sample.c sign.c symmetric.c

# label, level dir, KEM dir (under kem/), SIG dir (under sig/, may be empty), extra protocol sources
define CRETAKE
SRCS_$(1) := $(PROTO_SRCS) $(5) \
    $(if $(findstring ZEN,$(3)),$(addprefix $(PRIM)/kem/$(3)/,$(ZEN_SRCS)),$(addprefix $(PRIM)/kem/$(3)/,$(PLAC_SRCS))) \
    $(if $(4),$(addprefix $(PRIM)/sig/$(4)/,$(BIT_SRCS)))
INC_$(1)  := -Isrc/$(1)/$(PRIM)/kem/$(3) $(if $(4),-Isrc/$(1)/$(PRIM)/sig/$(4))
DEFS_$(1) := -DBIT_USE_SHAKE=0 -DRL_KEM_USE_CONJ_NTT_REJECTION=0
$$(eval $$(call ngcc_instance,$(1),$(REF)/$(2)/$(1)))
endef

$(eval $(call CRETAKE,CreTAKE-K2K-PLAC128,CreTAKE128,POLARLAC-128,,twokem.c))
$(eval $(call CRETAKE,CreTAKE-K2K-ZEN128,CreTAKE128,ZEN_128,,twokem.c))
$(eval $(call CRETAKE,CreTAKE-K2S-PLAC128-BiT128,CreTAKE128,POLARLAC-128,BiT-128,))
$(eval $(call CRETAKE,CreTAKE-K2S-ZEN128-BiT128,CreTAKE128,ZEN_128,BiT-128,))
$(eval $(call CRETAKE,CreTAKE-S2K-BiT128-PLAC128,CreTAKE128,POLARLAC-128,BiT-128,))
$(eval $(call CRETAKE,CreTAKE-S2K-BiT128-ZEN128,CreTAKE128,ZEN_128,BiT-128,))
$(eval $(call CRETAKE,CreTAKE-S2S-BiT128-ePLAC128,CreTAKE128,POLARLAC-128,BiT-128,))
$(eval $(call CRETAKE,CreTAKE-S2S-BiT128-eZEN128,CreTAKE128,ZEN_128,BiT-128,))

$(eval $(call CRETAKE,CreTAKE-K2K-PLAC256,CreTAKE256,POLARLAC-256,,twokem.c))
$(eval $(call CRETAKE,CreTAKE-K2K-ZEN256,CreTAKE256,ZEN_256,,twokem.c))
$(eval $(call CRETAKE,CreTAKE-K2S-PLAC256-BiT256,CreTAKE256,POLARLAC-256,BiT-256,))
$(eval $(call CRETAKE,CreTAKE-K2S-ZEN256-BiT256,CreTAKE256,ZEN_256,BiT-256,))
$(eval $(call CRETAKE,CreTAKE-S2K-BiT256-PLAC256,CreTAKE256,POLARLAC-256,BiT-256,))
$(eval $(call CRETAKE,CreTAKE-S2K-BiT256-ZEN256,CreTAKE256,ZEN_256,BiT-256,))
$(eval $(call CRETAKE,CreTAKE-S2S-BiT256-ePLAC256,CreTAKE256,POLARLAC-256,BiT-256,))
$(eval $(call CRETAKE,CreTAKE-S2S-BiT256-eZEN256,CreTAKE256,ZEN_256,BiT-256,))

$(eval $(call CRETAKE,CreTAKE-K2K-PLAC512,CreTAKE512,POLARLAC-512,,twokem.c twopke.c))
$(eval $(call CRETAKE,CreTAKE-K2K-PLAC512Star,CreTAKE512,POLARLAC-512-Star,,twokem.c twopke.c))
$(eval $(call CRETAKE,CreTAKE-K2K-ZEN512,CreTAKE512,ZEN_512,,twokem.c))
$(eval $(call CRETAKE,CreTAKE-K2S-PLAC512-BiT512,CreTAKE512,POLARLAC-512,BiT-512,))
$(eval $(call CRETAKE,CreTAKE-K2S-ZEN512-BiT512,CreTAKE512,ZEN_512,BiT-512,))
$(eval $(call CRETAKE,CreTAKE-S2K-BiT512-PLAC512,CreTAKE512,POLARLAC-512,BiT-512,))
$(eval $(call CRETAKE,CreTAKE-S2K-BiT512-ZEN512,CreTAKE512,ZEN_512,BiT-512,))
$(eval $(call CRETAKE,CreTAKE-S2S-BiT512-ePLAC512,CreTAKE512,POLARLAC-512,BiT-512,))
$(eval $(call CRETAKE,CreTAKE-S2S-BiT512-eZEN512,CreTAKE512,ZEN_512,BiT-512,))

include ../api/link_finish.mk
