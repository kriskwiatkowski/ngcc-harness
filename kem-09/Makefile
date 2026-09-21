# NGCC uniform build: kem-09 CheetahKEM (reference implementation)
NGCC_ID   := kem-09
NGCC_TYPE := kem
NGCC_ALG  := CheetahKEM
include ../api/link_rules.mk

REF := Implementations/Reference_Implementation
NGCC_KAT_DIR := Test_Vectors

# Per the candidate makefile: SOURCES = auxfunc.c drng.c mod.c ntt.c poly.c
# KEM_Cheetah.c (the default glob minus KAT_KEM.c gives exactly that).
# drng.c/auxfunc.c are byte-identical to api/. All randomness in
# KEM_Cheetah.c comes from drng_algorithm (defined in the excluded KAT driver;
# the shim provides it). The API header is KEM_Cheetah.h. The candidate builds
# with -O3 -march=native -flto; the plain -O2 build is used here.
define CHEETAH
SHIMDEFS_$(1) := -DNGCC_INSTANCE_HEADER='"KEM_Cheetah.h"'
$$(eval $$(call ngcc_instance,$(1),$(REF)/$(1)))
endef

$(eval $(call CHEETAH,Cheetah128))
$(eval $(call CHEETAH,Cheetah256))
$(eval $(call CHEETAH,Cheetah384))
$(eval $(call CHEETAH,Cheetah512))

include ../api/link_finish.mk
