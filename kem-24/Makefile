# NGCC uniform build: kem-24 MORNING-Scabbard (reference implementation)
NGCC_ID   := kem-24
NGCC_TYPE := kem
NGCC_ALG  := MORNING-Scabbard
include ../api/link_rules.mk

REF := Implementations/Reference_Implementation
# Implementations/Test_Vectors is an identical copy
NGCC_KAT_DIR := Test_Vectors

# Per the candidate Makefile: SOURCES = auxfunc.c cbd.c drng.c indcpa.c
# KEM_scabbard<n>.c packing.c poly.c polyvec.c verify.c minal.c (explicit list
# because scabbard512 also ships auxfunc_detail.c, a cycle-counting variant of
# auxfunc.c that its own build does not use; test/ holds only the speed
# benchmark). The candidate links -lcrypto but no source includes OpenSSL, so it
# is not needed. The API header is KEM_scabbard<n>.h (no KEM_AlgorithmInstance.h).
# Randomness comes from get_random_number(&drng_algorithm, ...) in
# KEM_scabbard<n>.c and indcpa.c. The shipped auxfunc.c differs from
# api/auxfunc.c in one line: pseudoXOF() allocates ceil(bits/256)*32 bytes for
# K instead of (bits+255)/8 (tighter but still sufficient; output unchanged).
define SCAB
SRCS_$(1) := auxfunc.c cbd.c drng.c indcpa.c KEM_$(1).c packing.c poly.c polyvec.c verify.c minal.c
SHIMDEFS_$(1) := -DNGCC_INSTANCE_HEADER='"KEM_$(1).h"'
$$(eval $$(call ngcc_instance,$(1),$(REF)/$(1)))
endef

$(eval $(call SCAB,scabbard128))
$(eval $(call SCAB,scabbard256))
$(eval $(call SCAB,scabbard512))

include ../api/link_finish.mk
