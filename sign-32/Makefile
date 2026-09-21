# NGCC uniform build: sign-32 UVW signature (reference implementation)
NGCC_ID   := sign-32
NGCC_TYPE := sig
NGCC_ALG  := UVW signature
include ../api/link_rules.mk

REF := Implementations/Reference_Implementation
NGCC_KAT_DIR := Test_Vectors

# Source list from Implementations/Reference_Implementation/Makefile
# (SRCS_COMMON minus KAT_SIG.c). -DUSE_API_PKC is essential: it makes
# uvw.c / fq_arithmetic/{vf3,dp}.c draw randomness from drng_algorithm (via
# the uvw_drng pointer set in SIG_AlgorithmInstance.c) and use the ICCS
# auxfunc hash; without it csprng.h reads OS entropy (getrandom) and the
# code expects a keccak/ directory that is not shipped. drng.c/auxfunc.c
# are the instance's own copies (identical to api/).
#
# Known candidate bug (not patched, see report): sig_verify() in
# SIG_AlgorithmInstance.c computes `result` from uvw_verify() but then
# `return 0;` unconditionally, so every signature is accepted and the
# harness reports CRYPTOFAIL (flipped message bit accepted). The generated
# KAT text itself matches Test_Vectors/ (checked with a scratch build that
# returns `result`). uvw.c also prints DBG_SIGN/DBG_VFY lines to stderr.
# UVW-512 reference keygen exceeds the harness' 900 s default (>30 min CPU
# without finishing the first keypair on an idle machine), hence TIMEOUT.
UVW_SRCS := SIG_AlgorithmInstance.c uvw.c gauss.c auxfunc.c drng.c \
            fq_arithmetic/vf3.c fq_arithmetic/mf3.c fq_arithmetic/dp.c

define UVW
SRCS_$(1) := $(UVW_SRCS)
DEFS_$(1) := -DUSE_API_PKC
TESTFLAGS_$(1) := $$(COUNT_$(1))
$$(eval $$(call ngcc_instance,$(1),$(REF)/$(1)))
endef
# UVW-512: one record only, with a 2 h limit (keygen alone is >30 min)
COUNT_UVW-512 := --count 1 --timeout 7200

$(eval $(call UVW,UVW-128))
$(eval $(call UVW,UVW-256))
$(eval $(call UVW,UVW-512))

include ../api/link_finish.mk
