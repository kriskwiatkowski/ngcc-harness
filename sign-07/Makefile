# NGCC uniform build: sign-07 CS (reference implementation)
NGCC_ID   := sign-07
NGCC_TYPE := sig
NGCC_ALG  := CS
include ../api/link_rules.mk

REF := Implementations/Reference_Implementation
NGCC_KAT_DIR := Test_Vectors

# No candidate Makefile: README says `gcc *.c -o main -O2`, i.e. every .c in
# the directory (= default glob minus KAT_SIG.c). The three directories differ
# only in `#define lambda` in params.h, which also sets ALGORITHM_NAME
# ("CS_128" etc.) used as ALGORITHM_INSTANCE, matching KAT_SIG_CS_<n>.txt.
# Randomness is drawn from drng_algorithm in cs.c; drng.c/auxfunc.c are the
# unmodified official copies.
#
# The candidate's SIG_AlgorithmInstance.h includes cs.h -> params.h, which
# #defines single-letter macros (n, k, q, ...) that break the shim's own
# `size_t n` parameter. The shim therefore includes the official ICCS API
# template header instead (identical prototypes, no params.h) and gets the
# instance name via -DNGCC_INSTANCE.
#
# ntt.c does #include "NTT.h", which is not in the submission (only ntt.h
# is, and it declares MultiplyNTT non-static while ntt.c defines it static,
# so ntt.c cannot compile against ntt.h on any platform). patches/common/NTT.h
# is a stand-in that includes ntt.h with that one prototype renamed; no
# submission file is modified. Likely the submitters' real NTT.h was lost
# (case-insensitive filesystem, .DS_Store present).
#
# symmetric.h holds a tentative definition `DRNG_ctx drng_algorithm;` and is
# included by cs.c, sampling.c and SIG_AlgorithmInstance.c (KAT_SIG.c defines
# it once more), so the candidate defines the DRNG context itself and relies
# on common-symbol merging: -fcommon (GCC >= 10 defaults to -fno-common) and
# -DNGCC_NO_DRNG so the shim only references it.
ICCS_SIG_H := API_PKC/Implementations/Reference_Implementation/AlgorithmInstance/SIG_AlgorithmInstance.h

# label, instance name
define CS
SHIMDEFS_$(1) := -DNGCC_INSTANCE_HEADER='"$(ICCS_SIG_H)"' -DNGCC_INSTANCE='"$(2)"' -DNGCC_NO_DRNG
INC_$(1) := -Ipatches/common
# sampling.c contains enormous generated initializer lines whose out-of-range
# literal warnings can expand to gigabytes of diagnostics on newer GCC. The
# literals intentionally wrap to uint64_t; suppress candidate-source warnings.
CFLAGS_$(1) := -fcommon -w
$$(eval $$(call ngcc_instance,$(1),$(REF)/$(1)))
endef

$(eval $(call CS,CS-128,CS_128))
$(eval $(call CS,CS-256,CS_256))
$(eval $(call CS,CS-512,CS_512))

include ../api/link_finish.mk
