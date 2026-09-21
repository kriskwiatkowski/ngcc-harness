# NGCC uniform build: kem-29 Polar-KEM (reference implementation)
NGCC_ID   := kem-29
NGCC_TYPE := kem
NGCC_ALG  := Polar-KEM
include ../api/link_rules.mk

# Non-standard layout: everything lives under Submission_Package/.
REF := Submission_Package/Implementations/Reference_Implementation
NGCC_KAT_DIR := Submission_Package/Test_Vectors

# Per the candidate Makefile: KEM_AlgorithmInstance.c polarkem_core.c
# polarkem_polar.c polarkem_pack.c polarkem_ct.c auxfunc.c drng.c (drng/auxfunc
# identical to api/). The default glob picks exactly these; KAT_KEM.c is the
# driver. KEM_AlgorithmInstance.c passes &drng_algorithm into the core.
# Optimized_Implementation is not built.
$(eval $(call ngcc_instance,PolarKEM-128,$(REF)/PolarKEM-128))
$(eval $(call ngcc_instance,PolarKEM-256,$(REF)/PolarKEM-256))
$(eval $(call ngcc_instance,PolarKEM-512,$(REF)/PolarKEM-512))

include ../api/link_finish.mk
