# NGCC uniform build: hash-18 Megascon (reference implementation)
NGCC_ID   := hash-18
NGCC_TYPE := hash
NGCC_ALG  := Megascon
include ../api/link_rules.mk

REF := Megascon/Implementations/Reference_Implementation
NGCC_KAT_DIR := Megascon/Test_Vectors/Test_Vector

# Fixed-length instances: CryptHash_AlgorithmInstance.c + drng.c (default glob).
$(eval $(call ngcc_instance,MEGASCON-384,$(REF)/MEGASCON-384))
$(eval $(call ngcc_instance,MEGASCON-512,$(REF)/MEGASCON-512))
$(eval $(call ngcc_instance,MEGASCON-768,$(REF)/MEGASCON-768))
$(eval $(call ngcc_instance,MEGASCON-1024,$(REF)/MEGASCON-1024))

# XOF instances: one source dir per capacity, but KAT files are submitted for
# output lengths 256, 1024 and 2048 bits (the header only names the 2048 one).
# CryptHash() takes the output length from digest_len_bits, so we build one
# library per output length and override the instance name / digest size in
# the shim only.
# label, dir, bits
define MXOF
SHIMDEFS_$(1) := -DNGCC_INSTANCE='"$(1)"' -DNGCC_DIGEST_BITS=$(3)
$$(eval $$(call ngcc_instance,$(1),$(REF)/$(2)))
endef

$(eval $(call MXOF,MEGASCON-384-XOF-256,MEGASCON-384-XOF,256))
$(eval $(call MXOF,MEGASCON-384-XOF-1024,MEGASCON-384-XOF,1024))
$(eval $(call MXOF,MEGASCON-384-XOF-2048,MEGASCON-384-XOF,2048))
$(eval $(call MXOF,MEGASCON-512-XOF-256,MEGASCON-512-XOF,256))
$(eval $(call MXOF,MEGASCON-512-XOF-1024,MEGASCON-512-XOF,1024))
$(eval $(call MXOF,MEGASCON-512-XOF-2048,MEGASCON-512-XOF,2048))

include ../api/link_finish.mk
