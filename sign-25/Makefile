# NGCC uniform build: sign-25 SQIsign2D2 (reference implementation)
NGCC_ID   := sign-25
NGCC_TYPE := sig
NGCC_ALG  := SQIsign2D2
include ../api/link_rules.mk

REF := Implementations/Reference_Implementation
NGCC_KAT_DIR := Test_Vectors

# Source list from <instance>/sqisign/Makefile: CORE_SRCS (top-level .c) +
# ec_arithmetic/*.c + sqisign/{keygen,sign,SIG_AlgorithmInstance}.c, with
# -I sqisign -I . -I ec_arithmetic/include, -O2 -DNDEBUG, -lgmp (system GMP
# from /usr/include/x86_64-linux-gnu/gmp.h; the shipped gmp/ folder holds a
# Windows import library and is not used). Randomness comes from
# drng_algorithm (intbig.c, lattice.c). Shipped drng.c/auxfunc.c are the
# official ones. config.h selects the signature encoding via
# `#ifndef COMPRESSED / #define COMPRESSED 0`; each directory therefore yields
# two instances, and the KAT files are named <instance>_{un,}compressed.
SQI_CORE := algebra.c auxfunc.c basis.c biextension.c dim2.c dim2id2iso.c dim4.c drng.c ec.c \
            finit.c fp.c fp2.c hd.c id2iso.c ideal.c intbig.c integers.c isog_chains.c klptx.c \
            lattice.c lll.c matkermod.c mp.c pack.c printer.c theta_isogenies.c theta_structure.c \
            tools.c xeval.c xisog.c \
            ec_arithmetic/endomorphism_action.c ec_arithmetic/gf_constants.c \
            ec_arithmetic/quaternion_data.c ec_arithmetic/torsion_constants.c \
            sqisign/keygen.c sqisign/sign.c sqisign/SIG_AlgorithmInstance.c

# dir, prime file, mode (compressed|uncompressed), COMPRESSED value
define SQI
SRCS_$(1)_$(3) := $(SQI_CORE) ec_arithmetic/fp_$(2).c
INC_$(1)_$(3)  := -Isrc/$(1)_$(3)/sqisign -Isrc/$(1)_$(3)/ec_arithmetic/include
DEFS_$(1)_$(3) := -DNDEBUG -DCOMPRESSED=$(4)
LDLIBS_$(1)_$(3) := -lgmp
# ALGORITHM_INSTANCE is the same for both encodings, so the instance name is
# overridden with the label (= KAT file name part) to keep results unambiguous.
SHIMDEFS_$(1)_$(3) := -DNGCC_INSTANCE_HEADER='"sqisign/SIG_AlgorithmInstance.h"' -DNGCC_INSTANCE='"$(1)_$(3)"'
$$(eval $$(call ngcc_instance,$(1)_$(3),$(REF)/$(1)))
endef

# dir, prime file
define SQI2
$(call SQI,$(1),$(2),uncompressed,0)
$(call SQI,$(1),$(2),compressed,1)
endef

$(eval $(call SQI2,SQISign2Dsquare-Level1-eff,p255))
$(eval $(call SQI2,SQISign2Dsquare-Level1-sec,p271))
$(eval $(call SQI2,SQISign2Dsquare-Level2-eff,p320))
$(eval $(call SQI2,SQISign2Dsquare-Level2-sec,p332))
$(eval $(call SQI2,SQISign2Dsquare-Level3-eff,p511))
$(eval $(call SQI2,SQISign2Dsquare-Level3-sec,p523))
$(eval $(call SQI2,SQISign2Dsquare-Level5-eff,p1024))
$(eval $(call SQI2,SQISign2Dsquare-Level5-sec,p1070))

include ../api/link_finish.mk
