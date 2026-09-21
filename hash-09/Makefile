# NGCC uniform build: hash-09 Eijen (reference implementation)
NGCC_ID   := hash-09
NGCC_TYPE := hash
NGCC_ALG  := Eijen
include ../api/link_rules.mk

REF := Eijen/Implementations/Reference_Implementation
NGCC_KAT_DIR := Eijen/Test_Vectors

# Per CMakeLists.txt: CryptHash_AlgorithmInstance.c eijen_ref.c drng.c
# (default glob).
$(eval $(call ngcc_instance,Eijen-256,$(REF)/Eijen-256))
$(eval $(call ngcc_instance,Eijen-384,$(REF)/Eijen-384))
$(eval $(call ngcc_instance,Eijen-512,$(REF)/Eijen-512))
$(eval $(call ngcc_instance,Eijen-768,$(REF)/Eijen-768))
$(eval $(call ngcc_instance,Eijen-1024,$(REF)/Eijen-1024))

include ../api/link_finish.mk
