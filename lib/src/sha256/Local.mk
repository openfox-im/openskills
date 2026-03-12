# Avatar src/crypto/sha256/Local.mk

$(call add-hdrs,../at_sha256.h ../at_sha256_constants.h)
$(call add-objs,at_sha256,at_crypto)

ifdef AT_HAS_AVX
$(call add-objs,at_sha256_batch_avx,at_crypto)
endif
ifdef AT_HAS_AVX512
$(call add-objs,at_sha256_batch_avx512,at_crypto)
endif

# Tests are in src/test/
# $(call make-unit-test,test_sha256,test_sha256,at_crypto at_util)