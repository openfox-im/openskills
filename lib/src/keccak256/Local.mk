# Avatar src/crypto/keccak256/Local.mk

$(call add-hdrs,../at_keccak256.h ../at_keccak256_private.h)
$(call add-objs,at_keccak256,at_crypto)
ifdef AT_HAS_AVX
$(call add-objs,at_keccak256_batch_avx2,at_crypto)
endif
ifdef AT_HAS_AVX512
$(call add-objs,at_keccak256_batch_avx512,at_crypto)
endif

# SIMD equivalence tests
$(call make-unit-test,test_keccak256_simd,test_keccak256_simd,at_crypto at_util)
$(call run-unit-test,test_keccak256_simd,)