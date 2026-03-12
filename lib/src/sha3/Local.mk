$(call add-hdrs,../at_sha3.h ../at_sha3_private.h ../at_sha3_keccak_avx2.h)
$(call add-objs,at_sha3,at_crypto)
ifdef AT_HAS_AVX
$(call add-objs,at_sha3_batch_avx2,at_crypto)
endif
ifdef AT_HAS_AVX512
$(call add-objs,at_sha3_batch_avx512,at_crypto)
endif

# SIMD equivalence tests
$(call make-unit-test,test_sha3_simd,test_sha3_simd,at_crypto at_util)
$(call run-unit-test,test_sha3_simd,)