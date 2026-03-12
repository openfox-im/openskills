# Avatar src/crypto/blake3/Local.mk

$(call add-hdrs,../at_blake3.h ../at_blake3_private.h)
$(call add-objs,at_blake3 at_blake3_ref,at_crypto)

ifdef AT_HAS_SSE
$(call add-objs,at_blake3_sse41,at_crypto)
endif
ifdef AT_HAS_AVX
$(call add-objs,at_blake3_avx2,at_crypto)
endif
ifdef AT_HAS_AVX512
$(call add-objs,at_blake3_avx512,at_crypto)
endif

# SIMD equivalence tests
$(call make-unit-test,test_blake3_simd,test_blake3_simd,at_crypto at_util)
$(call run-unit-test,test_blake3_simd,)