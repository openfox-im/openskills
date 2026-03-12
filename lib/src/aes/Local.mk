# Avatar src/crypto/aes/Local.mk

$(call add-hdrs,../at_aes_base.h ../at_aes_gcm.h ../at_aes_gcm_ref.h)
$(call add-objs,at_aes_base_ref at_aes_gcm_ref at_aes_gcm_ref_ghash,at_crypto)

# x86 optimized implementations
ifdef AT_HAS_X86
$(call add-objs,at_aes_gcm_x86,at_crypto)
ifdef AT_HAS_AESNI
$(call add-asms,at_aes_base_aesni,at_crypto)
$(call add-asms,at_aes_gcm_aesni,at_crypto)
ifdef AT_HAS_GFNI
$(call add-asms,at_aes_gcm_avx10,at_crypto)
endif
endif
endif