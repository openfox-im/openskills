# Avatar src/crypto/secp256r1/Local.mk
# secp256r1 (P-256) ECDSA via vendored s2n-bignum assembly

$(call add-hdrs,../at_secp256r1.h ../at_secp256r1_private.h)
$(call add-objs,at_secp256r1,at_crypto)
