# Avatar src/crypto/secp256k1/Local.mk
# secp256k1 ECDSA recovery via vendored libsecp256k1

$(call add-hdrs,../at_secp256k1.h)
$(call add-objs,at_secp256k1,at_crypto)
