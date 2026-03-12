# Avatar src/crypto/bech32/Local.mk
# Bech32 encoding/decoding for TOS addresses

$(call add-hdrs,../at_bech32.h)
$(call add-objs,at_bech32,at_crypto)

# Tests
# $(call make-unit-test,test_bech32,test_bech32,at_crypto at_util)