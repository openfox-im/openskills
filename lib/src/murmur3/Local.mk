# Murmur3 module build configuration

$(call add-hdrs,include/at/crypto/murmur3/at_murmur3.h)

$(call make-lib,at_murmur3)
$(call add-objs,at_murmur3,at_murmur3)