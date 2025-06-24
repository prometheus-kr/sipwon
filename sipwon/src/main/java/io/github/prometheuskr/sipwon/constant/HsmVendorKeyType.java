package io.github.prometheuskr.sipwon.constant;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

public enum HsmVendorKeyType {
    DES(PKCS11Constants.CKK_DES),
    DDES(PKCS11Constants.CKK_DES2),
    TDES(PKCS11Constants.CKK_DES3),
    AES(PKCS11Constants.CKK_AES),

    SEED(PKCS11Constants.CKK_SEED),
    SEED_PTK(PKCS11Constants.CKK_VENDOR_DEFINED + 0x203l),
    
    ;

    private final Long keyType;

    private HsmVendorKeyType(Long keyType) {
        this.keyType = keyType;
    }

    public Long getKeyType() {
        return keyType;
    }

    public static HsmVendorKeyType fromLongValue(Long value) {
        for (HsmVendorKeyType type : HsmVendorKeyType.values()) {
            if (type.getKeyType().equals(value)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unsupported key type: " + value);
    }
}
