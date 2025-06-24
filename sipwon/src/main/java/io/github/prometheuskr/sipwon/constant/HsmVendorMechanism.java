package io.github.prometheuskr.sipwon.constant;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.parameters.Parameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

public enum HsmVendorMechanism {
    DES_ECB(PKCS11Constants.CKM_DES_ECB),
    DES_CBC(PKCS11Constants.CKM_DES_CBC),
    DES_MAC(PKCS11Constants.CKM_DES_MAC),
    DES_MAC_GENERAL(PKCS11Constants.CKM_DES_MAC_GENERAL),

    DES3_ECB(PKCS11Constants.CKM_DES3_ECB),
    DES3_CBC(PKCS11Constants.CKM_DES3_CBC),
    DES3_MAC(PKCS11Constants.CKM_DES3_MAC),
    DES3_MAC_GENERAL(PKCS11Constants.CKM_DES3_MAC_GENERAL),
    DES3_X919_MAC_PTK(PKCS11Constants.CKM_VENDOR_DEFINED + PKCS11Constants.CKM_DES3_MAC),
    DES3_X919_MAC_GENERAL_PTK(PKCS11Constants.CKM_VENDOR_DEFINED + PKCS11Constants.CKM_DES3_MAC_GENERAL),

    AES_ECB(PKCS11Constants.CKM_AES_ECB),
    AES_CBC(PKCS11Constants.CKM_AES_CBC),
    AES_MAC(PKCS11Constants.CKM_AES_MAC),
    AES_MAC_GENERAL(PKCS11Constants.CKM_AES_MAC_GENERAL),

    SEED_ECB(PKCS11Constants.CKM_SEED_ECB),
    SEED_CBC(PKCS11Constants.CKM_SEED_CBC),
    SEED_MAC(PKCS11Constants.CKM_SEED_MAC),
    SEED_MAC_GENERAL(PKCS11Constants.CKM_SEED_MAC_GENERAL),

    SEED_ECB_PTK(PKCS11Constants.CKM_VENDOR_DEFINED + 0x9D1l),
    SEED_CBC_PTK(PKCS11Constants.CKM_VENDOR_DEFINED + 0x9D2l),
    SEED_MAC_PTK(PKCS11Constants.CKM_VENDOR_DEFINED + 0x9D3l),
    SEED_MAC_GENERAL_PTK(PKCS11Constants.CKM_VENDOR_DEFINED + 0x9D4l),

    // for Derived Key
    DES_ECB_ENCRYPT_DATA(PKCS11Constants.CKM_DES_ECB_ENCRYPT_DATA),
    DES_CBC_ENCRYPT_DATA(PKCS11Constants.CKM_DES_CBC_ENCRYPT_DATA),
    DES3_ECB_ENCRYPT_DATA(PKCS11Constants.CKM_DES3_ECB_ENCRYPT_DATA),
    DES3_CBC_ENCRYPT_DATA(PKCS11Constants.CKM_DES3_CBC_ENCRYPT_DATA),
    AES_ECB_ENCRYPT_DATA(PKCS11Constants.CKM_AES_ECB_ENCRYPT_DATA),
    AES_CBC_ENCRYPT_DATA(PKCS11Constants.CKM_AES_CBC_ENCRYPT_DATA),

    ;

    private final Long mech;

    private HsmVendorMechanism(Long mechanism) {
        this.mech = mechanism;
    }

    public Mechanism getMechanism() {
        return getMechanism(null);
    }

    public Mechanism getMechanism(Parameters parameters) {
        Mechanism mechanism = Mechanism.get(mech);
        mechanism.setParameters(parameters);
        return mechanism;
    }
}
