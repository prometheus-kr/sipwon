package io.github.prometheuskr.sipwon.constant;

public enum HsmMechanism {
    DES_ECB(HsmVendorMechanism.DES_ECB),
    DES_CBC(HsmVendorMechanism.DES_CBC),
    DES_MAC(HsmVendorMechanism.DES_MAC),
    DES_MAC_GENERAL(HsmVendorMechanism.DES_MAC_GENERAL),

    DES3_ECB(HsmVendorMechanism.DES3_ECB),
    DES3_CBC(HsmVendorMechanism.DES3_CBC),
    DES3_MAC(HsmVendorMechanism.DES3_MAC),
    DES3_MAC_GENERAL(HsmVendorMechanism.DES3_MAC_GENERAL),
    DES3_X919_MAC(null),
    DES3_X919_MAC_GENERAL(null),

    AES_ECB(HsmVendorMechanism.AES_ECB),
    AES_CBC(HsmVendorMechanism.AES_CBC),
    AES_MAC(HsmVendorMechanism.AES_MAC),
    AES_MAC_GENERAL(HsmVendorMechanism.AES_MAC_GENERAL),

    SEED_ECB(null),
    SEED_CBC(null),
    SEED_MAC(null),
    SEED_MAC_GENERAL(null),

    // for Derived Key
    DES_ECB_ENCRYPT_DATA(HsmVendorMechanism.DES_ECB_ENCRYPT_DATA),
    DES_CBC_ENCRYPT_DATA(HsmVendorMechanism.DES_CBC_ENCRYPT_DATA),
    DES3_ECB_ENCRYPT_DATA(HsmVendorMechanism.DES3_ECB_ENCRYPT_DATA),
    DES3_CBC_ENCRYPT_DATA(HsmVendorMechanism.DES3_CBC_ENCRYPT_DATA),
    AES_ECB_ENCRYPT_DATA(HsmVendorMechanism.AES_ECB_ENCRYPT_DATA),
    AES_CBC_ENCRYPT_DATA(HsmVendorMechanism.AES_CBC_ENCRYPT_DATA),

    ;

    private HsmVendorMechanism mechanism0;

    HsmMechanism(HsmVendorMechanism mechanism0) {
        this.mechanism0 = mechanism0;
    }

    public HsmVendorMechanism getMechanism0(HsmVendor hsmVendor) {
        if (mechanism0 != null) {
            return mechanism0;
        }

        switch (hsmVendor) {
            case PTK: {
                switch (this) {
                    case DES3_X919_MAC:
                        return HsmVendorMechanism.DES3_X919_MAC_PTK;
                    case DES3_X919_MAC_GENERAL:
                        return HsmVendorMechanism.DES3_X919_MAC_GENERAL_PTK;
                    case SEED_ECB:
                        return HsmVendorMechanism.SEED_ECB_PTK;
                    case SEED_CBC:
                        return HsmVendorMechanism.SEED_CBC_PTK;
                    case SEED_MAC:
                        return HsmVendorMechanism.SEED_MAC_PTK;
                    case SEED_MAC_GENERAL:
                        return HsmVendorMechanism.SEED_MAC_GENERAL_PTK;
                    default:
                        return mechanism0;
                }
            }
            case NFAST:
                switch (this) {
                    default:
                        throw new IllegalArgumentException("Unsupported mechanism for NFAST: " + this);
                }
        }

        return mechanism0;
    }
}
