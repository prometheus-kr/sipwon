package io.github.prometheuskr.sipwon.constant;

/**
 * Enumeration of supported HSM (Hardware Security Module) cryptographic mechanisms.
 * <p>
 * Each constant represents a cryptographic operation mode (such as ECB, CBC, MAC, etc.)
 * for various algorithms (DES, 3DES, AES, SEED), and is mapped to a vendor-specific
 * mechanism via {@link HsmVendorMechanism}. Some mechanisms require vendor-specific
 * mapping and are initialized with {@code null}, to be resolved dynamically at runtime.
 * <p>
 * The enum provides a method to retrieve the actual vendor-specific mechanism for a given
 * {@link HsmVendor}, throwing an exception if the mechanism is unsupported for the vendor.
 * <ul>
 * <li>DES/3DES/AES/SEED: ECB, CBC, MAC, MAC_GENERAL modes</li>
 * <li>3DES X9.19 MAC and SEED modes require vendor-specific mapping</li>
 * <li>Derived key encryption mechanisms for DES, 3DES, and AES</li>
 * </ul>
 *
 * @see HsmVendorMechanism
 * @see HsmVendor
 */
public enum HsmMechanism {
    /** DES ECB */
    DES_ECB(HsmVendorMechanism.DES_ECB),
    /** DES CBC */
    DES_CBC(HsmVendorMechanism.DES_CBC),
    /** DES MAC */
    DES_MAC(HsmVendorMechanism.DES_MAC),
    /** DES MAC_GENERAL */
    DES_MAC_GENERAL(HsmVendorMechanism.DES_MAC_GENERAL),

    /** 3DES ECB */
    DES3_ECB(HsmVendorMechanism.DES3_ECB),
    /** 3DES CBC */
    DES3_CBC(HsmVendorMechanism.DES3_CBC),
    /** 3DES MAC */
    DES3_MAC(HsmVendorMechanism.DES3_MAC),
    /** 3DES MAC_GENERAL */
    DES3_MAC_GENERAL(HsmVendorMechanism.DES3_MAC_GENERAL),
    /** 3DES X9.19 MAC (Requires vendor-specific mapping) */
    DES3_X919_MAC(null),
    /** 3DES X9.19 MAC_GENERAL (Requires vendor-specific mapping) */
    DES3_X919_MAC_GENERAL(null),

    /** AES ECB */
    AES_ECB(HsmVendorMechanism.AES_ECB),
    /** AES CBC */
    AES_CBC(HsmVendorMechanism.AES_CBC),
    /** AES MAC */
    AES_MAC(HsmVendorMechanism.AES_MAC),
    /** AES MAC_GENERAL */
    AES_MAC_GENERAL(HsmVendorMechanism.AES_MAC_GENERAL),

    /** SEED ECB (Requires vendor-specific mapping) */
    SEED_ECB(null),
    /** SEED CBC (Requires vendor-specific mapping) */
    SEED_CBC(null),
    /** SEED MAC (Requires vendor-specific mapping) */
    SEED_MAC(null),
    /** SEED MAC_GENERAL (Requires vendor-specific mapping) */
    SEED_MAC_GENERAL(null),

    /** DES ECB for Derived Key */
    DES_ECB_ENCRYPT_DATA(HsmVendorMechanism.DES_ECB_ENCRYPT_DATA),
    /** DES CBC for Derived Key */
    DES_CBC_ENCRYPT_DATA(HsmVendorMechanism.DES_CBC_ENCRYPT_DATA),
    /** 3DES ECB for Derived Key */
    DES3_ECB_ENCRYPT_DATA(HsmVendorMechanism.DES3_ECB_ENCRYPT_DATA),
    /** 3DES CBC for Derived Key */
    DES3_CBC_ENCRYPT_DATA(HsmVendorMechanism.DES3_CBC_ENCRYPT_DATA),
    /** AES ECB for Derived Key */
    AES_ECB_ENCRYPT_DATA(HsmVendorMechanism.AES_ECB_ENCRYPT_DATA),
    /** AES CBC for Derived Key */
    AES_CBC_ENCRYPT_DATA(HsmVendorMechanism.AES_CBC_ENCRYPT_DATA),
    ;

    /**
     * The primary mechanism associated with the HSM vendor.
     * This field holds the specific {@link HsmVendorMechanism} instance used as the default or initial mechanism.
     */
    private final HsmVendorMechanism mechanism0;

    /**
     * Constructs an instance of {@code HsmMechanism} with the specified {@link HsmVendorMechanism}.
     *
     * @param mechanism0
     *            the vendor-specific mechanism to associate with this HSM mechanism
     */
    HsmMechanism(HsmVendorMechanism mechanism0) {
        this.mechanism0 = mechanism0;
    }

    /**
     * Returns the corresponding {@link HsmVendorMechanism} for the specified {@link HsmVendor}.
     * <p>
     * If a vendor-specific mechanism is defined for the current instance and the given vendor,
     * it is returned. Otherwise, the default mechanism is returned. For unsupported mechanisms
     * and vendors, an {@link IllegalArgumentException} may be thrown.
     *
     * @param hsmVendor
     *            the HSM vendor for which to retrieve the mechanism
     * @return the vendor-specific {@link HsmVendorMechanism}, or the default mechanism if not specified
     * @throws IllegalArgumentException
     *             if the mechanism is not supported for the given vendor
     */
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
