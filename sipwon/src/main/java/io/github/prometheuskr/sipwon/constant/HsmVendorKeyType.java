package io.github.prometheuskr.sipwon.constant;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * Enum representing various HSM (Hardware Security Module) vendor key types.
 * Each enum constant is associated with a specific key type value defined by PKCS#11 constants.
 * <p>
 * Supported key types include:
 * <ul>
 * <li>DES</li>
 * <li>DDES (Double DES)</li>
 * <li>TDES (Triple DES)</li>
 * <li>AES</li>
 * <li>SEED</li>
 * <li>SEED_PTK (Vendor-defined SEED key type)</li>
 * </ul>
 * <p>
 * Provides a method to retrieve the enum constant from its corresponding long value.
 */
public enum HsmVendorKeyType {
    /**
     * Data Encryption Standard key
     */
    DES(PKCS11Constants.CKK_DES),
    /**
     * Double-length DES key
     */
    DDES(PKCS11Constants.CKK_DES2),
    /**
     * Triple DES (3DES) key
     */
    TDES(PKCS11Constants.CKK_DES3),
    /**
     * Advanced Encryption Standard key
     */
    AES(PKCS11Constants.CKK_AES),

    /**
     * SEED block cipher key (commonly used in South Korea)
     */
    SEED(PKCS11Constants.CKK_SEED),
    /**
     * Vendor-defined SEED key type for PTK HSMs.
     */
    SEED_PTK(PKCS11Constants.CKK_VENDOR_DEFINED + 0x203l),

    ;

    /**
     * Represents the type of key associated with the HSM vendor.
     * This value is typically used to distinguish between different key types
     * supported by the HSM (Hardware Security Module).
     */
    private final Long keyType;

    /**
     * Constructs a new HsmVendorKeyType with the specified key type.
     *
     * @param keyType
     *            the unique identifier for the HSM vendor key type
     */
    private HsmVendorKeyType(Long keyType) {
        this.keyType = keyType;
    }

    /**
     * Returns the key type associated with this instance.
     *
     * @return the key type as a {@link Long}
     */
    public Long getKeyType() {
        return keyType;
    }

    /**
     * Returns the {@code HsmVendorKeyType} corresponding to the specified {@code Long} value.
     * <p>
     * Iterates through all available {@code HsmVendorKeyType} enum constants and returns the one whose
     * key type matches the provided value.
     * 
     * @param value
     *            the {@code Long} value representing the key type to look up
     * @return the matching {@code HsmVendorKeyType} enum constant
     * @throws IllegalArgumentException
     *             if no matching key type is found for the given value
     */
    public static HsmVendorKeyType fromLongValue(Long value) {
        for (HsmVendorKeyType type : HsmVendorKeyType.values()) {
            if (type.getKeyType().equals(value)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unsupported key type: " + value);
    }
}
