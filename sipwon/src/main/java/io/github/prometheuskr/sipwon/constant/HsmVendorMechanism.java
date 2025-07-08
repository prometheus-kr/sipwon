package io.github.prometheuskr.sipwon.constant;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.parameters.Parameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * Enum representing various HSM (Hardware Security Module) vendor-specific and standard cryptographic mechanisms.
 * <p>
 * Each enum constant is associated with a specific PKCS#11 mechanism identifier, which may be standard or
 * vendor-defined.
 * These mechanisms cover a range of cryptographic operations, including DES, 3DES, AES, and SEED algorithms in various
 * modes
 * (ECB, CBC, MAC, MAC_GENERAL), as well as mechanisms for derived key operations.
 * <ul>
 * <li>DES, 3DES, AES, SEED: Standard block cipher algorithms in ECB, CBC, and MAC modes.</li>
 * <li>_PTK suffix: Vendor-defined mechanisms for specific use cases (e.g., PTK - PIN Translation Key).</li>
 * <li>_ENCRYPT_DATA suffix: Mechanisms for data encryption using derived keys.</li>
 * </ul>
 * <p>
 * Each enum constant provides a method to obtain a {@link Mechanism} instance, optionally with parameters.
 * 
 * @see PKCS11Constants
 * @see Mechanism
 */
public enum HsmVendorMechanism {
    /**
     * Represents the DES ECB (Electronic Codebook) mode mechanism.
     */
    DES_ECB(PKCS11Constants.CKM_DES_ECB),
    /**
     * Represents the DES CBC (Cipher Block Chaining) mode mechanism.
     */
    DES_CBC(PKCS11Constants.CKM_DES_CBC),
    /**
     * Represents the DES MAC (Message Authentication Code) mechanism.
     */
    DES_MAC(PKCS11Constants.CKM_DES_MAC),
    /**
     * Represents the DES MAC_GENERAL mechanism, which is a more general form of DES MAC.
     */
    DES_MAC_GENERAL(PKCS11Constants.CKM_DES_MAC_GENERAL),

    /**
     * Represents the Triple DES (3DES) ECB mode mechanism.
     */
    DES3_ECB(PKCS11Constants.CKM_DES3_ECB),
    /**
     * Represents the Triple DES (3DES) CBC mode mechanism.
     */
    DES3_CBC(PKCS11Constants.CKM_DES3_CBC),
    /**
     * Represents the Triple DES (3DES) MAC mechanism.
     */
    DES3_MAC(PKCS11Constants.CKM_DES3_MAC),
    /**
     * Represents the Triple DES (3DES) MAC_GENERAL mechanism, which is a more general form of 3DES MAC.
     */
    DES3_MAC_GENERAL(PKCS11Constants.CKM_DES3_MAC_GENERAL),
    /**
     * Represents the Triple DES (3DES) X9.19 MAC mechanism, which is a specific MAC algorithm defined by the X9.19
     * standard.
     */
    DES3_X919_MAC_PTK(PKCS11Constants.CKM_VENDOR_DEFINED + PKCS11Constants.CKM_DES3_MAC),
    /**
     * Represents the Triple DES (3DES) X9.19 MAC_GENERAL mechanism, which is a more general form of the X9.19 MAC.
     */
    DES3_X919_MAC_GENERAL_PTK(PKCS11Constants.CKM_VENDOR_DEFINED + PKCS11Constants.CKM_DES3_MAC_GENERAL),

    /**
     * Represents the AES (Advanced Encryption Standard) ECB (Electronic Codebook) mode mechanism.
     */
    AES_ECB(PKCS11Constants.CKM_AES_ECB),
    /**
     * Represents the AES CBC (Cipher Block Chaining) mode mechanism.
     */
    AES_CBC(PKCS11Constants.CKM_AES_CBC),
    /**
     * Represents the AES MAC (Message Authentication Code) mechanism.
     */
    AES_MAC(PKCS11Constants.CKM_AES_MAC),
    /**
     * Represents the AES MAC_GENERAL mechanism, which is a more general form of AES MAC.
     */
    AES_MAC_GENERAL(PKCS11Constants.CKM_AES_MAC_GENERAL),

    /**
     * Represents the SEED (a block cipher algorithm) ECB (Electronic Codebook) mode mechanism.
     */
    SEED_ECB(PKCS11Constants.CKM_SEED_ECB),
    /**
     * Represents the SEED CBC (Cipher Block Chaining) mode mechanism.
     */
    SEED_CBC(PKCS11Constants.CKM_SEED_CBC),
    /**
     * Represents the SEED MAC (Message Authentication Code) mechanism.
     */
    SEED_MAC(PKCS11Constants.CKM_SEED_MAC),
    /**
     * Represents the SEED MAC_GENERAL mechanism, which is a more general form of SEED MAC.
     */
    SEED_MAC_GENERAL(PKCS11Constants.CKM_SEED_MAC_GENERAL),

    /**
     * Represents the SEED PTK (PIN Translation Key) mechanism for vendor-specific operations.
     */
    SEED_ECB_PTK(PKCS11Constants.CKM_VENDOR_DEFINED + 0x9D1l),
    /**
     * Represents the SEED CBC PTK (PIN Translation Key) mechanism for vendor-specific operations.
     */
    SEED_CBC_PTK(PKCS11Constants.CKM_VENDOR_DEFINED + 0x9D2l),
    /**
     * Represents the SEED MAC PTK (PIN Translation Key) mechanism for vendor-specific operations.
     */
    SEED_MAC_PTK(PKCS11Constants.CKM_VENDOR_DEFINED + 0x9D3l),
    /**
     * Represents the SEED MAC_GENERAL PTK (PIN Translation Key) mechanism for vendor-specific operations.
     */
    SEED_MAC_GENERAL_PTK(PKCS11Constants.CKM_VENDOR_DEFINED + 0x9D4l),

    /**
     * Represents the DES ECB mechanism for derived key operations.
     */
    DES_ECB_ENCRYPT_DATA(PKCS11Constants.CKM_DES_ECB_ENCRYPT_DATA),
    /**
     * Represents the DES CBC mechanism for derived key operations.
     */
    DES_CBC_ENCRYPT_DATA(PKCS11Constants.CKM_DES_CBC_ENCRYPT_DATA),
    /**
     * Represents the Triple DES (3DES) ECB mechanism for derived key operations.
     */
    DES3_ECB_ENCRYPT_DATA(PKCS11Constants.CKM_DES3_ECB_ENCRYPT_DATA),
    /**
     * Represents the Triple DES (3DES) CBC mechanism for derived key operations.
     */
    DES3_CBC_ENCRYPT_DATA(PKCS11Constants.CKM_DES3_CBC_ENCRYPT_DATA),
    /**
     * Represents the AES ECB mechanism for derived key operations.
     */
    AES_ECB_ENCRYPT_DATA(PKCS11Constants.CKM_AES_ECB_ENCRYPT_DATA),
    /**
     * Represents the AES CBC mechanism for derived key operations.
     */
    AES_CBC_ENCRYPT_DATA(PKCS11Constants.CKM_AES_CBC_ENCRYPT_DATA),

    ;

    /**
     * Represents the mechanism identifier associated with the HSM vendor.
     * This value is typically used to specify the cryptographic mechanism
     * supported or required by the HSM (Hardware Security Module).
     */
    private final Long mech;

    /**
     * Constructs an instance of {@code HsmVendorMechanism} with the specified mechanism identifier.
     *
     * @param mechanism
     *            the unique identifier for the HSM vendor mechanism
     */
    private HsmVendorMechanism(Long mechanism) {
        this.mech = mechanism;
    }

    /**
     * Retrieves the default {@link Mechanism} associated with this vendor mechanism.
     * <p>
     * This method is a convenience overload that calls {@link #getMechanism(Parameters)}
     * with a {@code null} parameter, returning the default mechanism.
     *
     * @return the default {@code Mechanism} for this vendor mechanism
     */
    public Mechanism getMechanism() {
        return getMechanism(null);
    }

    /**
     * Retrieves a {@link Mechanism} instance based on the current mechanism type,
     * sets its parameters using the provided {@link Parameters} object, and returns it.
     *
     * @param parameters
     *            the parameters to be set on the mechanism
     * @return a configured {@link Mechanism} instance
     */
    public Mechanism getMechanism(Parameters parameters) {
        Mechanism mechanism = Mechanism.get(mech);
        mechanism.setParameters(parameters);
        return mechanism;
    }
}
