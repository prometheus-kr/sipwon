package io.github.prometheuskr.sipwon.constant;

/**
 * Enum representing supported Hardware Security Module (HSM) vendors.
 * <p>
 * This enum is used to specify the type of HSM vendor integrated with the system.
 * <ul>
 * <li>{@link #PTK} - Represents the PTK HSM vendor.</li>
 * <li>{@link #NFAST} - Represents the nCipher nFast HSM vendor.</li>
 * </ul>
 */
public enum HsmVendor {
    /**
     * Represents the PTK HSM vendor
     */
    PTK,
    /**
     * Represents the nCipher nFast HSM vendor
     */
    NFAST,

    ;
}
