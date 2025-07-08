package io.github.prometheuskr.sipwon.constant;

/**
 * Enumeration representing the types of cryptographic keys supported by the HSM
 * (Hardware Security Module).
 * <ul>
 * <li>{@link #DES} - Data Encryption Standard key.</li>
 * <li>{@link #DDES} - Double-length DES key.</li>
 * <li>{@link #TDES} - Triple DES (3DES) key.</li>
 * <li>{@link #AES} - Advanced Encryption Standard key.</li>
 * <li>{@link #SEED} - SEED block cipher key (commonly used in South Korea).</li>
 * </ul>
 */
public enum HsmKeyType {
    /**
     * Data Encryption Standard key
     */
    DES,
    /**
     * Double-length DES key
     */
    DDES,
    /**
     * Triple DES (3DES) key
     */
    TDES,
    /**
     * Advanced Encryption Standard key
     */
    AES,

    /**
     * SEED block cipher key (commonly used in South Korea)
     */
    SEED,

    ;
}
