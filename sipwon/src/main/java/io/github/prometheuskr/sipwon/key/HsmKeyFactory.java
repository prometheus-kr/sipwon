package io.github.prometheuskr.sipwon.key;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Key;
import io.github.prometheuskr.sipwon.constant.HsmVendorKeyType;
import io.github.prometheuskr.sipwon.constant.HsmKeyType;
import io.github.prometheuskr.sipwon.constant.HsmVendor;
import lombok.extern.slf4j.Slf4j;

/**
 * Factory class for creating {@link HsmKey} instances based on the provided HSM vendor, session, and key information.
 * <p>
 * This class provides static methods to obtain concrete implementations of {@link HsmKey} for different key types
 * and to create temporary HSM keys from raw values.
 * <p>
 * Usage of this class is restricted to static methods; instantiation is not allowed.
 * <ul>
 * <li>{@link #getHsmKey(HsmVendor, Session, Key)}: Returns an {@link HsmKey} instance corresponding to the key
 * type.</li>
 * <li>{@link #createTempHsmKey(HsmVendor, Session, HsmKeyType, String)}: Creates a temporary {@link HsmKey} from a raw
 * value.</li>
 * </ul>
 */
@Slf4j
public class HsmKeyFactory {

    /**
     * Private constructor to prevent instantiation of the {@code HsmKeyFactory} class.
     * This class is intended to be used in a static context only.
     */
    private HsmKeyFactory() {}

    /**
     * Creates and returns an {@link HsmKey} instance based on the specified HSM vendor, session, and key.
     * The type of {@link HsmKey} returned depends on the {@link HsmVendorKeyType} derived from the provided key.
     *
     * @param hsmVendor
     *            the HSM vendor implementation to use
     * @param session
     *            the current HSM session
     * @param key
     *            the key object containing key type and related information
     * @return an instance of {@link HsmKey} corresponding to the key type (DES, DDES, TDES, AES, SEED, or SEED_PTK)
     */
    public static HsmKey getHsmKey(HsmVendor hsmVendor, Session session, Key key) {
        log.debug("key: [{}]", key);

        HsmVendorKeyType keyType = HsmVendorKeyType.fromLongValue(key.getKeyType().getLongValue());
        return switch (keyType) {
            case DES -> new HsmKey_DES(hsmVendor, session, key);
            case DDES -> new HsmKey_DDES(hsmVendor, session, key);
            case TDES -> new HsmKey_TDES(hsmVendor, session, key);
            case AES -> new HsmKey_AES(hsmVendor, session, key);
            case SEED, SEED_PTK -> new HsmKey_SEED(hsmVendor, session, key);
        };
    }

    /**
     * Creates a temporary {@link HsmKey} instance of the specified type and initializes it with the provided value.
     *
     * @param hsmVendor
     *            the HSM vendor to use for key creation
     * @param session
     *            the session associated with the HSM operation
     * @param keyType
     *            the type of HSM key to create (e.g., DES, DDES, TDES, AES, SEED)
     * @param value
     *            the value to initialize the key with
     * @return a newly created {@link HsmKey} instance initialized with the given value
     * @throws TokenException
     *             if an error occurs during key creation or initialization
     */
    public static HsmKey createTempHsmKey(HsmVendor hsmVendor, Session session, HsmKeyType keyType, String value)
            throws TokenException {

        HsmKey key = switch (keyType) {
            case DES -> new HsmKey_DES(hsmVendor, session, null);
            case DDES -> new HsmKey_DDES(hsmVendor, session, null);
            case TDES -> new HsmKey_TDES(hsmVendor, session, null);
            case AES -> new HsmKey_AES(hsmVendor, session, null);
            case SEED -> new HsmKey_SEED(hsmVendor, session, null);
        };

        return key.createKey(value);
    }
}
