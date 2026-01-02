package io.github.prometheuskr.sipwon.session;

import java.util.List;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.DES2SecretKey;
import iaik.pkcs.pkcs11.objects.DES3SecretKey;
import iaik.pkcs.pkcs11.objects.DESSecretKey;
import iaik.pkcs.pkcs11.objects.Key;
import io.github.prometheuskr.sipwon.constant.HsmKeyType;
import io.github.prometheuskr.sipwon.constant.HsmVendor;
import io.github.prometheuskr.sipwon.key.HsmKey;
import io.github.prometheuskr.sipwon.key.HsmKeyFactory;
import io.github.prometheuskr.sipwon.key.vendor.SEEDSecretKey;
import io.github.prometheuskr.sipwon.key.vendor.SEEDSecretKeyPTK;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

/**
 * Implementation of the {@link HsmSession} interface that manages a session with a Hardware Security Module (HSM).
 * This class abstracts vendor-specific key handling and session management.
 * <p>
 * Responsibilities include:
 * <ul>
 * <li>Managing the lifecycle of an HSM session.</li>
 * <li>Finding and creating HSM keys based on vendor and key type.</li>
 * <li>Handling exceptions during session closure gracefully.</li>
 * </ul>
 * <p>
 * Supported HSM vendors are defined by {@link HsmVendor}, and supported key types by {@link HsmKeyType}.
 * <p>
 * Example usage:
 * 
 * <pre>
 *     try (HsmSession session = new HsmSessionImpl(...)) {
 *         HsmKey key = session.findHsmKey("label", HsmKeyType.AES);
 *         // Use the key...
 *     }
 * </pre>
 */
@Slf4j
public class HsmSessionImpl implements HsmSession {
    @NonNull
    /**
     * The underlying Hibernate {@link Session} used for database operations within this session implementation.
     */
    private final Session session;
    /**
     * The vendor-specific implementation of the Hardware Security Module (HSM) used in this session.
     * This field determines which HSM vendor's API and features are utilized.
     */
    private final HsmVendor hsmVendor;

    /**
     * Constructs a new {@code HsmSessionImpl} instance with the specified session and HSM vendor.
     *
     * @param hsmSession
     *            the session associated with the HSM
     * @param hsmVendor
     *            the vendor implementation of the HSM
     */
    HsmSessionImpl(Session hsmSession, HsmVendor hsmVendor) {
        this.session = hsmSession;
        this.hsmVendor = hsmVendor;
    }

    /**
     * Closes the current HSM session.
     * <p>
     * Attempts to close the underlying session and logs a warning if a {@link TokenException}
     * occurs during the process. Any such exception is ignored to ensure that the close
     * operation does not propagate exceptions to the caller.
     */
    @Override
    public void close() {
        try {
            session.closeSession();
        } catch (TokenException e) {
            log.warn("an exception occured during closeSession.. but ignored this exception.", e);
        }
    }

    /**
     * Finds and returns an {@link HsmKey} based on the provided key label and key type.
     * <p>
     * This method creates a vendor-specific key template, sets its label, and searches for matching keys
     * in the current session. If exactly one key is found, it is returned as an {@link HsmKey} instance.
     * If no key or multiple keys are found with the specified label, a {@link RuntimeException} is thrown.
     *
     * @param keyLabel
     *            the label of the key to search for
     * @param keyType
     *            the type of the key to search for
     * @return the {@link HsmKey} corresponding to the specified label and type
     * @throws TokenException
     *             if an error occurs while communicating with the HSM token
     * @throws RuntimeException
     *             if no key or multiple keys are found for the given label
     */
    @Override
    public HsmKey findHsmKey(String keyLabel, HsmKeyType keyType) throws TokenException {
        Key key = newVendorKey(keyType);

        key.getLabel().setCharArrayValue(keyLabel.toCharArray());

        List<Key> keyList = ModuleHelper.findKey(session, key);
        if (keyList.size() != 1) {
            throw new RuntimeException("Key not found or multiple keys found for label: " + keyLabel);
        }

        return HsmKeyFactory.getHsmKey(hsmVendor, session, keyList.get(0));
    }

    /**
     * Creates a temporary HSM key of the specified type and value.
     *
     * @param keyType
     *            the type of the HSM key to create
     * @param value
     *            the value to be used for the temporary key
     * @return a newly created temporary {@link HsmKey}
     * @throws TokenException
     *             if an error occurs during key creation
     */
    @Override
    public HsmKey createTempHsmKey(HsmKeyType keyType, String value) throws TokenException {
        return HsmKeyFactory.createTempHsmKey(hsmVendor, session, keyType, value);
    }

    /**
     * Creates a new vendor-specific cryptographic key instance based on the provided {@link HsmKeyType}
     * and the current HSM vendor.
     * <p>
     * Depending on the {@code hsmVendor} field, this method instantiates and returns the appropriate
     * key implementation for the specified key type. If the vendor or key type is not recognized,
     * the method returns {@code null}.
     *
     * @param keyType
     *            the type of key to create (e.g., DES, DDES, TDES, AES, SEED)
     * @return a new instance of the vendor-specific key, or {@code null} if the vendor or key type is unsupported
     */
    private Key newVendorKey(HsmKeyType keyType) {
        switch (hsmVendor) {
            case PTK:
                switch (keyType) {
                    case DES:
                        return new DESSecretKey();
                    case DDES:
                        return new DES2SecretKey();
                    case TDES:
                        return new DES3SecretKey();
                    case AES:
                        return new AESSecretKey();
                    case SEED:
                        return new SEEDSecretKeyPTK();
                }
                break;
            case NFAST:
                switch (keyType) {
                    case DES:
                        return new DESSecretKey();
                    case DDES:
                        return new DES2SecretKey();
                    case TDES:
                        return new DES3SecretKey();
                    case AES:
                        return new AESSecretKey();
                    case SEED:
                        return new SEEDSecretKey();
                }
                break;
        }

        return null;
    }
}
