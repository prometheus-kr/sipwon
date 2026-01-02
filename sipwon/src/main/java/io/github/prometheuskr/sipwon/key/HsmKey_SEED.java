package io.github.prometheuskr.sipwon.key;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.GenericSecretKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.parameters.Parameters;
import io.github.prometheuskr.sipwon.constant.HsmMechanism;
import io.github.prometheuskr.sipwon.constant.HsmVendorMechanism;
import io.github.prometheuskr.sipwon.key.vendor.SEEDSecretKeyPTK;
import io.github.prometheuskr.sipwon.constant.HsmVendor;
import io.github.prometheuskr.sipwon.util.Util;
import lombok.extern.slf4j.Slf4j;

/**
 * Implementation of the {@link HsmKey} interface for SEED cryptographic operations using a Hardware Security Module
 * (HSM).
 * <p>
 * This class provides methods for encryption, decryption, MAC generation, key derivation, and key wrapping
 * using the SEED algorithm. It supports vendor-specific mechanisms and manages cryptographic keys within a secure HSM
 * session.
 * <p>
 * <b>Features:</b>
 * <ul>
 * <li>Encrypts and decrypts data using SEED mechanisms supported by the configured HSM vendor.</li>
 * <li>Generates Message Authentication Codes (MAC) for data integrity and authentication.</li>
 * <li>Derives new HSM keys from input data using SEED encryption.</li>
 * <li>Wraps and unwraps keys for secure key management and transport.</li>
 * <li>Supports vendor-specific key creation and mechanism mapping.</li>
 * </ul>
 * <p>
 * <b>Usage:</b>
 * 
 * <pre>
 * HsmKey_SEED seedKey = new HsmKey_SEED(hsmVendor, session, key);
 * String encrypted = seedKey.encrypt(data, HsmMechanism.SEED_ECB);
 * String decrypted = seedKey.decrypt(encrypted, HsmMechanism.SEED_ECB);
 * String mac = seedKey.mac(data, HsmMechanism.SEED_CBC_PTK);
 * HsmKey derivedKey = seedKey.derive(data);
 * String wrappedKey = seedKey.wrapKey(anotherSeedKey);
 * </pre>
 * <p>
 * <b>Note:</b> Currently, only the PTK vendor is supported for SEED key creation.
 * <p>
 * All data inputs and outputs are expected to be hexadecimal-encoded strings.
 *
 * @see HsmKey
 * @see HsmVendor
 * @see Session
 * @see GenericSecretKey
 */
@Slf4j
public class HsmKey_SEED implements HsmKey {
    /**
     * The initial vector (IV) used for cryptographic operations, represented as a 32-character string of zeros.
     * This value is typically used to provide an initial state for encryption algorithms that require an IV.
     */
    private static final String INITIAL_VECTOR = String.format("%032d", 0);

    /**
     * The HSM (Hardware Security Module) vendor associated with this key.
     * This field specifies which HSM implementation is being used for cryptographic operations.
     */
    private final HsmVendor hsmVendor;
    /**
     * The {@code session} represents an active connection to the HSM (Hardware Security Module).
     * It is used to perform cryptographic operations and manage keys within the secure environment.
     * This session is typically established and managed by the underlying cryptographic provider.
     */
    private final Session session;
    /**
     * The cryptographic secret key used for HSM (Hardware Security Module) operations.
     * This key is represented by a {@link GenericSecretKey} instance and is immutable.
     */
    private final GenericSecretKey key;

    /**
     * Constructs a new {@code HsmKey_SEED} instance with the specified HSM vendor, session, and key.
     *
     * @param hsmVendor
     *            the HSM vendor implementation to be used
     * @param session
     *            the session associated with the HSM
     * @param key
     *            the cryptographic key, expected to be of type {@code GenericSecretKey}
     */
    HsmKey_SEED(HsmVendor hsmVendor, Session session, Key key) {
        this.hsmVendor = hsmVendor;
        this.session = session;
        this.key = (GenericSecretKey) key;
    }

    /**
     * Encrypts the provided data using the specified HSM mechanism.
     * <p>
     * This method initializes the encryption operation with the given mechanism and key,
     * converts the input hexadecimal string to a byte array, performs the encryption using
     * the HSM session, and returns the encrypted result as a hexadecimal string.
     *
     * @param data
     *            the data to encrypt, represented as a hexadecimal string
     * @param hsmMechanism
     *            the HSM mechanism to use for encryption
     * @return the encrypted data as a hexadecimal string
     * @throws TokenException
     *             if an error occurs during encryption
     */
    @Override
    public String encrypt(String data, HsmMechanism hsmMechanism) throws TokenException {
        log.debug("data to encrypt: [{}]", data);

        Mechanism mechanism = toMechanism(hsmMechanism);
        session.encryptInit(mechanism, key);

        byte[] inputData = Util.hexaString2ByteArray(data);
        byte[] encryptedData = session.encrypt(inputData);
        String result = Util.byteArray2HexaString(encryptedData);
        log.debug("encrypted result [{}]", result);

        return result;
    }

    /**
     * Decrypts the given hexadecimal-encoded data using the specified HSM mechanism.
     * <p>
     * This method initializes the decryption operation with the provided mechanism and key,
     * converts the input hexadecimal string to a byte array, performs the decryption using the HSM session,
     * and returns the decrypted result as a hexadecimal string.
     *
     * @param data
     *            the hexadecimal-encoded string to decrypt
     * @param hsmMechanism
     *            the HSM mechanism to use for decryption
     * @return the decrypted data as a hexadecimal-encoded string
     * @throws TokenException
     *             if an error occurs during decryption
     */
    @Override
    public String decrypt(String data, HsmMechanism hsmMechanism) throws TokenException {
        log.debug("data to decrypt: [{}]", data);

        Mechanism mechanism = toMechanism(hsmMechanism);
        session.decryptInit(mechanism, key);

        byte[] inputData = Util.hexaString2ByteArray(data);
        byte[] decryptedData = session.decrypt(inputData);
        String result = Util.byteArray2HexaString(decryptedData);
        log.debug("decrypted result [{}]", result);

        return result;
    }

    /**
     * Generates a Message Authentication Code (MAC) for the given data using the specified HSM mechanism.
     * <p>
     * This method initializes the signing operation with the provided mechanism and key,
     * converts the input hexadecimal string to a byte array, and computes the MAC.
     * The resulting MAC is converted back to a hexadecimal string and truncated to the first 8 characters.
     *
     * @param data
     *            the hexadecimal string representation of the data to be signed
     * @param hsmMechanism
     *            the HSM mechanism to use for signing
     * @return the first 8 characters of the hexadecimal MAC string
     * @throws TokenException
     *             if an error occurs during the signing process
     */
    @Override
    public String mac(String data, HsmMechanism hsmMechanism) throws TokenException {
        log.debug("data to sign: [{}]", data);

        Mechanism mechanism = toMechanism(hsmMechanism);
        session.signInit(mechanism, key);

        byte[] inputData = Util.hexaString2ByteArray(data);
        byte[] signedData = session.sign(inputData);
        String result = Util.byteArray2HexaString(signedData).substring(0, 8);
        log.debug("signed result [{}]", result);

        return result;
    }

    /**
     * Derives a new {@link HsmKey} from the provided data string.
     * <p>
     * This method encrypts the input data using the SEED ECB mechanism and creates a new HsmKey
     * instance from the resulting encrypted value.
     * 
     * @param data
     *            the input data to derive the key from
     * @return a new {@link HsmKey} derived from the input data
     * @throws TokenException
     *             if an error occurs during key derivation or encryption
     */
    @Override
    public HsmKey derive(String data) throws TokenException {
        log.debug("data to derive: [{}]", data);

        String keyValue = encrypt(data, HsmMechanism.SEED_ECB);
        return createKey(keyValue);
    }

    /**
     * Wraps the specified target key using the SEED ECB mechanism.
     * <p>
     * This method wraps the provided {@code targetKey} with the current key instance,
     * using the SEED ECB encryption mechanism. The wrapped key is returned as a hexadecimal string.
     * 
     * @param targetKey
     *            the {@link HsmKey} to be wrapped; must be an instance of {@link HsmKey_SEED}
     * @return the wrapped key as a hexadecimal string
     * @throws TokenException
     *             if an error occurs during the key wrapping process
     */
    @Override
    public String wrapKey(HsmKey targetKey) throws TokenException {
        log.debug("targetKey to wrap: [can't read key value]");

        Mechanism mechanism = toMechanism(HsmMechanism.SEED_ECB);

        byte[] wrappedKey = session.wrapKey(mechanism, key, ((HsmKey_SEED) targetKey).key);
        String result = Util.byteArray2HexaString(wrappedKey);
        log.debug("wrapped result [{}]", result);

        return result;
    }

    /**
     * Creates a new SEED HSM key using the provided hexadecimal string value.
     * <p>
     * This method converts the input hexadecimal string to a byte array and initializes
     * a key template specific to the configured HSM vendor. Currently, only the PTK vendor
     * is supported for SEED key creation. The method sets the appropriate attributes for
     * the key (encryption, decryption, unwrapping, signing) and creates the key object
     * within the HSM session.
     * 
     * @param value
     *            the hexadecimal string representation of the key value
     * @return a new {@link HsmKey_SEED} instance representing the created key
     * @throws TokenException
     *             if the HSM vendor is unsupported or key creation fails
     */
    @Override
    public HsmKey createKey(String value) throws TokenException {
        log.debug("value to createKey: [{}]", value);
        byte[] keyValueByteArray = Util.hexaString2ByteArray(value);

        GenericSecretKey keyTemplate;
        if (hsmVendor == HsmVendor.PTK) {
            keyTemplate = new SEEDSecretKeyPTK();
        } else {
            throw new TokenException("Unsupported HSM vendor for SEED key creation: " + hsmVendor);
        }

        keyTemplate.getToken().setBooleanValue(Boolean.FALSE);
        keyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        keyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        keyTemplate.getValue().setByteArrayValue(keyValueByteArray);
        GenericSecretKey dkey = (GenericSecretKey) session.createObject(keyTemplate);

        return new HsmKey_SEED(hsmVendor, session, dkey);
    }

    /**
     * Converts the specified {@link HsmMechanism} to a {@link Mechanism} using the default
     * SEED initial vector.
     *
     * @param hsmMechanism
     *            the HSM mechanism to convert
     * @return a {@link Mechanism} instance configured with the given HSM mechanism and the default SEED initial vector
     */
    private Mechanism toMechanism(HsmMechanism hsmMechanism) {
        return toMechanism(hsmMechanism, INITIAL_VECTOR);
    }

    /**
     * Converts the specified {@link HsmMechanism} and associated data into a {@link Mechanism} object.
     * <p>
     * This method determines the appropriate vendor-specific mechanism using the provided
     * {@code hsmVendor}, and constructs the required parameters based on the mechanism type.
     * For {@code SEED_CBC_PTK}, it creates an {@link InitializationVectorParameters} using
     * the hexadecimal string {@code data}. For other mechanisms, no parameters are provided.
     *
     * @param hsmMechanism
     *            the high-level HSM mechanism to convert
     * @param data
     *            the hexadecimal string data used for parameter construction (e.g., IV)
     * @return the constructed {@link Mechanism} object with appropriate parameters
     */
    private Mechanism toMechanism(HsmMechanism hsmMechanism, String data) {
        HsmVendorMechanism changedMechanism = hsmMechanism.getMechanism0(hsmVendor);

        Parameters param;
        switch (changedMechanism) {
            case SEED_CBC_PTK:
                param = new InitializationVectorParameters(Util.hexaString2ByteArray(data));
                break;
            default:
                param = null;
                break;
        }
        return changedMechanism.getMechanism(param);
    }
}
