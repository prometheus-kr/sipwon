package io.github.prometheuskr.sipwon.key;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.parameters.KeyDerivationStringDataParameters;
import iaik.pkcs.pkcs11.parameters.Parameters;
import io.github.prometheuskr.sipwon.constant.HsmMechanism;
import io.github.prometheuskr.sipwon.constant.HsmVendor;
import io.github.prometheuskr.sipwon.constant.HsmVendorMechanism;
import io.github.prometheuskr.sipwon.util.Util;
import lombok.extern.slf4j.Slf4j;

/**
 * Implementation of the {@link HsmKey} interface for AES keys managed by an HSM (Hardware Security Module).
 * <p>
 * This class provides cryptographic operations such as encryption, decryption, MAC (signing), key derivation,
 * key wrapping, and key creation using AES keys within an HSM session. It abstracts vendor-specific mechanisms
 * and parameter handling for AES operations.
 * <p>
 * Supported mechanisms include:
 * <ul>
 * <li>AES CBC (Cipher Block Chaining)</li>
 * <li>AES ECB (Electronic Codebook)</li>
 * <li>AES ECB Encrypt Data (for key derivation)</li>
 * </ul>
 * <p>
 * All data inputs and outputs are expected to be hexadecimal strings.
 * <p>
 * Note: The actual key material is never exposed in logs or return values.
 */
@Slf4j
public class HsmKey_AES implements HsmKey {
    /**
     * The initial vector (IV) used for AES encryption operations.
     * This IV is a 32-character string consisting of repeated '0' characters.
     * Note: The length and value of the IV should match the requirements of the AES mode being used.
     */
    private static final String INITIAL_VECTOR = "0".repeat(32);

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
     * The AES secret key used for cryptographic operations.
     * This key is immutable and securely stored within the class.
     */
    private final AESSecretKey key;

    /**
     * Constructs an instance of {@code HsmKey_AES} with the specified HSM vendor, session, and key.
     *
     * @param hsmVendor
     *            the HSM vendor implementation to be used
     * @param session
     *            the session associated with the HSM
     * @param key
     *            the AES secret key to be managed by this instance
     */
    HsmKey_AES(HsmVendor hsmVendor, Session session, Key key) {
        this.hsmVendor = hsmVendor;
        this.session = session;
        this.key = (AESSecretKey) key;
    }

    /**
     * Encrypts the given data using the specified HSM mechanism.
     * <p>
     * This method initializes the encryption operation with the provided mechanism and key,
     * converts the input hexadecimal string to a byte array, performs encryption using the HSM session,
     * and returns the encrypted result as a hexadecimal string.
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
     * and returns the decrypted data as a hexadecimal string.
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
     * converts the input hexadecimal string to a byte array, and computes the MAC using the HSM session.
     * The resulting MAC is converted back to a hexadecimal string and truncated to the first 8 characters.
     *
     * @param data
     *            the input data as a hexadecimal string to be signed
     * @param hsmMechanism
     *            the HSM mechanism to use for signing
     * @return the first 8 characters of the hexadecimal representation of the MAC
     * @throws TokenException
     *             if an error occurs during the signing operation
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
     * Derives a new AES HSM key from the current key using the specified data.
     * <p>
     * This method creates a key template with specific attributes for the derived key,
     * sets up the appropriate mechanism for key derivation (AES ECB encrypt data with the provided data),
     * and invokes the HSM session to derive a new key. The derived key is returned as a new {@link HsmKey_AES}
     * instance.
     *
     * @param data
     *            the data used in the key derivation process (e.g., derivation parameter or input data)
     * @return a new {@link HsmKey_AES} instance representing the derived key
     * @throws TokenException
     *             if the key derivation operation fails
     */
    @Override
    public HsmKey derive(String data) throws TokenException {
        log.debug("data to derive: [{}]", data);

        AESSecretKey keyTemplate = new AESSecretKey();
        keyTemplate.getToken().setBooleanValue(Boolean.FALSE);
        keyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDerive().setBooleanValue(Boolean.TRUE);
        keyTemplate.getValueLen().setLongValue(16L);

        Mechanism mechanism = toMechanism(HsmMechanism.AES_ECB_ENCRYPT_DATA, data);

        Key dkey = session.deriveKey(mechanism, key, keyTemplate);
        log.debug("derived key [can't read key value]");

        return new HsmKey_AES(hsmVendor, session, dkey);
    }

    /**
     * Wraps the specified target key using the current AES key and returns the wrapped key as a hexadecimal string.
     * <p>
     * This method uses the AES ECB mechanism to wrap the provided {@code targetKey}. The wrapped key is returned
     * as a hexadecimal string representation. The actual key values are not logged for security reasons.
     *
     * @param targetKey
     *            the {@link HsmKey} to be wrapped; must be an instance of {@link HsmKey_AES}
     * @return the wrapped key as a hexadecimal string
     * @throws TokenException
     *             if an error occurs during the key wrapping process
     */
    @Override
    public String wrapKey(HsmKey targetKey) throws TokenException {
        log.debug("targetKey to wrap: [can't read key value]");

        Mechanism mechanism = toMechanism(HsmMechanism.AES_ECB);

        byte[] wrappedKey = session.wrapKey(mechanism, key, ((HsmKey_AES) targetKey).key);
        String result = Util.byteArray2HexaString(wrappedKey);
        log.debug("wrapped result [{}]", result);

        return result;
    }

    /**
     * Creates a new AES HSM key using the provided hexadecimal string value.
     * <p>
     * The method converts the input hexadecimal string to a byte array, sets up an AES key template
     * with appropriate attributes (encryption, decryption, unwrapping, signing), and creates the key
     * object in the HSM session. The resulting key is wrapped in an {@link HsmKey_AES} instance.
     *
     * @param value
     *            the hexadecimal string representation of the AES key material
     * @return a new {@link HsmKey_AES} instance representing the created key
     * @throws TokenException
     *             if there is an error during key creation in the HSM session
     */
    @Override
    public HsmKey createKey(String value) throws TokenException {
        log.debug("value to createKey: [{}]", value);
        byte[] keyValueByteArray = Util.hexaString2ByteArray(value);

        AESSecretKey keyTemplate = new AESSecretKey();
        keyTemplate.getToken().setBooleanValue(Boolean.FALSE);
        keyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        keyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        keyTemplate.getValue().setByteArrayValue(keyValueByteArray);
        AESSecretKey dkey = (AESSecretKey) session.createObject(keyTemplate);

        return new HsmKey_AES(hsmVendor, session, dkey);
    }

    /**
     * Converts the specified {@link HsmMechanism} to a {@link Mechanism} instance,
     * using the default initial vector.
     *
     * @param hsmMechanism
     *            the HSM mechanism to convert
     * @return a {@link Mechanism} corresponding to the provided HSM mechanism and the default initial vector
     */
    private Mechanism toMechanism(HsmMechanism hsmMechanism) {
        return toMechanism(hsmMechanism, INITIAL_VECTOR);
    }

    /**
     * Converts the specified {@link HsmMechanism} and associated data into a {@link Mechanism} object,
     * using the appropriate parameters based on the mechanism type.
     * <p>
     * The method first resolves the vendor-specific mechanism using {@code hsmMechanism.getMechanism0(hsmVendor)}.
     * It then selects the correct parameter type for the mechanism:
     * <ul>
     * <li>{@code AES_CBC}: Uses {@link InitializationVectorParameters} initialized with the byte array
     * representation of the provided hexadecimal string {@code data}.</li>
     * <li>{@code AES_ECB_ENCRYPT_DATA}: Uses {@link KeyDerivationStringDataParameters} initialized with the byte array
     * representation of the provided hexadecimal string {@code data}.</li>
     * <li>Other mechanisms: No parameters are provided (null).</li>
     * </ul>
     * Finally, the method returns the constructed {@link Mechanism} object.
     *
     * @param hsmMechanism
     *            the high-level HSM mechanism to convert
     * @param data
     *            a hexadecimal string representing mechanism-specific data (e.g., IV or key derivation data)
     * @return the corresponding {@link Mechanism} object with appropriate parameters
     */
    private Mechanism toMechanism(HsmMechanism hsmMechanism, String data) {
        HsmVendorMechanism changedMechanism = hsmMechanism.getMechanism0(hsmVendor);

        Parameters param = switch (changedMechanism) {
            case AES_CBC -> new InitializationVectorParameters(Util.hexaString2ByteArray(data));
            case AES_ECB_ENCRYPT_DATA -> new KeyDerivationStringDataParameters(Util.hexaString2ByteArray(data));
            default -> null;
        };

        return changedMechanism.getMechanism(param);
    }
}
