package io.github.prometheuskr.sipwon.key;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.DESSecretKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.parameters.KeyDerivationStringDataParameters;
import iaik.pkcs.pkcs11.parameters.Parameters;
import io.github.prometheuskr.sipwon.constant.HsmMechanism;
import io.github.prometheuskr.sipwon.constant.HsmVendor;
import io.github.prometheuskr.sipwon.constant.HsmVendorMechanism;
import io.github.prometheuskr.sipwon.util.Util;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class HsmKey_DES implements HsmKey {
    private static final String DES_INITIAL_VECTOR = "0".repeat(16);

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
     * The DES secret key used for cryptographic operations.
     */
    private final DESSecretKey key;

    /**
     * Constructs a new {@code HsmKey_DES} instance with the specified HSM vendor, session, and key.
     *
     * @param hsmVendor
     *            the HSM vendor implementation to use
     * @param session
     *            the session associated with the HSM
     * @param key
     *            the DES secret key to be managed by this instance
     */
    HsmKey_DES(HsmVendor hsmVendor, Session session, Key key) {
        this.hsmVendor = hsmVendor;
        this.session = session;
        this.key = (DESSecretKey) key;
    }

    /**
     * Encrypts the given hexadecimal string data using the specified HSM mechanism.
     * <p>
     * This method initializes the encryption operation with the provided mechanism and key,
     * converts the input hexadecimal string to a byte array, performs encryption using the HSM session,
     * and returns the encrypted result as a hexadecimal string.
     *
     * @param data
     *            the input data to encrypt, represented as a hexadecimal string
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
     * @return the decrypted data as a hexadecimal string
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
     *            the hexadecimal string representation of the data to be signed
     * @param hsmMechanism
     *            the HSM mechanism to use for signing
     * @return the first 8 characters of the hexadecimal MAC string
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
     * Derives a new DES key from the current key using the specified data.
     * <p>
     * This method creates a key template with specific attributes for encryption, decryption,
     * signing, and derivation. It then uses the provided data to create a mechanism for key derivation,
     * and derives a new key using the current session and key. The derived key is returned as a new
     * {@link HsmKey_DES} instance.
     *
     * @param data
     *            the data used for key derivation (typically a derivation parameter or value)
     * @return a new {@link HsmKey_DES} instance representing the derived key
     * @throws TokenException
     *             if key derivation fails or an error occurs in the HSM session
     */
    @Override
    public HsmKey derive(String data) throws TokenException {
        log.debug("data to derive: [{}]", data);

        DESSecretKey keyTemplate = new DESSecretKey();
        keyTemplate.getToken().setBooleanValue(Boolean.FALSE);
        keyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDerive().setBooleanValue(Boolean.TRUE);

        Mechanism mechanism = toMechanism(HsmMechanism.DES_ECB_ENCRYPT_DATA, data);

        Key dkey = session.deriveKey(mechanism, key, keyTemplate);
        log.debug("derived key [can't read key value]");

        return new HsmKey_DES(hsmVendor, session, dkey);
    }

    /**
     * Wraps the specified target DES key using the current DES key and returns the wrapped key as a hexadecimal string.
     * <p>
     * This method uses the DES ECB mechanism to wrap the provided {@code targetKey}. The wrapped key is returned
     * as a hexadecimal string representation. Debug logs are generated for the wrapping process, but the actual key
     * values are not logged for security reasons.
     *
     * @param targetKey
     *            the {@link HsmKey} to be wrapped; must be an instance of {@link HsmKey_DES}
     * @return the wrapped key as a hexadecimal string
     * @throws TokenException
     *             if an error occurs during the key wrapping process
     */
    @Override
    public String wrapKey(HsmKey targetKey) throws TokenException {
        log.debug("targetKey to wrap: [can't read key value]");

        Mechanism mechanism = toMechanism(HsmMechanism.DES_ECB);

        byte[] wrappedKey = session.wrapKey(mechanism, key, ((HsmKey_DES) targetKey).key);
        String result = Util.byteArray2HexaString(wrappedKey);
        log.debug("wrapped result [{}]", result);

        return result;
    }

    /**
     * Creates a new DES HSM key using the provided hexadecimal string value.
     * <p>
     * This method converts the given hexadecimal string into a byte array,
     * sets up a DESSecretKey template with appropriate attributes for encryption,
     * decryption, unwrapping, and signing, and then creates the key object in the HSM session.
     * The resulting key is wrapped in an {@link HsmKey_DES} instance.
     *
     * @param value
     *            the hexadecimal string representation of the key value
     * @return a new {@link HsmKey_DES} instance representing the created key
     * @throws TokenException
     *             if an error occurs during key creation in the HSM
     */
    @Override
    public HsmKey createKey(String value) throws TokenException {
        log.debug("value to createKey: [{}]", value);
        byte[] keyValueByteArray = Util.hexaString2ByteArray(value);

        DESSecretKey keyTemplate = new DESSecretKey();
        keyTemplate.getToken().setBooleanValue(Boolean.FALSE);
        keyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        keyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        keyTemplate.getValue().setByteArrayValue(keyValueByteArray);
        DESSecretKey dkey = (DESSecretKey) session.createObject(keyTemplate);

        return new HsmKey_DES(hsmVendor, session, dkey);
    }

    /**
     * Converts the specified {@link HsmMechanism} to a {@link Mechanism} using the default DES initial vector.
     *
     * @param hsmMechanism
     *            the HSM mechanism to convert
     * @return the corresponding {@link Mechanism} instance
     */
    private Mechanism toMechanism(HsmMechanism hsmMechanism) {
        return toMechanism(hsmMechanism, DES_INITIAL_VECTOR);
    }

    /**
     * Converts the specified {@link HsmMechanism} and associated data into a {@link Mechanism} object,
     * using the appropriate parameters based on the mechanism type.
     * <p>
     * The method first resolves the vendor-specific mechanism using {@code hsmMechanism.getMechanism0(hsmVendor)}.
     * It then constructs the required parameters for the mechanism:
     * <ul>
     * <li>If the mechanism is {@code DES_CBC}, an {@link InitializationVectorParameters} is created using the provided
     * data.</li>
     * <li>If the mechanism is {@code DES_ECB_ENCRYPT_DATA}, a {@link KeyDerivationStringDataParameters} is created
     * using the provided data.</li>
     * <li>For other mechanisms, {@code null} is used as the parameter.</li>
     * </ul>
     * The data string is expected to be a hexadecimal string, which is converted to a byte array.
     * Finally, the method returns the mechanism object with the constructed parameters.
     *
     * @param hsmMechanism
     *            the high-level HSM mechanism to convert
     * @param data
     *            the hexadecimal string data used for mechanism parameters
     * @return the corresponding {@link Mechanism} object with appropriate parameters
     */
    private Mechanism toMechanism(HsmMechanism hsmMechanism, String data) {
        HsmVendorMechanism changedMechanism = hsmMechanism.getMechanism0(hsmVendor);

        Parameters param = switch (changedMechanism) {
            case DES_CBC -> new InitializationVectorParameters(Util.hexaString2ByteArray(data));
            case DES_ECB_ENCRYPT_DATA -> new KeyDerivationStringDataParameters(Util.hexaString2ByteArray(data));
            default -> null;
        };

        return changedMechanism.getMechanism(param);
    }
}
