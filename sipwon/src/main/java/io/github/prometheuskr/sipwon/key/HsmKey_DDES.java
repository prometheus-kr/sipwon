package io.github.prometheuskr.sipwon.key;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.DES2SecretKey;
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
 * Implementation of the {@link HsmKey} interface for Double/Triple DES (DDES) keys managed by an HSM.
 * <p>
 * This class provides cryptographic operations such as encryption, decryption, MAC generation, key derivation,
 * key wrapping, and key creation using a DES2SecretKey within a PKCS#11 session.
 * <ul>
 * <li>Encrypts and decrypts data using the specified HSM mechanism.</li>
 * <li>Generates MACs (Message Authentication Codes) for data integrity and authentication.</li>
 * <li>Derives new keys from existing keys using key derivation mechanisms.</li>
 * <li>Wraps (exports) other keys using this key as the wrapping key.</li>
 * <li>Creates new HSM keys from provided key values.</li>
 * </ul>
 * <p>
 * Mechanism selection and parameterization are handled internally based on the HSM vendor and operation type.
 *
 * @see HsmKey
 * @see HsmVendor
 * @see Session
 * @see DES2SecretKey
 */
@Slf4j
public class HsmKey_DDES implements HsmKey {
    /**
     * The initial vector (IV) used for cryptographic operations, represented as a 16-character string of zeros.
     * This IV is typically used in symmetric encryption algorithms that require a fixed-length initialization vector.
     */
    private static final String INITIAL_VECTOR = "0".repeat(16);

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
     * The DES2SecretKey instance representing the double-length DES (Data Encryption Standard) key
     * used for cryptographic operations in this class.
     */
    private final DES2SecretKey key;

    /**
     * Constructs an instance of {@code HsmKey_DDES} with the specified HSM vendor, session, and key.
     *
     * @param hsmVendor
     *            the HSM vendor implementation to be used
     * @param session
     *            the session associated with the HSM
     * @param key
     *            the key to be used, expected to be of type {@code DES2SecretKey}
     */
    HsmKey_DDES(HsmVendor hsmVendor, Session session, Key key) {
        this.hsmVendor = hsmVendor;
        this.session = session;
        this.key = (DES2SecretKey) key;
    }

    /**
     * Encrypts the provided hexadecimal string data using the specified HSM mechanism.
     * <p>
     * This method initializes the encryption operation with the given mechanism and key,
     * converts the input hexadecimal string to a byte array, performs the encryption,
     * and returns the encrypted result as a hexadecimal string.
     *
     * @param data
     *            the data to encrypt, represented as a hexadecimal string
     * @param hsmMechanism
     *            the HSM mechanism to use for encryption
     * @return the encrypted data as a hexadecimal string
     * @throws TokenException
     *             if an error occurs during the encryption process
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
     * Decrypts the provided hexadecimal-encoded data using the specified HSM mechanism.
     * <p>
     * This method initializes the decryption operation with the given mechanism and key,
     * converts the input hexadecimal string to a byte array, performs the decryption using the HSM session,
     * and returns the decrypted result as a hexadecimal string.
     *
     * @param data
     *            the hexadecimal-encoded string representing the data to decrypt
     * @param hsmMechanism
     *            the mechanism to use for decryption
     * @return the decrypted data as a hexadecimal-encoded string
     * @throws TokenException
     *             if an error occurs during the decryption process
     */
    @Override
    public String decrypt(String data, HsmMechanism hsmMechanism) throws TokenException {
        log.debug("data to decrypt: [{}]", data);

        Mechanism mechanism = toMechanism(hsmMechanism);
        session.decryptInit(mechanism, key);

        byte[] inputData = Util.hexaString2ByteArray(data);
        byte[] encryptedData = session.decrypt(inputData);
        String result = Util.byteArray2HexaString(encryptedData);
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
     * Derives a new HSM key using the specified data as input.
     * <p>
     * This method creates a key template with specific attributes (encryption, decryption,
     * signing, and derivation enabled), constructs a mechanism for DES3 ECB encryption with
     * the provided data, and uses the current session to derive a new key from the existing key.
     *
     * @param data
     *            the input data used for key derivation
     * @return a new {@link HsmKey} instance representing the derived key
     * @throws TokenException
     *             if an error occurs during key derivation
     */
    @Override
    public HsmKey derive(String data) throws TokenException {
        log.debug("data to derive: [{}]", data);

        DES2SecretKey keyTemplate = new DES2SecretKey();
        keyTemplate.getToken().setBooleanValue(Boolean.FALSE);
        keyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDerive().setBooleanValue(Boolean.TRUE);

        Mechanism mechanism = toMechanism(HsmMechanism.DES3_ECB_ENCRYPT_DATA, data);

        Key dkey = session.deriveKey(mechanism, key, keyTemplate);
        log.debug("derived key [can't read key value]");

        return new HsmKey_DDES(hsmVendor, session, dkey);
    }

    /**
     * Wraps the specified target key using the current key and a 3DES ECB mechanism.
     * <p>
     * This method uses the session to wrap the {@code targetKey} with the current key instance,
     * utilizing the DES3_ECB mechanism. The wrapped key is returned as a hexadecimal string.
     *
     * @param targetKey
     *            the {@link HsmKey} to be wrapped
     * @return the wrapped key as a hexadecimal string
     * @throws TokenException
     *             if an error occurs during the key wrapping process
     */
    @Override
    public String wrapKey(HsmKey targetKey) throws TokenException {
        log.debug("targetKey to derive: [can't read key value]");

        Mechanism mechanism = toMechanism(HsmMechanism.DES3_ECB);

        byte[] wrappedKey = session.wrapKey(mechanism, key, ((HsmKey_DDES) targetKey).key);
        String result = Util.byteArray2HexaString(wrappedKey);
        log.debug("wrapped result [{}]", result);

        return result;
    }

    /**
     * Creates a new HSM key using the provided hexadecimal string value.
     * <p>
     * This method converts the input hexadecimal string to a byte array,
     * initializes a DES2SecretKey template with appropriate attributes for
     * encryption, decryption, unwrapping, and signing, and then creates the
     * key object in the HSM session. The resulting key is wrapped in an
     * {@link HsmKey_DDES} instance.
     *
     * @param value
     *            the hexadecimal string representing the key value
     * @return a new {@link HsmKey_DDES} instance containing the created key
     * @throws TokenException
     *             if key creation fails in the HSM session
     */
    @Override
    public HsmKey createKey(String value) throws TokenException {
        log.debug("value to createKey: [{}]", value);
        byte[] keyValueByteArray = Util.hexaString2ByteArray(value);

        DES2SecretKey keyTemplate = new DES2SecretKey();
        keyTemplate.getToken().setBooleanValue(Boolean.FALSE);
        keyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        keyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        keyTemplate.getValue().setByteArrayValue(keyValueByteArray);
        DES2SecretKey dkey = (DES2SecretKey) session.createObject(keyTemplate);

        return new HsmKey_DDES(hsmVendor, session, dkey);
    }

    /**
     * Converts the specified {@link HsmMechanism} to a {@link Mechanism} using the default initial vector.
     *
     * @param hsmMechanism
     *            the HSM mechanism to convert
     * @return the corresponding {@link Mechanism} instance
     */
    private Mechanism toMechanism(HsmMechanism hsmMechanism) {
        return toMechanism(hsmMechanism, INITIAL_VECTOR);
    }

    /**
     * Converts the specified {@link HsmMechanism} and associated data into a {@link Mechanism} object,
     * using the appropriate parameters based on the mechanism type.
     * <p>
     * This method determines the vendor-specific mechanism using {@code hsmMechanism.getMechanism0(hsmVendor)},
     * then constructs the required {@link Parameters} instance depending on the mechanism:
     * <ul>
     * <li>For {@code DES3_CBC}, {@code DES3_X919_MAC_PTK}, and {@code DES3_X919_MAC_GENERAL_PTK},
     * an {@link InitializationVectorParameters} is created from the provided hex string data.</li>
     * <li>For {@code DES3_ECB_ENCRYPT_DATA} and {@code DES3_CBC_ENCRYPT_DATA},
     * a {@link KeyDerivationStringDataParameters} is created from the provided hex string data.</li>
     * <li>For other mechanisms, {@code null} is used as the parameter.</li>
     * </ul>
     *
     * @param hsmMechanism
     *            the high-level HSM mechanism to convert
     * @param data
     *            a hexadecimal string representing the parameter data required by the mechanism
     * @return a {@link Mechanism} instance configured with the appropriate parameters
     */
    private Mechanism toMechanism(HsmMechanism hsmMechanism, String data) {
        HsmVendorMechanism changedMechanism = hsmMechanism.getMechanism0(hsmVendor);

        Parameters param = switch (changedMechanism) {
            case DES3_CBC -> new InitializationVectorParameters(Util.hexaString2ByteArray(data));
            case DES3_ECB_ENCRYPT_DATA -> new KeyDerivationStringDataParameters(Util.hexaString2ByteArray(data));
            case DES3_CBC_ENCRYPT_DATA -> new KeyDerivationStringDataParameters(Util.hexaString2ByteArray(data));
            case DES3_X919_MAC_PTK -> new InitializationVectorParameters(Util.hexaString2ByteArray(data));
            case DES3_X919_MAC_GENERAL_PTK -> new InitializationVectorParameters(Util.hexaString2ByteArray(data));
            default -> null;
        };

        return changedMechanism.getMechanism(param);
    }
}
