package io.github.prometheuskr.sipwon.key;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.DES3SecretKey;
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
 * Implementation of the {@link HsmKey} interface for Triple DES (TDES/3DES) cryptographic operations
 * using a Hardware Security Module (HSM).
 * <p>
 * This class encapsulates a TDES secret key and provides methods for encryption, decryption,
 * message authentication code (MAC) generation, key derivation, key wrapping, and key creation,
 * all performed within the secure environment of an HSM. It supports various HSM mechanisms and
 * vendor-specific configurations.
 * <p>
 * Key features:
 * <ul>
 * <li>Encrypts and decrypts data using TDES and specified HSM mechanisms.</li>
 * <li>Generates MACs for data integrity and authentication.</li>
 * <li>Derives new TDES keys from existing keys and input data.</li>
 * <li>Wraps and unwraps keys securely for transport or storage.</li>
 * <li>Creates new TDES keys in the HSM from provided values.</li>
 * <li>Handles mechanism parameterization based on HSM vendor and operation type.</li>
 * </ul>
 * <p>
 * This class is intended for use in environments where cryptographic key material must remain
 * protected within an HSM, and where operations must comply with security and compliance requirements.
 *
 * @author PrometheusKR
 */
@Slf4j
public class HsmKey_TDES implements HsmKey {
    /**
     * The initial vector (IV) used for cryptographic operations, represented as a 16-character string of zeros.
     * This is typically used in block cipher modes that require an IV, such as CBC mode.
     * The value "0000000000000000" ensures a predictable and consistent IV for encryption and decryption processes.
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
     * The Triple DES (3DES) secret key used for cryptographic operations.
     * This key is immutable and securely stored within the class.
     */
    private final DES3SecretKey key;

    /**
     * Constructs an instance of {@code HsmKey_TDES} with the specified HSM vendor, session, and key.
     *
     * @param hsmVendor
     *            the HSM vendor implementation to be used
     * @param session
     *            the session associated with the HSM
     * @param key
     *            the cryptographic key, expected to be an instance of {@code DES3SecretKey}
     */
    HsmKey_TDES(HsmVendor hsmVendor, Session session, Key key) {
        this.hsmVendor = hsmVendor;
        this.session = session;
        this.key = (DES3SecretKey) key;
    }

    /**
     * Encrypts the provided hexadecimal string data using the specified HSM mechanism.
     * <p>
     * This method initializes the encryption operation with the given mechanism and key,
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
     *            the hexadecimal string representing the encrypted data to be decrypted
     * @param hsmMechanism
     *            the HSM mechanism to use for decryption
     * @return the decrypted data as a hexadecimal string
     * @throws TokenException
     *             if an error occurs during the decryption process
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
     * signs the input data, and returns the first 8 characters of the resulting signature
     * as a hexadecimal string. The input data is expected to be a hexadecimal string.
     *
     * @param data
     *            the input data to be signed, represented as a hexadecimal string
     * @param hsmMechanism
     *            the HSM mechanism to use for signing
     * @return the first 8 characters of the MAC as a hexadecimal string
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
     * Derives a new TDES (Triple DES) key from the current key using the provided data.
     * <p>
     * This method creates a key template with specific attributes for encryption, decryption,
     * signing, and derivation. It then constructs a mechanism using the provided data and
     * derives a new key using the current session and key. The derived key is returned as
     * a new {@link HsmKey_TDES} instance.
     * 
     * @param data
     *            the data used for key derivation, typically as input to the mechanism
     * @return a new {@link HsmKey_TDES} instance representing the derived key
     * @throws TokenException
     *             if key derivation fails or a token-related error occurs
     */
    @Override
    public HsmKey derive(String data) throws TokenException {
        log.debug("data to derive: [{}]", data);

        DES3SecretKey keyTemplate = new DES3SecretKey();
        keyTemplate.getToken().setBooleanValue(Boolean.FALSE);
        keyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDerive().setBooleanValue(Boolean.TRUE);

        Mechanism mech = toMechanism(HsmMechanism.DES3_ECB_ENCRYPT_DATA, data);

        Key dkey = session.deriveKey(mech, key, keyTemplate);
        log.debug("derived key [can't read key value]");

        return new HsmKey_TDES(hsmVendor, session, dkey);
    }

    /**
     * Wraps the specified target key using the current TDES key and returns the wrapped key as a hexadecimal string.
     * <p>
     * This method uses the DES3_ECB mechanism to wrap the provided {@code targetKey}. The wrapped key is returned
     * as a hexadecimal string representation. The actual key value of the target key is not logged for security
     * reasons.
     *
     * @param targetKey
     *            the {@link HsmKey} to be wrapped; must be an instance of {@link HsmKey_TDES}
     * @return the wrapped key as a hexadecimal string
     * @throws TokenException
     *             if an error occurs during the key wrapping process
     */
    @Override
    public String wrapKey(HsmKey targetKey) throws TokenException {
        log.debug("targetKey to wrap: [can't read key value]");

        Mechanism mechanism = toMechanism(HsmMechanism.DES3_ECB);

        byte[] wrappedKey = session.wrapKey(mechanism, key, ((HsmKey_TDES) targetKey).key);
        String result = Util.byteArray2HexaString(wrappedKey);
        log.debug("wrapped result [{}]", result);

        return result;
    }

    /**
     * Creates a new TDES (Triple DES) HSM key using the provided hexadecimal string value.
     * <p>
     * This method converts the input hexadecimal string to a byte array and initializes
     * a DES3SecretKey template with appropriate attributes for encryption, decryption,
     * unwrapping, and signing. The key is then created in the HSM session and wrapped
     * in an {@link HsmKey_TDES} instance.
     * 
     * @param value
     *            the hexadecimal string representing the key value
     * @return a new {@link HsmKey_TDES} instance containing the created key
     * @throws TokenException
     *             if an error occurs during key creation in the HSM
     */
    @Override
    public HsmKey createKey(String value) throws TokenException {
        log.debug("value to createKey: [{}]", value);
        byte[] keyValueByteArray = Util.hexaString2ByteArray(value);

        DES3SecretKey keyTemplate = new DES3SecretKey();
        keyTemplate.getToken().setBooleanValue(Boolean.FALSE);
        keyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        keyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        keyTemplate.getValue().setByteArrayValue(keyValueByteArray);
        DES3SecretKey dkey = (DES3SecretKey) session.createObject(keyTemplate);

        return new HsmKey_TDES(hsmVendor, session, dkey);
    }

    /**
     * Converts the specified {@link HsmMechanism} to a {@link Mechanism} using the default
     * DES initial vector.
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
     * This method determines the vendor-specific mechanism using {@code hsmVendor}, then selects
     * the correct parameter type for the mechanism. Supported mechanisms include DES3_CBC, DES3_ECB_ENCRYPT_DATA,
     * DES3_CBC_ENCRYPT_DATA, DES3_X919_MAC_PTK, and DES3_X919_MAC_GENERAL_PTK. The data string is expected
     * to be a hexadecimal string and is converted to a byte array for parameter construction.
     *
     * @param hsmMechanism
     *            the high-level HSM mechanism to convert
     * @param data
     *            the hexadecimal string data used to construct mechanism parameters
     * @return the constructed {@link Mechanism} with the appropriate parameters
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
