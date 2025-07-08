package io.github.prometheuskr.sipwon.key;

import iaik.pkcs.pkcs11.TokenException;
import io.github.prometheuskr.sipwon.constant.HsmMechanism;

/**
 * Represents a cryptographic key managed by a Hardware Security Module (HSM).
 * Provides methods for encryption, decryption, MAC generation, key derivation,
 * key wrapping, and key creation using specified HSM mechanisms.
 */
public interface HsmKey {
    /**
     * Encrypts the given data using the specified HSM mechanism.
     *
     * @param data
     *            the plaintext data to be encrypted
     * @param hsmMechanism
     *            the cryptographic mechanism to use for encryption
     * @return the encrypted data as a String
     * @throws TokenException
     *             if an error occurs during the encryption process
     */
    String encrypt(String data, HsmMechanism hsmMechanism) throws TokenException;

    /**
     * Decrypts the provided encrypted data using the specified HSM mechanism.
     *
     * @param data
     *            the encrypted data to be decrypted, represented as a String
     * @param hsmMechanism
     *            the mechanism to use for decryption, provided by the HSM
     * @return the decrypted data as a String
     * @throws TokenException
     *             if an error occurs during the decryption process
     */
    String decrypt(String data, HsmMechanism hsmMechanism) throws TokenException;

    /**
     * Generates a Message Authentication Code (MAC) for the given data using the specified HSM mechanism.
     *
     * @param data
     *            the input data to be authenticated
     * @param hsmMechanism
     *            the cryptographic mechanism to use for MAC generation
     * @return the generated MAC as a string
     * @throws TokenException
     *             if an error occurs during MAC generation
     */
    String mac(String data, HsmMechanism hsmMechanism) throws TokenException;

    /**
     * Derives a new {@code HsmKey} instance based on the provided data.
     *
     * @param data
     *            the input data used for key derivation
     * @return a new {@code HsmKey} derived from the input data
     * @throws TokenException
     *             if the key derivation process fails
     */
    HsmKey derive(String data) throws TokenException;

    /**
     * Wraps the specified target key using this HSM key.
     *
     * @param targetKey
     *            the {@link HsmKey} to be wrapped
     * @return a {@link String} representing the wrapped key
     * @throws TokenException
     *             if an error occurs during the key wrapping process
     */
    String wrapKey(HsmKey targetKey) throws TokenException;

    /**
     * Creates a new HSM (Hardware Security Module) key using the provided value.
     *
     * @param value
     *            the value to be used for key creation
     * @return the created {@link HsmKey} instance
     * @throws TokenException
     *             if an error occurs during key creation
     */
    HsmKey createKey(String value) throws TokenException;
}
