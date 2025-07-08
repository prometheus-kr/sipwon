package io.github.prometheuskr.sipwon.session;

import iaik.pkcs.pkcs11.TokenException;
import io.github.prometheuskr.sipwon.constant.HsmKeyType;
import io.github.prometheuskr.sipwon.key.HsmKey;

/**
 * Represents a session with a Hardware Security Module (HSM).
 * Provides methods to find and create HSM keys within the session context.
 * Implementations are responsible for managing the lifecycle of the session,
 * including resource cleanup via {@link #close()}.
 */
public interface HsmSession extends AutoCloseable {
    /**
     * Finds and retrieves an HSM key based on the specified key label and key type.
     *
     * @param keyLabel
     *            the label identifying the HSM key to find
     * @param keyType
     *            the type of the HSM key to find
     * @return the {@link HsmKey} matching the given label and type
     * @throws TokenException
     *             if an error occurs while accessing the HSM or if the key cannot be found
     */
    HsmKey findHsmKey(String keyLabel, HsmKeyType keyType) throws TokenException;

    /**
     * Creates a temporary HSM key of the specified type with the given value.
     *
     * @param keyType
     *            the type of the HSM key to create
     * @param value
     *            the value to be used for the temporary key
     * @return the created temporary {@link HsmKey}
     * @throws TokenException
     *             if an error occurs during key creation
     */
    HsmKey createTempHsmKey(HsmKeyType keyType, String value) throws TokenException;
}