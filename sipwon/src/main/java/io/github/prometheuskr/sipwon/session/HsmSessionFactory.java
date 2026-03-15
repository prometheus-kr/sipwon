package io.github.prometheuskr.sipwon.session;

import iaik.pkcs.pkcs11.TokenException;

/**
 * Factory interface for creating and managing HSM (Hardware Security Module) sessions.
 * <p>
 * Implementations of this interface are responsible for providing access to HSM sessions
 * based on token labels and optional PINs, as well as performing health checks on the HSM.
 */
public interface HsmSessionFactory {
    /**
     * Retrieves an {@link HsmSession} associated with the specified token label.
     *
     * @return an {@link HsmSession} instance corresponding to the given token label
     * @throws TokenException
     *             if there is an error obtaining the HSM session
     */
    HsmSession getHsmSession() throws TokenException;

    /**
     * Retrieves an {@link HsmSession} instance associated with the specified token label and PIN.
     *
     * @param pin
     *            the PIN used to authenticate with the HSM token
     * @return an {@link HsmSession} for the specified token and PIN
     * @throws TokenException
     *             if the session cannot be established or authentication fails
     */
    HsmSession getHsmSession(String pin) throws TokenException;
}