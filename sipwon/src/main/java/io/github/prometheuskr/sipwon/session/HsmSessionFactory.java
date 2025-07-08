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
     * @param tokenLabel
     *            the label of the token for which the HSM session is requested
     * @return an {@link HsmSession} instance corresponding to the given token label
     * @throws TokenException
     *             if there is an error obtaining the HSM session
     */
    HsmSession getHsmSession(String tokenLabel) throws TokenException;

    /**
     * Retrieves an {@link HsmSession} instance associated with the specified token label and PIN.
     *
     * @param tokenLabel
     *            the label of the HSM token to connect to
     * @param pin
     *            the PIN used to authenticate with the HSM token
     * @return an {@link HsmSession} for the specified token and PIN
     * @throws TokenException
     *             if the session cannot be established or authentication fails
     */
    HsmSession getHsmSession(String tokenLabel, String pin) throws TokenException;

    /**
     * Checks the status or availability of the HSM (Hardware Security Module).
     * <p>
     * This method should perform necessary validation or health checks to ensure
     * that the HSM is operational and ready for use. Implementations may throw
     * exceptions if the HSM is not accessible or if any issues are detected.
     */
    void checkHsm();
}