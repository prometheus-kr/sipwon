package io.github.prometheuskr.sipwon.session;

import iaik.pkcs.pkcs11.TokenException;

/**
 * Implementation of the {@link HsmSessionFactory} interface that provides methods to create and manage HSM sessions.
 * <p>
 * This class uses a {@link ModuleConfig} instance to interact with the underlying HSM module and vendor.
 * <p>
 * Main responsibilities:
 * <ul>
 * <li>Obtain {@link HsmSession} instances for a given token label and optional PIN.</li>
 * <li>Delegate HSM health checks to the configured module.</li>
 * </ul>
 */
public class HsmSessionFactoryImpl implements HsmSessionFactory {
    /**
     * Configuration object for the HSM (Hardware Security Module) module.
     * Holds settings and parameters required to initialize and manage HSM sessions.
     */
    private final ModuleConfig hsmModuleConfig;

    /**
     * Constructs a new {@code HsmSessionFactoryImpl} with the specified HSM module configuration.
     *
     * @param hsmModuleConfig
     *            the configuration object for the HSM module
     */
    public HsmSessionFactoryImpl(ModuleConfig hsmModuleConfig) {
        this.hsmModuleConfig = hsmModuleConfig;
    }

    /**
     * Retrieves an {@link HsmSession} associated with the specified token label.
     *
     * @param tokenLabel
     *            the label of the token for which the HSM session is requested
     * @return an {@link HsmSession} instance corresponding to the given token label
     * @throws TokenException
     *             if there is an error obtaining the HSM session
     */
    @Override
    public HsmSession getHsmSession(String tokenLabel) throws TokenException {
        return getHsmSession(tokenLabel, null);
    }

    /**
     * Retrieves an {@link HsmSession} instance for the specified token label and PIN.
     *
     * @param tokenLabel
     *            the label of the HSM token to connect to
     * @param pin
     *            the PIN used to authenticate with the HSM token
     * @return an {@link HsmSession} associated with the given token and PIN
     * @throws TokenException
     *             if there is an error obtaining the HSM session
     */
    @Override
    public HsmSession getHsmSession(String tokenLabel, String pin) throws TokenException {
        return new HsmSessionImpl(hsmModuleConfig.getHsmSession(tokenLabel, pin), hsmModuleConfig.getHsmVendor());
    }

    /**
     * Checks the status or availability of the HSM (Hardware Security Module) by delegating
     * the operation to the configured {@code hsmModuleConfig}. This method ensures that the
     * HSM is properly initialized and ready for cryptographic operations.
     */
    @Override
    public void checkHsm() {
        hsmModuleConfig.checkHsm();
    }
}
