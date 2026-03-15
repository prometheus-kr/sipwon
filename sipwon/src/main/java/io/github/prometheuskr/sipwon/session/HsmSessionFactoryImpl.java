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

    private final String tokenLabel;

    /**
     * Constructs a new {@code HsmSessionFactoryImpl} with the specified HSM module configuration.
     *
     * @param hsmModuleConfig
     *            the configuration object for the HSM module
     * @param tokenLabel
     *            the label of the token for which the HSM session is requested
     */
    public HsmSessionFactoryImpl(ModuleConfig hsmModuleConfig, String tokenLabel) {
        this.hsmModuleConfig = hsmModuleConfig;
        this.tokenLabel = tokenLabel;
        hsmModuleConfig.checkHsm();
    }

    /**
     * Retrieves an {@link HsmSession} associated with the specified token label.
     *
     * @return an {@link HsmSession} instance corresponding to the given token label
     * @throws TokenException
     *             if there is an error obtaining the HSM session
     */
    @Override
    public HsmSession getHsmSession() throws TokenException {
        return getHsmSession(null);
    }

    /**
     * Retrieves an {@link HsmSession} instance for the specified PIN.
     *
     * @param pin
     *            the PIN used to authenticate with the HSM token
     * @return an {@link HsmSession} associated with the given token and PIN
     * @throws TokenException
     *             if there is an error obtaining the HSM session
     */
    @Override
    public HsmSession getHsmSession(String pin) throws TokenException {
        return new HsmSessionImpl(hsmModuleConfig.getHsmSession(this.tokenLabel, pin), hsmModuleConfig.getHsmVendor());
    }
}
