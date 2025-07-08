package io.github.prometheuskr.sipwon.autoconfig;

import java.io.IOException;
import java.util.stream.Collectors;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import iaik.pkcs.pkcs11.TokenException;
import io.github.prometheuskr.sipwon.config.HsmProperties;
import io.github.prometheuskr.sipwon.session.HsmSessionFactory;
import io.github.prometheuskr.sipwon.session.HsmSessionFactoryImpl;
import io.github.prometheuskr.sipwon.session.ModuleConfig;

/**
 * Auto-configuration class for setting up the HSM (Hardware Security Module) session factory.
 * <p>
 * This configuration class is activated automatically and binds the {@link HsmProperties}
 * configuration properties. It provides a {@link HsmSessionFactory} bean, which is initialized
 * using the provided PKCS#11 library path, token labels, and PINs from the application properties.
 * <p>
 * If initialization of the HSM module configuration fails due to a {@link TokenException} or
 * {@link IOException}, a {@link RuntimeException} is thrown.
 * 
 * @author Prometheus
 */
@Configuration
@EnableConfigurationProperties(HsmProperties.class)
public class SipwonAutoConfiguration {

    /**
     * Creates and configures an {@link HsmSessionFactory} bean using the provided {@link HsmProperties}.
     * <p>
     * This method initializes the HSM module configuration by constructing a {@link ModuleConfig}
     * with the PKCS#11 library path, a map of token labels to PINs, and the cache key usage flag.
     * If initialization fails due to a {@link TokenException} or {@link IOException}, a {@link RuntimeException} is
     * thrown.
     * 
     * @param hsmProperties
     *            the HSM properties containing configuration details such as the PKCS#11 library path,
     *            token labels, PINs, and cache key usage flag
     * @return a configured {@link HsmSessionFactory} instance
     * @throws RuntimeException
     *             if the HSM module configuration fails to initialize
     */
    @Bean
    @ConditionalOnMissingBean(HsmSessionFactory.class)
    public HsmSessionFactory hsmSessionFactory(HsmProperties hsmProperties) {
        try {
            ModuleConfig moduleConfig = new ModuleConfig(hsmProperties.getPkcs11LibraryPath(),
                    hsmProperties.getTokenLabelAndPin().stream()
                            .collect(Collectors.toMap(
                                    HsmProperties.TokenPin::getTokenLabel,
                                    HsmProperties.TokenPin::getPin)),
                    hsmProperties.getUseCacheKey());
            return new HsmSessionFactoryImpl(moduleConfig);
        } catch (TokenException | IOException e) {
            throw new RuntimeException("Failed to initialize HSM module configuration", e);
        }
    }
}