package io.github.prometheuskr.sipwon.autoconfig;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.github.prometheuskr.sipwon.config.HsmProperties;

/**
 * Auto-configuration class for setting up the HSM (Hardware Security Module) session factories.
 * <p>
 * This configuration class is activated automatically and binds the {@link HsmProperties}
 * configuration properties. It creates a {@link HsmSessionFactoryRegistry} that manages
 * multiple HSM session factories with token label-based lookup and round-robin load balancing.
 * 
 * @author Prometheus
 */
@Configuration
@EnableConfigurationProperties(HsmProperties.class)
public class SipwonAutoConfiguration {

    /**
     * Creates a {@link HsmSessionFactoryRegistry} that provides token label-based lookup
     * of HSM session factories with round-robin load balancing.
     * <p>
     * The registry internally creates and manages all HSM session factories based on the
     * configuration properties. It maps token labels to their corresponding factories and
     * distributes requests across them using a round-robin strategy when multiple factories
     * support the same token label.
     * 
     * @param hsmProperties
     *            the HSM properties containing multiple named HSM configurations
     * @return a registry for token label-based factory lookup
     * @throws IllegalArgumentException
     *             if duplicate pkcs11-library-path is detected
     * @throws RuntimeException
     *             if any HSM module configuration fails to initialize
     */
    @Bean
    public HsmSessionFactoryRegistry hsmSessionFactoryRegistry(HsmProperties hsmProperties) {
        return new HsmSessionFactoryRegistry(hsmProperties);
    }
}