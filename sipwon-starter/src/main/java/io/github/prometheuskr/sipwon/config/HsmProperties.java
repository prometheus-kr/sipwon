package io.github.prometheuskr.sipwon.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Configuration properties for HSM (Hardware Security Module) integration.
 * <p>
 * Binds properties with the prefix <code>sipwon</code> from the application's configuration files.
 * Supports multiple HSM configurations through the <code>configs</code> map.
 * <p>
 * Example configuration:
 * 
 * <pre>
 * sipwon:
 *   configs:
 *     hsm1:
 *       pkcs11-library-path: /path/to/hsm1/library.so
 *       token-label-and-pin:
 *         - token-label: token1
 *           pin: 1234
 *       use-cache-key: false
 * </pre>
 * 
 * @author Prometheus
 */
@Data
@NoArgsConstructor
@ConfigurationProperties(prefix = "sipwon")
public class HsmProperties {
    /**
     * Map of HSM configurations. Each key is the configuration name, and the value contains
     * PKCS#11 library path, token label and PIN pairs, and cache key settings.
     */
    private Map<String, HsmConfig> configs = new HashMap<>();

    /**
     * Individual HSM configuration containing all necessary settings for a single HSM device.
     * <p>
     * Each configuration consists of:
     * <ul>
     * <li>A PKCS#11 library path - the native library for HSM communication</li>
     * <li>Token label and PIN pairs - authentication credentials for HSM tokens</li>
     * <li>Cache key setting - performance optimization option</li>
     * </ul>
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class HsmConfig {
        /**
         * The file system path to the PKCS#11 library used for hardware security module (HSM) integration.
         * This property specifies the location of the native library required to interface with the HSM device.
         */
        private String pkcs11LibraryPath;
        /**
         * A list containing {@link TokenPin} objects, each representing a mapping between
         * a token label and its corresponding PIN. This list is used to store and manage
         * multiple token label and PIN pairs for secure access to tokens.
         */
        private List<TokenPin> tokenLabelAndPin = new ArrayList<>();
        /**
         * Indicates whether to use a cached key for HSM (Hardware Security Module) operations.
         * <p>
         * When set to {@code true}, the application will cache cryptographic keys to improve
         * performance by avoiding repeated key retrieval operations from the HSM device.
         * When set to {@code false} (default), keys are retrieved from the HSM for each operation.
         * <p>
         * <strong>Note:</strong> Enabling key caching can improve performance but may have
         * security implications. Ensure this aligns with your security requirements.
         */
        private Boolean useCacheKey = Boolean.FALSE;
    }

    /**
     * Represents the PIN information associated with a specific token.
     * <p>
     * This class holds the label of the token and its corresponding PIN,
     * typically used for authentication or secure access to hardware security modules (HSM).
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TokenPin {
        /**
         * The label used to identify the token within the HSM (Hardware Security Module).
         * This is typically used to select or reference a specific token for cryptographic operations.
         */
        private String tokenLabel;
        /**
         * The PIN (Personal Identification Number) used for authentication or security purposes.
         */
        private String pin;
    }
}
