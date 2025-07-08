package io.github.prometheuskr.sipwon.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Configuration properties for HSM (Hardware Security Module) integration.
 * <p>
 * Binds properties with the prefix <code>sipwon</code> from the application's configuration files.
 * <ul>
 * <li><b>pkcs11LibraryPath</b>: Path to the PKCS#11 library used for HSM operations.</li>
 * <li><b>tokenLabelAndPin</b>: List of token label and PIN pairs for accessing HSM tokens.</li>
 * <li><b>useCacheKey</b>: Flag indicating whether to cache keys retrieved from the HSM.</li>
 * </ul>
 * <p>
 * The nested {@link TokenPin} class represents a pair of token label and PIN required for authentication.
 */
@Data
@NoArgsConstructor
@ConfigurationProperties(prefix = "sipwon")
public class HsmProperties {
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
     * When set to {@code TRUE}, the application will attempt to retrieve and use a cached key
     * instead of generating or fetching a new one for each operation. This can improve performance,
     * but may have security implications depending on the use case.
     */
    private Boolean useCacheKey = Boolean.FALSE;

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
