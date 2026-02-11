package io.github.prometheuskr.sipwon.autoconfig;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import iaik.pkcs.pkcs11.TokenException;
import io.github.prometheuskr.sipwon.config.HsmProperties;
import io.github.prometheuskr.sipwon.session.HsmSessionFactory;
import io.github.prometheuskr.sipwon.session.HsmSessionFactoryImpl;
import io.github.prometheuskr.sipwon.session.ModuleConfig;

/**
 * Registry for managing HSM session factories with token label-based lookup and round-robin load balancing.
 * <p>
 * This class provides a mechanism to retrieve {@link HsmSessionFactory} instances by token label.
 * When multiple factories support the same token label, it distributes requests across them
 * using a round-robin strategy for load balancing.
 * 
 * @author Prometheus
 */
public class HsmSessionFactoryRegistry {

    private final Map<String, List<HsmSessionFactory>> tokenLabelToFactories;
    private final Map<String, AtomicInteger> tokenLabelToRoundRobinIndex;

    /**
     * Creates a new registry instance and initializes all HSM session factories
     * from the provided configuration properties.
     * 
     * @param hsmProperties
     *            the HSM properties containing multiple named HSM configurations
     * @throws IllegalArgumentException
     *             if duplicate pkcs11-library-path is detected
     * @throws RuntimeException
     *             if any HSM module configuration fails to initialize
     */
    public HsmSessionFactoryRegistry(HsmProperties hsmProperties) {
        this.tokenLabelToFactories = new HashMap<>();
        this.tokenLabelToRoundRobinIndex = new ConcurrentHashMap<>();

        initializeFactories(hsmProperties);
    }

    /**
     * Initializes HSM session factories from the configuration properties.
     * 
     * @param hsmProperties
     *            the HSM properties containing multiple named HSM configurations
     * @throws IllegalArgumentException
     *             if duplicate pkcs11-library-path is detected
     * @throws RuntimeException
     *             if any HSM module configuration fails to initialize
     */
    private void initializeFactories(HsmProperties hsmProperties) {
        Map<String, String> pkcs11PathToConfigName = new HashMap<>();

        hsmProperties.getConfigs().forEach((name, config) -> {
            String pkcs11LibraryPath = config.getPkcs11LibraryPath();

            // Check for duplicate pkcs11-library-path
            if (pkcs11LibraryPath != null) {
                String existingConfigName = pkcs11PathToConfigName.get(pkcs11LibraryPath);
                if (existingConfigName != null) {
                    throw new IllegalArgumentException(
                            String.format(
                                    "Duplicate pkcs11-library-path detected: '%s' is used in both '%s' and '%s' configurations",
                                    pkcs11LibraryPath, existingConfigName, name));
                }
                pkcs11PathToConfigName.put(pkcs11LibraryPath, name);
            }

            try {
                // Create ModuleConfig and HsmSessionFactory
                ModuleConfig moduleConfig = new ModuleConfig(
                        pkcs11LibraryPath,
                        config.getTokenLabelAndPin().stream()
                                .collect(Collectors.toMap(
                                        HsmProperties.TokenPin::getTokenLabel,
                                        HsmProperties.TokenPin::getPin)),
                        config.getUseCacheKey());
                HsmSessionFactory factory = new HsmSessionFactoryImpl(moduleConfig);

                // Store factory by name
                List<String> tokenLabels = config.getTokenLabelAndPin().stream()
                        .map(HsmProperties.TokenPin::getTokenLabel)
                        .collect(Collectors.toList());
                registerFactory(tokenLabels, factory);

            } catch (TokenException | IOException e) {
                throw new RuntimeException(
                        "Failed to initialize HSM module configuration for: " + name, e);
            }
        });
    }

    /**
     * Registers a factory for the specified token labels.
     * 
     * @param tokenLabels
     *            the list of token labels supported by this factory
     * @param factory
     *            the HSM session factory to register
     */
    private void registerFactory(List<String> tokenLabels, HsmSessionFactory factory) {
        for (String tokenLabel : tokenLabels) {
            tokenLabelToFactories.computeIfAbsent(tokenLabel, k -> new ArrayList<>()).add(factory);
        }
    }

    /**
     * Retrieves an HSM session factory for the specified token label using round-robin selection.
     * <p>
     * If multiple factories support the same token label, this method distributes requests
     * across them in a round-robin fashion to balance the load.
     * 
     * @param tokenLabel
     *            the token label to look up
     * @return an HSM session factory supporting the specified token label
     * @throws IllegalArgumentException
     *             if no factory is found for the given token label
     */
    public HsmSessionFactory getFactory(String tokenLabel) {
        List<HsmSessionFactory> factories = tokenLabelToFactories.get(tokenLabel);
        if (factories == null || factories.isEmpty()) {
            throw new IllegalArgumentException(
                    "No HSM session factory found for token label: " + tokenLabel);
        }

        if (factories.size() == 1) {
            return factories.get(0);
        }

        // Round-robin selection for multiple factories
        AtomicInteger index = tokenLabelToRoundRobinIndex.computeIfAbsent(
                tokenLabel, k -> new AtomicInteger(0));
        int currentIndex = index.getAndIncrement() % factories.size();
        return factories.get(currentIndex);
    }
}
