package io.github.prometheuskr.sipwon.session;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.SlotInfo;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.objects.Key;
import io.github.prometheuskr.sipwon.constant.HsmVendor;
import io.github.prometheuskr.sipwon.util.Util;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

/**
 * ModuleConfig is responsible for managing the configuration and caching of HSM (Hardware Security Module) tokens and
 * keys.
 * It handles the initialization of the PKCS#11 module, maintains token and key caches, and provides session management
 * with load balancing across available tokens. The class also supports health checking of the HSM and automatic cache
 * rebuilding.
 * <p>
 * Main responsibilities:
 * <ul>
 * <li>Initialize and manage the PKCS#11 module and vendor information.</li>
 * <li>Cache tokens and keys for efficient access, with optional key caching.</li>
 * <li>Provide thread-safe access to HSM sessions, supporting load balancing for tokens with the same label.</li>
 * <li>Perform periodic health checks on the HSM and rebuild caches as needed.</li>
 * </ul>
 * <p>
 * Key Components:
 * <ul>
 * <li>{@code Module} and {@code HsmVendor}: Represent the PKCS#11 module and its vendor.</li>
 * <li>{@code pinByTokenLabel}: Maps token labels to their corresponding PINs.</li>
 * <li>{@code tokenAndInfoListByTokenLabel}: Caches lists of tokens and their info, grouped by label.</li>
 * <li>{@code tokenAndKeyListByKeyClassNameAndKeyLabel}: Caches keys found on tokens, grouped by key class and
 * label.</li>
 * <li>{@code useCacheKey}: Indicates whether key caching is enabled.</li>
 * </ul>
 * <p>
 * Usage:
 * <ul>
 * <li>Instantiate with the PKCS#11 library path, token label-to-PIN map, and cache key flag.</li>
 * <li>Use {@code getHsmSession} to obtain a session for a specific token label and PIN.</li>
 * <li>Call {@code checkHsm} to start background health checking of the HSM.</li>
 * </ul>
 * <p>
 * Thread Safety:
 * <ul>
 * <li>Uses concurrent collections for caches to ensure thread-safe access.</li>
 * <li>Health check and cache rebuild operations are synchronized to prevent race conditions.</li>
 * </ul>
 * <p>
 * Exceptions:
 * <ul>
 * <li>Throws {@code TokenException} for PKCS#11 errors.</li>
 * <li>Throws {@code IOException} for module initialization errors.</li>
 * <li>Throws {@code IllegalArgumentException} if a requested token label is not found.</li>
 * </ul>
 */
@Slf4j
public class ModuleConfig {

    /**
     * The {@code module} instance associated with this configuration.
     * Represents the specific module for which the configuration is applied.
     */
    private final Module module;
    /**
     * The vendor of the Hardware Security Module (HSM) used in this module configuration.
     * This field specifies which HSM implementation is being utilized.
     */
    private final HsmVendor hsmVendor;
    /**
     * A mapping of token labels to their corresponding PINs.
     * The key represents the token label, and the value is the associated PIN as a string.
     * This map is used to securely store and retrieve PINs for different tokens by their labels.
     */
    private final Map<String, String> pinByTokenLabel;
    /**
     * Indicates whether a cache key should be used for caching operations.
     * When set to {@code true}, caching mechanisms will utilize a specific cache key.
     */
    private final boolean useCacheKey;
    /**
     * A thread-safe map that associates a token label (as a String) with an {@link AtomicInteger} index.
     * This is used to keep track of the current index or position for each token label in a concurrent environment.
     * The use of {@link ConcurrentHashMap} ensures safe access and updates from multiple threads,
     * while {@link AtomicInteger} allows atomic increment and retrieval of the index value per token label.
     */
    private final Map<String, AtomicInteger> listIndexByTokenLabel = new ConcurrentHashMap<>();
    /**
     * A thread-safe map that associates a token label (as a {@link String}) with a list of {@link TokenAndInfo}
     * objects.
     * <p>
     * This map is used to efficiently store and retrieve collections of token-related information grouped by their
     * labels.
     * The use of {@link ConcurrentHashMap} ensures safe concurrent access and modification in multi-threaded
     * environments.
     */
    private final Map<String, List<TokenAndInfo>> tokenAndInfoListByTokenLabel = new ConcurrentHashMap<>();
    /**
     * A thread-safe map that organizes {@link TokenAndKeyList} instances by key class name and key label.
     * <p>
     * The outer map uses the key class name as its key, mapping to an inner map.
     * The inner map uses the key label as its key, mapping to the corresponding {@link TokenAndKeyList}.
     * This structure allows efficient retrieval of token and key lists based on both class name and label.
     */
    private final Map<String, Map<String, TokenAndKeyList>> tokenAndKeyListByKeyClassNameAndKeyLabel = new ConcurrentHashMap<>();

    /**
     * Represents a combination of a {@link Token} and its associated {@link TokenInfo}.
     * <p>
     * This class provides convenient access to both the token object and its metadata,
     * such as the label of the token.
     */
    @Data
    static class TokenAndInfo {
        /**
         * The {@code Token} instance associated with this module configuration.
         * Used for authentication or authorization purposes within the session.
         */
        private final Token token;
        /**
         * Holds information about the authentication token associated with the session.
         */
        private final TokenInfo tokenInfo;

        /**
         * Retrieves the label associated with the token, with leading and trailing whitespace removed.
         *
         * @return the trimmed label of the token
         */
        public String getTokenLabel() {
            return tokenInfo.getLabel().trim();
        }
    }

    /**
     * Represents a container for a {@link Token} and its associated list of {@link Key} objects.
     * <p>
     * This class holds a single token and a mutable list of keys related to that token.
     * <p>
     * The {@code keyList} is initialized as an empty {@link ArrayList}.
     */
    @Data
    static class TokenAndKeyList {
        /**
         * The {@code token} used for authentication or authorization within the session module.
         * This is a final reference to a {@link Token} object, ensuring its immutability after initialization.
         */
        private final Token token;
        /**
         * A list that stores {@link Key} objects associated with this module configuration.
         * This list is initialized as an empty {@link ArrayList}.
         */
        private final List<Key> keyList = new ArrayList<>();
    }

    /**
     * Constructs a new {@code ModuleConfig} instance with the specified PKCS#11 library path,
     * a mapping of token labels to PINs, and a flag indicating whether to use a cached key.
     * <p>
     * This constructor initializes the HSM vendor and module using the provided library path,
     * sets up the PIN mapping, and builds the cache as needed.
     *
     * @param pkcs11LibraryPath
     *            the file system path to the PKCS#11 library
     * @param pinByTokenLabel
     *            a map associating token labels with their corresponding PINs
     * @param useCacheKey
     *            {@code true} to enable key caching; {@code false} otherwise
     * @throws TokenException
     *             if there is an error interacting with the token or HSM
     * @throws IOException
     *             if an I/O error occurs during initialization
     */
    public ModuleConfig(String pkcs11LibraryPath, Map<String, String> pinByTokenLabel, boolean useCacheKey)
            throws TokenException, IOException {
        this.useCacheKey = useCacheKey;
        this.pinByTokenLabel = pinByTokenLabel;
        this.hsmVendor = ModuleHelper.getHsmVendor(pkcs11LibraryPath);
        this.module = ModuleHelper.buildModule(pkcs11LibraryPath);
        buildCache();
    }

    /**
     * Retrieves the configured HSM (Hardware Security Module) vendor.
     *
     * @return the {@link HsmVendor} currently set for this module configuration
     */
    HsmVendor getHsmVendor() {
        return hsmVendor;
    }

    /**
     * Retrieves an HSM session for the specified token label and PIN.
     * <p>
     * This method looks up the list of tokens associated with the given token label,
     * applies a load balancing strategy to select a token, and then opens a session
     * using the provided PIN.
     *
     * @param tokenLabel
     *            the label of the token to retrieve the session for
     * @param pin
     *            the PIN to authenticate with the token
     * @return a {@link Session} object representing the opened HSM session
     * @throws TokenException
     *             if there is an error opening the session with the token
     * @throws IllegalArgumentException
     *             if no token is found for the specified label
     */
    Session getHsmSession(String tokenLabel, String pin) throws TokenException {
        List<TokenAndInfo> tokenAndInfoList = tokenAndInfoListByTokenLabel.get(tokenLabel);
        if (tokenAndInfoList == null || tokenAndInfoList.isEmpty()) {
            throw new IllegalArgumentException("No token found for label: " + tokenLabel);
        }

        int index = loadBalancing(tokenLabel);
        return openSessionHsm(tokenAndInfoList.get(index), pin);
    }

    /**
     * Returns the index for load balancing based on the given token label.
     * This method retrieves the list of tokens associated with the specified token label,
     * determines its size, and uses an atomic integer to keep track of the current index
     * for that label. It increments the index atomically and returns the next index in a
     * round-robin fashion, ensuring thread safety and even distribution.
     *
     * @param tokenLabel
     *            the label used to identify the token list and index tracker
     * @return the next index for load balancing, in the range [0, size)
     */
    private int loadBalancing(String tokenLabel) {
        int size = tokenAndInfoListByTokenLabel.get(tokenLabel).size();
        AtomicInteger aInt = listIndexByTokenLabel.computeIfAbsent(tokenLabel, k -> new AtomicInteger(0));
        return Math.abs(aInt.getAndIncrement() % size);
    }

    /**
     * Opens a session with a Hardware Security Module (HSM) using the provided token information and PIN.
     * <p>
     * If the provided PIN is {@code null}, the method retrieves the PIN associated with the token label
     * from the {@code pinByTokenLabel} map.
     *
     * @param tokenAndInfo
     *            the token and its associated information required to open the session
     * @param pin
     *            the PIN to use for authentication; if {@code null}, the PIN is looked up by token label
     * @return a {@link Session} object representing the opened session with the HSM
     * @throws TokenException
     *             if an error occurs while opening the session
     */
    private Session openSessionHsm(TokenAndInfo tokenAndInfo, String pin) throws TokenException {
        return ModuleHelper.openSession(
                tokenAndInfo.getToken(),
                pin == null ? pinByTokenLabel.get(tokenAndInfo.getTokenLabel()) : pin);
    }

    /**
     * Initiates a health check for the HSM (Hardware Security Module) by starting a new thread.
     * The health check logic is executed in the {@code doHealthCheck} method, running in a separate thread
     * named "HsmHealthCheckSignalThread" to avoid blocking the main execution flow.
     */
    void checkHsm() {
        new Thread(this::doHealthCheck, "HsmHealthCheckSignalThread").start();
    }

    /**
     * Periodically performs a health check on the HSM (Hardware Security Module) by attempting to initialize
     * the module, build the cache, and open/close a session. If the health check fails, it logs the error,
     * finalizes the module, clears the cache, and increases the backoff time up to a maximum limit.
     * The method runs indefinitely in a loop, with a backoff delay between each check.
     * <p>
     * The backoff starts at 10 seconds and increases by 10 seconds on each failure, up to a maximum of 60 seconds.
     * On success, the backoff resets to 10 seconds.
     * <p>
     * This method is intended to be run in a background thread to continuously monitor the health of the HSM.
     */
    private void doHealthCheck() {
        final int maxBackoff = 60_000;
        while (true) {
            int backoff = 10_000;
            Util.sleep(backoff);

            synchronized (this) {
                try {
                    ModuleHelper.initialize(module);
                    buildCache();
                    String tokenLabel = pinByTokenLabel.keySet().stream()
                            .findFirst()
                            .orElseThrow(() -> new RuntimeException("No token label found"));
                    Session session = getHsmSession(tokenLabel, null);
                    ModuleHelper.closeSession(session);
                    backoff = 10_000;
                } catch (Exception e) {
                    log.error("HSM Health Check failed: {}", e.getMessage(), e);
                    ModuleHelper.finalize(module);
                    clearCache();
                    backoff = Math.min(backoff + 10_000, maxBackoff);
                }
            }
        }
    }

    /**
     * Clears all cached token and key information by removing all entries from
     * the internal cache maps. This method should be called to reset or refresh
     * the cache when the underlying data changes or needs to be invalidated.
     */
    private void clearCache() {
        tokenAndInfoListByTokenLabel.clear();
        tokenAndKeyListByKeyClassNameAndKeyLabel.clear();
    }

    /**
     * Builds and initializes the cache for token and key information if it has not already been populated.
     * <p>
     * This method checks if the {@code tokenAndInfoListByTokenLabel} cache is empty.
     * If it is, it proceeds to populate the cache by invoking {@link #cacheToken()} and {@link #cacheKey()}.
     * If the cache is already populated, the method returns immediately.
     *
     * @throws TokenException
     *             if an error occurs during the caching process.
     */
    private void buildCache() throws TokenException {
        if (!tokenAndInfoListByTokenLabel.isEmpty())
            return;

        cacheToken();
        cacheKey();
    }

    /**
     * Caches token information for the current module by retrieving the slot list and checking each token and its
     * associated information.
     * Logs the resulting mapping of token labels to their information.
     *
     * @throws TokenException
     *             if an error occurs while processing tokens.
     */
    private void cacheToken() throws TokenException {
        ModuleHelper.getSlotList(module).forEach(this::checkTokenAndInfo);
        log.info("tokenAndInfoListByTokenLabel: {}", tokenAndInfoListByTokenLabel);
    }

    /**
     * Checks the provided {@link Slot} for a valid {@link Token} and its associated information.
     * <p>
     * Logs details about the slot, slot info, and token info if available. If a token is present and its label
     * exists in the {@code pinByTokenLabel} map, adds a new {@link TokenAndInfo} instance to the
     * {@code tokenAndInfoListByTokenLabel} map under the corresponding token label.
     * <p>
     * Any exceptions encountered during the process are caught and logged as warnings.
     *
     * @param slot
     *            the {@link Slot} to check for token and information
     */
    private void checkTokenAndInfo(Slot slot) {
        log.info("Slot: {}", slot);

        try {
            SlotInfo slotInfo = slot.getSlotInfo();
            log.info("SlotInfo: {}", slotInfo);

            Token token = slot.getToken();
            if (token != null) {
                TokenInfo tokenInfo = token.getTokenInfo();
                log.info("TokenInfo: {}", tokenInfo);

                String tokenLabel = tokenInfo.getLabel().trim();
                if (pinByTokenLabel.containsKey(tokenLabel))
                    tokenAndInfoListByTokenLabel
                            .computeIfAbsent(tokenLabel, k -> new CopyOnWriteArrayList<>())
                            .add(new TokenAndInfo(token, tokenInfo));
            }
        } catch (Exception ignore) {
            log.warn("Failed to get slot info: {}", ignore.getMessage(), ignore);
        }
    }

    /**
     * Caches token and key information if caching is enabled.
     * <p>
     * This method checks the {@code useCacheKey} flag to determine whether caching should proceed.
     * If enabled, it iterates over all token and info lists, processing each entry via
     * {@link #iterateTokenAndInfoList}.
     * After processing, it logs the current state of {@code tokenAndKeyListByKeyClassNameAndKeyLabel}.
     *
     * @throws TokenException
     *             if an error occurs during token processing.
     */
    private void cacheKey() throws TokenException {
        if (!useCacheKey)
            return;

        tokenAndInfoListByTokenLabel.values().forEach(this::iterateTokenAndInfoList);

        log.info("tokenAndKeyListByKeyClassNameAndKeyLabel: {}", tokenAndKeyListByKeyClassNameAndKeyLabel);
    }

    /**
     * Iterates over a list of {@link TokenAndInfo} objects and processes each element
     * by invoking the {@code findAllKeysInToken} method.
     *
     * @param list
     *            the list of {@code TokenAndInfo} objects to be processed
     */
    private void iterateTokenAndInfoList(List<TokenAndInfo> list) {
        list.forEach(this::findAllKeysInToken);
    }

    /**
     * Scans all keys available in the given token and organizes them into a nested map structure
     * based on their class name and label. For each key found with a non-empty label, the method
     * adds it to the {@code tokenAndKeyListByKeyClassNameAndKeyLabel} map, grouping by key class
     * name and label. Handles any {@link TokenException} by logging a warning and ensures the
     * session is closed after the operation.
     *
     * @param tokenAndInfo
     *            the {@link TokenAndInfo} object containing the token to scan for keys
     */
    private void findAllKeysInToken(TokenAndInfo tokenAndInfo) {
        Token token = tokenAndInfo.getToken();
        Session session = null;
        try {
            session = openSessionHsm(tokenAndInfo, null);
            List<Key> allObjects = ModuleHelper.findKey(session, new Key());
            allObjects.stream()
                    .filter(key -> key.getLabel() != null && !key.getLabel().toString().isEmpty())
                    .forEach(key -> tokenAndKeyListByKeyClassNameAndKeyLabel
                            .computeIfAbsent(key.getClass().getSimpleName(), k -> new HashMap<>())
                            .computeIfAbsent(key.getLabel().toString(), k -> new TokenAndKeyList(token))
                            .getKeyList()
                            .add(key));
        } catch (TokenException ignore) {
            log.warn("Token(label={}) session/object scan failed", tokenAndInfo.getTokenLabel(), ignore);
        } finally {
            ModuleHelper.closeSession(session);
        }
    }
}
