package io.github.prometheuskr.sipwon.session;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import iaik.pkcs.pkcs11.DefaultInitializeArgs;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.Token.SessionReadWriteBehavior;
import iaik.pkcs.pkcs11.Token.SessionType;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import io.github.prometheuskr.sipwon.constant.HsmVendor;
import io.github.prometheuskr.sipwon.util.Util;
import lombok.extern.slf4j.Slf4j;

/**
 * Helper class for interacting with PKCS#11 HSM modules.
 * <p>
 * Provides utility methods for:
 * <ul>
 * <li>Determining HSM vendor from PKCS#11 library path</li>
 * <li>Loading and initializing PKCS#11 modules</li>
 * <li>Managing module and session lifecycle</li>
 * <li>Finding cryptographic keys on the HSM</li>
 * </ul>
 * <p>
 * Handles vendor-specific logic for supported HSMs (e.g., PTK, NFAST).
 * Logs module information and found keys for debugging purposes.
 * <p>
 * Note: This class is package-private and intended for internal use.
 */
@Slf4j
class ModuleHelper {

    /**
     * Constant representing the identifier for the "cknfast" module.
     * Used to reference the CKNFAST module within the application.
     */
    private static final String CKNFAST = "cknfast";
    /**
     * Constant representing the name "cryptoki", which may refer to the PKCS#11 Cryptoki standard.
     * Typically used as an identifier for cryptographic modules or libraries.
     */
    private static final String CRYPTOKI = "cryptoki";

    /**
     * Determines the HSM (Hardware Security Module) vendor based on the provided PKCS#11 library path.
     *
     * @param pkcs11LibraryPath
     *            the file path to the PKCS#11 library
     * @return the corresponding {@link HsmVendor} enum value for the detected vendor
     * @throws RuntimeException
     *             if the library path does not match any supported vendor
     */
    static HsmVendor getHsmVendor(String pkcs11LibraryPath) {
        if (pkcs11LibraryPath.contains(CRYPTOKI)) {
            return HsmVendor.PTK;
        }

        if (pkcs11LibraryPath.contains(CKNFAST)) {
            return HsmVendor.NFAST;
        }

        throw new RuntimeException("Unsupported PKCS#11 library path: " + pkcs11LibraryPath);
    }

    /**
     * Builds and initializes a PKCS#11 Module using the specified library path.
     * <p>
     * This method loads the PKCS#11 module from the provided library path, initializes it,
     * logs module information if info-level logging is enabled, and returns the initialized module.
     *
     * @param pkcs11LibraryPath
     *            the file system path to the PKCS#11 library
     * @return the initialized {@link Module} instance
     * @throws IOException
     *             if an I/O error occurs during module loading or initialization
     * @throws TokenException
     *             if a PKCS#11 token-related error occurs
     */
    static Module buildModule(String pkcs11LibraryPath) throws IOException, TokenException {
        Module module = Module.getInstance(pkcs11LibraryPath);

        ModuleHelper.initialize(module);
        if (log.isInfoEnabled()) {
            log.info("HSM Module Info: {}", module.getInfo());
        }

        return module;
    }

    /**
     * Initializes the given PKCS#11 module with default initialization arguments.
     * <p>
     * If the module is already initialized, this method will silently ignore the
     * {@code CKR_CRYPTOKI_ALREADY_INITIALIZED} error. Any other {@link PKCS11Exception}
     * will be propagated.
     *
     * @param module
     *            the PKCS#11 module to initialize
     * @throws TokenException
     *             if an error occurs during initialization, except when the module is already initialized
     */
    static void initialize(Module module) throws TokenException {
        try {
            module.initialize(new DefaultInitializeArgs());
        } catch (PKCS11Exception e) {
            if (e.getErrorCode() != PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
                throw e;
            }
        }
    }

    /**
     * Attempts to finalize the given {@link Module} by calling its {@code finalize} method with {@code null} as the
     * argument.
     * <p>
     * If a {@link TokenException} is thrown during finalization, it is silently ignored.
     *
     * @param module
     *            the {@link Module} instance to finalize
     */
    static void finalize(Module module) {
        try {
            module.finalize(null);
        } catch (TokenException ignore) {
        }
    }

    /**
     * Retrieves a list of {@link Slot} objects associated with the specified {@link Module}.
     *
     * @param module
     *            the module from which to retrieve the slot list
     * @return a list of slots available in the given module
     * @throws TokenException
     *             if an error occurs while accessing the token slots
     */
    static List<Slot> getSlotList(Module module) throws TokenException {
        return Arrays.asList(module.getSlotList(false));
    }

    /**
     * Opens a new session with the specified token and logs in using the provided PIN.
     *
     * @param token
     *            the token to open the session with
     * @param pin
     *            the PIN used to log in to the session
     * @return a new {@link Session} object representing the opened session
     * @throws TokenException
     *             if an error occurs while opening the session or during login
     */
    static Session openSession(Token token, String pin) throws TokenException {
        Session s = token.openSession(SessionType.SERIAL_SESSION, SessionReadWriteBehavior.RO_SESSION, null, null);
        login(s, pin);
        return s;
    }

    /**
     * Attempts to log in to the given PKCS#11 session using the provided PIN.
     * <p>
     * If the PIN is empty or null, the method returns immediately without attempting to log in.
     * If the user is already logged in, the method suppresses the corresponding exception.
     * Any other PKCS#11 exceptions encountered during login are propagated.
     *
     * @param session
     *            the PKCS#11 session to log in to
     * @param pin
     *            the user PIN for authentication
     * @throws TokenException
     *             if a PKCS#11 error occurs during login, except when the user is already logged in
     */
    private static void login(Session session, String pin) throws TokenException {
        if (Util.isEmpty(pin))
            return;

        try {
            session.login(Session.UserType.USER, pin.toCharArray());
        } catch (PKCS11Exception e) {
            if (e.getErrorCode() != PKCS11Constants.CKR_USER_ALREADY_LOGGED_IN)
                throw e;
        }
    }

    /**
     * Closes the provided {@link Session} safely.
     * <p>
     * If the session is not {@code null}, attempts to close it by calling {@code closeSession()}.
     * Any {@link TokenException} thrown during the close operation is caught and ignored.
     *
     * @param session
     *            the session to be closed; may be {@code null}
     */
    static void closeSession(Session session) {
        if (session != null) {
            try {
                session.closeSession();
            } catch (TokenException ignore) {
            }
        }
    }

    /**
     * Finds and returns a list of keys in the given PKCS#11 session that match the specified template.
     * This method initializes a search for objects matching the provided key template,
     * retrieves them in batches of up to 10, and collects them into a list. The search
     * continues until fewer than 10 objects are returned in a batch, indicating that all
     * matching objects have been found. The search is finalized before returning the results.
     *
     * @param session
     *            the PKCS#11 session to search for keys in
     * @param template
     *            the key template used to filter the search
     * @return a list of {@link Key} objects matching the template
     * @throws TokenException
     *             if an error occurs during the search operation
     */
    static List<Key> findKey(Session session, Key template) throws TokenException {
        List<Key> keyList = new ArrayList<>();
        iaik.pkcs.pkcs11.objects.Object[] objs;
        session.findObjectsInit(template);

        do {
            objs = session.findObjects(10);
            Stream.of(objs).forEach(obj -> keyList.add((Key) obj));
        } while (objs.length == 10);
        session.findObjectsFinal();

        log.debug("Found keys: {}", keyList);
        return keyList;
    }
}
