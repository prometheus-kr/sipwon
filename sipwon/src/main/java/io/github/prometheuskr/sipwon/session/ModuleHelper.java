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

@Slf4j
class ModuleHelper {

    private static final String CKNFAST = "cknfast";
    private static final String CRYPTOKI = "cryptoki";

    static HsmVendor getHsmVendor(String pkcs11LibraryPath) {
        if (pkcs11LibraryPath.contains(CRYPTOKI)) {
            return HsmVendor.PTK;
        }

        if (pkcs11LibraryPath.contains(CKNFAST)) {
            return HsmVendor.NFAST;
        }

        throw new RuntimeException("Unsupported PKCS#11 library path: " + pkcs11LibraryPath);
    }

    static Module buildModule(String pkcs11LibraryPath) throws IOException, TokenException {
        Module module = Module.getInstance(pkcs11LibraryPath);

        ModuleHelper.initialize(module);
        if (log.isInfoEnabled()) {
            log.info("HSM Module Info: {}", module.getInfo());
        }

        return module;
    }

    static void initialize(Module module) throws TokenException {
        try {
            module.initialize(new DefaultInitializeArgs());
        } catch (PKCS11Exception e) {
            if (e.getErrorCode() != PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
                throw e;
            }
        }
    }

    static void finalize(Module module) {
        try {
            module.finalize(null);
        } catch (TokenException ignore) {
        }
    }

    static List<Slot> getSlotList(Module module) throws TokenException {
        return Arrays.asList(module.getSlotList(false));
    }

    static Session openSession(Token token, String pin) throws TokenException {
        Session s = token.openSession(SessionType.SERIAL_SESSION, SessionReadWriteBehavior.RO_SESSION, null, null);
        login(s, pin);
        return s;
    }

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

    static void closeSession(Session session) {
        if (session != null) {
            try {
                session.closeSession();
            } catch (TokenException ignore) {
            }
        }
    }

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
