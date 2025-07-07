package io.github.prometheuskr.sipwon.session;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.stream.Stream;

import iaik.pkcs.pkcs11.DefaultInitializeArgs;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.SlotInfo;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.Token.SessionReadWriteBehavior;
import iaik.pkcs.pkcs11.Token.SessionType;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import io.github.prometheuskr.sipwon.util.Util;
import lombok.extern.slf4j.Slf4j;

@Slf4j
class ModuleHelper {
    static void logModuleInfo(Module module, String newLine) throws TokenException {
        if (log.isInfoEnabled()) {
            log.info("HSM Module Info: {}{}", newLine, module.getInfo());
        }
    }

    static void forEachSlot(Module module, Consumer<Slot> slotConsumer) throws TokenException {
        Stream.of(module.getSlotList(false)).forEach(slotConsumer);
    }

    static void logSlotInfo(Slot slot, String newLine, Consumer<Token> tokenConsumer) {
        log.info("Slot: {}{}", newLine, slot);
        try {
            SlotInfo slotInfo = slot.getSlotInfo();
            log.info("SlotInfo: {}{}", newLine, slotInfo);

            if (slotInfo.isTokenPresent() && tokenConsumer != null)
                tokenConsumer.accept(slot.getToken());
        } catch (Exception e) {
            log.warn("Failed to get slot info: {}", e.getMessage(), e);
        }
    }

    static void logTokenInfo(Token token, String newLine) throws TokenException {
        TokenInfo tokenInfo = token.getTokenInfo();
        log.info("TokenInfo: {}{}", newLine, tokenInfo);
    }

    static void addTokenIfPresent(Token token, Map<String, String> tokenLabelAndPin,
            Map<String, List<ModuleConfig.TokenAndInfo>> tokenAndInfoListByTokenLabel) throws TokenException {
        TokenInfo tokenInfo = token.getTokenInfo();
        String tokenLabel = tokenInfo.getLabel().trim();

        if (tokenLabelAndPin.containsKey(tokenLabel)) {
            tokenAndInfoListByTokenLabel.computeIfAbsent(tokenLabel, k -> new CopyOnWriteArrayList<>())
                    .add(new ModuleConfig.TokenAndInfo(token, tokenInfo));
        }
    }

    static List<Key> findKeyHsm(Session session) throws TokenException {
        List<Key> keyList = new ArrayList<>();
        iaik.pkcs.pkcs11.objects.Object[] objs;
        session.findObjectsInit(new Key());

        do {
            objs = session.findObjects(10);
            Stream.of(objs).forEach(obj -> keyList.add((Key) obj));
        } while (objs.length == 10);
        session.findObjectsFinal();

        log.debug("Found keys: {}", keyList);
        return keyList;
    }

    static Session openSessionHsm(Token token, String pin) throws TokenException {
        Session session = token.openSession(
                SessionType.SERIAL_SESSION,
                SessionReadWriteBehavior.RO_SESSION,
                null,
                null);
        loginHsm(session, pin);

        return session;
    }

    static void loginHsm(Session session, String pin) throws TokenException {
        if (Util.isNotEmpty(pin)) {
            Util.runAndIgnore(() -> session.login(Session.UserType.USER, pin.toCharArray()),
                    PKCS11Constants.CKR_USER_ALREADY_LOGGED_IN);
        }
    }

    static void closeSessionHsm(Session session) {
        if (session != null) {
            try {
                session.closeSession();
            } catch (TokenException ignore) {
            }
        }
    }

    static void initializeHsm(Module module) throws TokenException {
        Util.runAndIgnore(() -> module.initialize(new DefaultInitializeArgs()),
                PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED);
    }

    static void finalizeHsm(Module module, Exception e) {
        log.error("HSM module initialization failed: {}", e.getMessage(), e);
        try {
            module.finalize(null);
        } catch (TokenException ignore) {
        }
    }
}
