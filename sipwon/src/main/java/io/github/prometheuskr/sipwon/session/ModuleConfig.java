package io.github.prometheuskr.sipwon.session;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import iaik.pkcs.pkcs11.DefaultInitializeArgs;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Session.UserType;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.SlotInfo;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.Token.SessionReadWriteBehavior;
import iaik.pkcs.pkcs11.Token.SessionType;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import io.github.prometheuskr.sipwon.constant.HsmVendor;
import io.github.prometheuskr.sipwon.util.Util;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ModuleConfig {
    private static final String NEW_LINE = System.lineSeparator();

    private final Module module;
    private final HsmVendor hsmVendor;
    private final Map<String, String> targetPin;
    private final String excludedTokenPattern;
    private final Map<String, AtomicInteger> listIndexByTokenLabel = new ConcurrentHashMap<>();
    private final Map<String, List<TokenAndInfo>> tokenAndInfoListByTokenLabel = new ConcurrentHashMap<>();
    private final Map<String, Map<String, TokenAndKeyList>> tokenAndKeyListByKeyClassNameAndKeyLabel = new ConcurrentHashMap<>();

    @Data
    class TokenAndInfo {
        private final Token token;
        private final TokenInfo tokenInfo;

        public String getTokenLabel() {
            return tokenInfo.getLabel().trim();
        }
    }

    @Data
    class TokenAndKeyList {
        private final Token token;
        private final List<Key> keyList = new ArrayList<>();
    }

    public ModuleConfig(String pkcs11LibraryPath, String excludedTokenPattern, Map<String, String> pinByTokenLabel)
            throws TokenException, IOException {
        if (pkcs11LibraryPath.contains("cryptoki")) {
            hsmVendor = HsmVendor.PTK;
        } else if (pkcs11LibraryPath.contains("cknfast")) {
            hsmVendor = HsmVendor.NFAST;
        } else {
            throw new RuntimeException("Unsupported PKCS#11 library path: " + pkcs11LibraryPath);
        }

        module = Module.getInstance(pkcs11LibraryPath);
        initializeHsm();

        this.excludedTokenPattern = excludedTokenPattern;
        targetPin = pinByTokenLabel;

        buildCache();
    }

    public HsmVendor getHsmVendor() {
        return hsmVendor;
    }

    void checkHsm() {
        new Thread(this::doHealthCheck, "HsmHealthCheckSignalThread").start();
    }

    Session getHsmSession(String tokenLabel, String pin) throws TokenException {
        List<TokenAndInfo> tokenAndInfos = tokenAndInfoListByTokenLabel.get(tokenLabel);
        if (tokenAndInfos == null || tokenAndInfos.isEmpty()) {
            throw new IllegalArgumentException("No token found for label: " + tokenLabel);
        }

        int size = tokenAndInfos.size();
        AtomicInteger aInt = listIndexByTokenLabel.computeIfAbsent(tokenLabel, k -> new AtomicInteger(0));
        int index = Math.abs(aInt.getAndIncrement() % size);

        return openSessionHsm(tokenAndInfos.get(index), pin);
    }

    private void doHealthCheck() {
        synchronized (this) {
            try {
                initializeHsm();
                buildCache();
            } catch (TokenException e) {
                finalizeHsm(e);
                clear();

                Util.sleep(1000);
                checkHsm();
            }
        }
    }

    private void clear() {
        tokenAndInfoListByTokenLabel.clear();
        tokenAndKeyListByKeyClassNameAndKeyLabel.clear();
    }

    private void buildCache() throws TokenException {
        if (tokenAndInfoListByTokenLabel.isEmpty()) {
            checkModuleInfo();
            checkKeyInfo();
        }
    }

    private void checkModuleInfo() throws TokenException {
        if (log.isInfoEnabled()) {
            log.info("HSM Module Info: {}{}", NEW_LINE, module.getInfo());
        }

        Stream.of(module.getSlotList(false)).forEach(this::checkSlotInfo);
        log.info("tokenAndInfoListByTokenLabel: {}", tokenAndInfoListByTokenLabel);
    }

    private void checkSlotInfo(Slot slot) {
        log.info("Slot: {}{}", NEW_LINE, slot);

        try {
            SlotInfo slotInfo = slot.getSlotInfo();
            log.info("SlotInfo: {}{}", NEW_LINE, slotInfo);
            if (slotInfo.isTokenPresent()) {
                checkTokenInfo(slot.getToken());
            }
        } catch (Exception e) {
            log.warn("Failed to get slot info: {}", e.getMessage(), e);
        }
    }

    private void checkTokenInfo(Token token) throws TokenException {
        TokenInfo tokenInfo = token.getTokenInfo();
        log.info("TokenInfo: {}{}", NEW_LINE, tokenInfo);

        String tokenLabel = tokenInfo.getLabel().trim();
        if (tokenLabel.matches(excludedTokenPattern)) {
            log.info("exclude token. label: {}", tokenLabel);
        } else {
            tokenAndInfoListByTokenLabel
                    .computeIfAbsent(tokenLabel, k -> new CopyOnWriteArrayList<>())
                    .add(new TokenAndInfo(token, tokenInfo));
        }
    }

    private void checkKeyInfo() throws TokenException {
        for (List<TokenAndInfo> tokenAndInfoList : tokenAndInfoListByTokenLabel.values()) {
            for (TokenAndInfo tokenAndInfo : tokenAndInfoList) {
                try {
                    findAllKeysInToken(tokenAndInfo);
                } catch (Exception e) {
                    String tokenLabel = tokenAndInfo.getTokenLabel();
                    log.warn("Token(label={}) session/object scan failed", tokenLabel, e);
                }
            }
        }
        log.info("tokenAndKeyListByKeyClassNameAndKeyLabel: {}", tokenAndKeyListByKeyClassNameAndKeyLabel);
    }

    private void findAllKeysInToken(TokenAndInfo tokenAndInfo) throws TokenException {
        Token token = tokenAndInfo.getToken();
        var session = openSessionHsm(tokenAndInfo);
        List<Key> allObjects = findKeyHsm(session);
        closeSessionHsm(session);

        // Class별로 분류하여 Map에 저장
        allObjects.forEach(key -> tokenAndKeyListByKeyClassNameAndKeyLabel
                .computeIfAbsent(key.getClass().getSimpleName(), k -> new java.util.HashMap<>())
                .computeIfAbsent(key.getLabel().toString(), k -> new TokenAndKeyList(token))
                .getKeyList()
                .add(key));
    }

    private void initializeHsm() throws TokenException {
        Util.runAndIgnore(() -> module.initialize(new DefaultInitializeArgs()),
                PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED);
    }

    private void finalizeHsm(Exception e) {
        log.error("HSM module initialization failed: {}", e.getMessage(), e);
        //@formatter:off
        try {module.finalize(null);} catch (TokenException ignore) {}
        //@formatter:on
    }

    private Session openSessionHsm(TokenAndInfo tokenAndInfo) throws TokenException {
        return openSessionHsm(tokenAndInfo, null);
    }

    private Session openSessionHsm(TokenAndInfo tokenAndInfo, String pin) throws TokenException {
        String tokenLabel = tokenAndInfo.getTokenLabel();
        Token token = tokenAndInfo.getToken();

        var session = token.openSession(SessionType.SERIAL_SESSION, SessionReadWriteBehavior.RO_SESSION, null, null);
        loginHsm(session, pin == null ? targetPin.get(tokenLabel) : pin);
        return session;
    }

    private void loginHsm(Session session, String pin) throws TokenException {
        if (Util.isNotEmpty(pin)) {
            Util.runAndIgnore(() -> session.login(UserType.USER, pin.toCharArray()),
                    PKCS11Constants.CKR_USER_ALREADY_LOGGED_IN);
        }
    }

    private void closeSessionHsm(Session session) throws TokenException {
        //@formatter:off
        try {session.closeSession();} catch (TokenException e) {
            log.debug("Failed to close session: {}, {}", e.getMessage(), e);
        }
        //@formatter:on
    }

    private List<Key> findKeyHsm(Session session) throws TokenException {
        List<Key> keyList = new java.util.ArrayList<>();
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
}
