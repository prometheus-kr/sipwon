package io.github.prometheuskr.sipwon.session;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.objects.Key;
import io.github.prometheuskr.sipwon.constant.HsmVendor;
import io.github.prometheuskr.sipwon.util.Util;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ModuleConfig {
    private static final String NEW_LINE = System.lineSeparator();

    private final Module module;
    private final HsmVendor hsmVendor;
    private final Map<String, String> pinByTokenLabel;
    private final boolean useCacheKey;
    private final Map<String, AtomicInteger> listIndexByTokenLabel = new ConcurrentHashMap<>();
    private final Map<String, List<TokenAndInfo>> tokenAndInfoListByTokenLabel = new ConcurrentHashMap<>();
    private final Map<String, Map<String, TokenAndKeyList>> tokenAndKeyListByKeyClassNameAndKeyLabel = new ConcurrentHashMap<>();

    @Data
    static class TokenAndInfo {
        private final Token token;
        private final TokenInfo tokenInfo;

        public String getTokenLabel() {
            return tokenInfo.getLabel().trim();
        }
    }

    @Data
    static class TokenAndKeyList {
        private final Token token;
        private final List<Key> keyList = new ArrayList<>();
    }

    public ModuleConfig(String pkcs11LibraryPath, Map<String, String> pinByTokenLabel, boolean useCacheKey)
            throws TokenException, IOException {
        if (pkcs11LibraryPath.contains("cryptoki")) {
            hsmVendor = HsmVendor.PTK;
        } else if (pkcs11LibraryPath.contains("cknfast")) {
            hsmVendor = HsmVendor.NFAST;
        } else {
            throw new RuntimeException("Unsupported PKCS#11 library path: " + pkcs11LibraryPath);
        }

        this.module = Module.getInstance(pkcs11LibraryPath);
        ModuleHelper.initializeHsm(module);
        this.pinByTokenLabel = pinByTokenLabel;
        this.useCacheKey = useCacheKey;
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
                ModuleHelper.initializeHsm(module);
                buildCache();

                // openSessionHsm(tokenAndInfoListByTokenLabel.values().stream().findFirst().get());
            } catch (TokenException e) {
                ModuleHelper.finalizeHsm(module, e);
                clear();
                Util.sleep(1000);
                checkHsm();
            } catch (Exception e) {
                ModuleHelper.finalizeHsm(module, e);
                clear();
                throw e;
            }
        }
    }

    private void clear() {
        tokenAndInfoListByTokenLabel.clear();
        tokenAndKeyListByKeyClassNameAndKeyLabel.clear();
    }

    private void buildCache() throws TokenException {
        if (tokenAndInfoListByTokenLabel.isEmpty()) {
            ModuleHelper.logModuleInfo(module, NEW_LINE);
            ModuleHelper.forEachSlot(module, slot -> ModuleHelper.logSlotInfo(slot, NEW_LINE, t -> {
                try {
                    ModuleHelper.addTokenIfPresent(t, pinByTokenLabel, tokenAndInfoListByTokenLabel);
                } catch (TokenException e) {
                    log.warn("Failed to add token: {}", e.getMessage(), e);
                }
            }));
            log.info("tokenAndInfoListByTokenLabel: {}", tokenAndInfoListByTokenLabel);
            checkKeyInfo();
        }
    }

    private void checkKeyInfo() throws TokenException {
        if (!useCacheKey)
            return;

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
        Session session = null;
        try {
            session = openSessionHsm(tokenAndInfo);
            List<Key> allObjects = ModuleHelper.findKeyHsm(session);
            allObjects.forEach(key -> tokenAndKeyListByKeyClassNameAndKeyLabel
                    .computeIfAbsent(key.getClass().getSimpleName(), k -> new java.util.HashMap<>())
                    .computeIfAbsent(key.getLabel().toString(), k -> new TokenAndKeyList(token))
                    .getKeyList()
                    .add(key));
        } finally {
            ModuleHelper.closeSessionHsm(session);
        }
    }

    private Session openSessionHsm(TokenAndInfo tokenAndInfo) throws TokenException {
        return openSessionHsm(tokenAndInfo, null);
    }

    private Session openSessionHsm(TokenAndInfo tokenAndInfo, String pin) throws TokenException {
        return ModuleHelper.openSessionHsm(
                tokenAndInfo.getToken(),
                pin == null ? pinByTokenLabel.get(tokenAndInfo.getTokenLabel()) : pin);
    }
}
