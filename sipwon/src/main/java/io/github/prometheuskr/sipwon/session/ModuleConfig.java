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

@Slf4j
public class ModuleConfig {

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
        this.useCacheKey = useCacheKey;
        this.pinByTokenLabel = pinByTokenLabel;
        this.hsmVendor = ModuleHelper.getHsmVendor(pkcs11LibraryPath);
        this.module = ModuleHelper.buildModule(pkcs11LibraryPath);
        buildCache();
    }

    HsmVendor getHsmVendor() {
        return hsmVendor;
    }

    Session getHsmSession(String tokenLabel, String pin) throws TokenException {
        List<TokenAndInfo> tokenAndInfoList = tokenAndInfoListByTokenLabel.get(tokenLabel);
        if (tokenAndInfoList == null || tokenAndInfoList.isEmpty()) {
            throw new IllegalArgumentException("No token found for label: " + tokenLabel);
        }

        int index = loadBalancing(tokenLabel);
        return openSessionHsm(tokenAndInfoList.get(index), pin);
    }

    private int loadBalancing(String tokenLabel) {
        int size = tokenAndInfoListByTokenLabel.get(tokenLabel).size();
        AtomicInteger aInt = listIndexByTokenLabel.computeIfAbsent(tokenLabel, k -> new AtomicInteger(0));
        return Math.abs(aInt.getAndIncrement() % size);
    }

    private Session openSessionHsm(TokenAndInfo tokenAndInfo, String pin) throws TokenException {
        return ModuleHelper.openSession(
                tokenAndInfo.getToken(),
                pin == null ? pinByTokenLabel.get(tokenAndInfo.getTokenLabel()) : pin);
    }

    void checkHsm() {
        new Thread(this::doHealthCheck, "HsmHealthCheckSignalThread").start();
    }

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

    private void clearCache() {
        tokenAndInfoListByTokenLabel.clear();
        tokenAndKeyListByKeyClassNameAndKeyLabel.clear();
    }

    private void buildCache() throws TokenException {
        if (!tokenAndInfoListByTokenLabel.isEmpty())
            return;

        cacheToken();
        cacheKey();
    }

    private void cacheToken() throws TokenException {
        ModuleHelper.getSlotList(module).forEach(this::checkTokenAndInfo);
        log.info("tokenAndInfoListByTokenLabel: {}", tokenAndInfoListByTokenLabel);
    }

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

    private void cacheKey() throws TokenException {
        if (!useCacheKey)
            return;

        tokenAndInfoListByTokenLabel.values().forEach(this::iterateTokenAndInfoList);

        log.info("tokenAndKeyListByKeyClassNameAndKeyLabel: {}", tokenAndKeyListByKeyClassNameAndKeyLabel);
    }

    private void iterateTokenAndInfoList(List<TokenAndInfo> list) {
        list.forEach(this::findAllKeysInToken);
    }

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
