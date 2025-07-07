package io.github.prometheuskr.sipwon.session;

import iaik.pkcs.pkcs11.TokenException;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class HsmSessionFactoryImpl implements HsmSessionFactory {
    private final ModuleConfig hsmModuleConfig;

    @Override
    public HsmSession getHsmSession(String tokenLabel) throws TokenException {
        return getHsmSession(tokenLabel, null);
    }

    @Override
    public HsmSession getHsmSession(String tokenLabel, String pin) throws TokenException {
        return new HsmSessionImpl(hsmModuleConfig.getHsmSession(tokenLabel, pin), hsmModuleConfig.getHsmVendor());
    }

    @Override
    public void checkHsm() {
        Thread thread = new Thread(() -> {
            while (true) {
                try {
                    hsmModuleConfig.checkHsm();
                    Thread.sleep(10_000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception ignore) {
                }
            }
        }, "HsmHealthCheckLoopThread");
        thread.setDaemon(true);
        thread.start();
    }
}
