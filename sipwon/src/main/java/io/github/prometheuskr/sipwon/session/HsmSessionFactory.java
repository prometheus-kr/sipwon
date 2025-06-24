package io.github.prometheuskr.sipwon.session;

import iaik.pkcs.pkcs11.TokenException;

public interface HsmSessionFactory {
    HsmSession getHsmSession(String tokenLabel) throws TokenException;

    HsmSession getHsmSession(String tokenLabel, String pin) throws TokenException;

    void checkHsm();
}