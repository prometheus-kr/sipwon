package io.github.prometheuskr.sipwon.key;

import iaik.pkcs.pkcs11.TokenException;
import io.github.prometheuskr.sipwon.constant.HsmMechanism;

public interface HsmKey {
    String encrypt(String data, HsmMechanism hsmMechanism) throws TokenException;

    String decrypt(String data, HsmMechanism hsmMechanism) throws TokenException;

    String mac(String data, HsmMechanism hsmMechanism) throws TokenException;

    HsmKey derive(String data) throws TokenException;

    String wrapKey(HsmKey targetKey) throws TokenException;

    HsmKey createKey(String value) throws TokenException;
}
