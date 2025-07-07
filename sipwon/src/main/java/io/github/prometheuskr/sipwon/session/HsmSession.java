package io.github.prometheuskr.sipwon.session;

import iaik.pkcs.pkcs11.TokenException;
import io.github.prometheuskr.sipwon.constant.HsmKeyType;
import io.github.prometheuskr.sipwon.key.HsmKey;

public interface HsmSession extends AutoCloseable {
    HsmKey findHsmKey(String keyLabel, HsmKeyType keyType) throws TokenException;

    HsmKey createTempHsmKey(HsmKeyType keyType, String value) throws TokenException;
}