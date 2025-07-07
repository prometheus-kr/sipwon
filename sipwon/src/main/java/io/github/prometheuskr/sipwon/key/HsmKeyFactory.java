package io.github.prometheuskr.sipwon.key;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Key;
import io.github.prometheuskr.sipwon.constant.HsmVendorKeyType;
import io.github.prometheuskr.sipwon.constant.HsmKeyType;
import io.github.prometheuskr.sipwon.constant.HsmVendor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class HsmKeyFactory {

    private HsmKeyFactory() {
    }

    public static HsmKey getHsmKey(HsmVendor hsmVendor, Session session, Key key) {
        log.debug("key: [{}]", key);

        HsmVendorKeyType keyType = HsmVendorKeyType.fromLongValue(key.getKeyType().getLongValue());
        return switch (keyType) {
            case DES -> new HsmKey_DES(hsmVendor, session, key);
            case DDES -> new HsmKey_DDES(hsmVendor, session, key);
            case TDES -> new HsmKey_TDES(hsmVendor, session, key);
            case AES -> new HsmKey_AES(hsmVendor, session, key);
            case SEED, SEED_PTK -> new HsmKey_SEED(hsmVendor, session, key);
        };
    }

    public static HsmKey createTempHsmKey(HsmVendor hsmVendor, Session session, HsmKeyType keyType, String value)
            throws TokenException {

        HsmKey key = switch (keyType) {
            case DES -> new HsmKey_DES(hsmVendor, session, null);
            case DDES -> new HsmKey_DDES(hsmVendor, session, null);
            case TDES -> new HsmKey_TDES(hsmVendor, session, null);
            case AES -> new HsmKey_AES(hsmVendor, session, null);
            case SEED -> new HsmKey_SEED(hsmVendor, session, null);
        };

        return key.createKey(value);
    }
}
