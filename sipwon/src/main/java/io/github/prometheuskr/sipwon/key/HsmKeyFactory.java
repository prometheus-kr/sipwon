package io.github.prometheuskr.sipwon.key;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.objects.Key;
import io.github.prometheuskr.sipwon.constant.HsmVendorKeyType;
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
}
