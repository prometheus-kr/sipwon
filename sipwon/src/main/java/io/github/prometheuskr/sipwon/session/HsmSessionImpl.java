package io.github.prometheuskr.sipwon.session;

import java.util.List;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.DES2SecretKey;
import iaik.pkcs.pkcs11.objects.DES3SecretKey;
import iaik.pkcs.pkcs11.objects.DESSecretKey;
import iaik.pkcs.pkcs11.objects.Key;
import io.github.prometheuskr.sipwon.constant.HsmKeyType;
import io.github.prometheuskr.sipwon.constant.HsmVendor;
import io.github.prometheuskr.sipwon.key.HsmKey;
import io.github.prometheuskr.sipwon.key.HsmKeyFactory;
import io.github.prometheuskr.sipwon.key.vendor.SEEDSecretKey;
import io.github.prometheuskr.sipwon.key.vendor.SEEDSecretKeyPTK;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class HsmSessionImpl implements HsmSession {
    @NonNull
    private final Session session;
    private final HsmVendor hsmVendor;

    HsmSessionImpl(Session hsmSession, HsmVendor hsmVendor) {
        this.session = hsmSession;
        this.hsmVendor = hsmVendor;
    }

    @Override
    public void close() {
        try {
            session.closeSession();
        } catch (TokenException e) {
            log.warn("an exception occured during closeSession.. but ignored this exception.", e);
        }
    }

    @Override
    public HsmKey findHsmKey(String keyLabel, HsmKeyType keyType) throws TokenException {
        Key key = newVendorKey(keyType);

        key.getLabel().setCharArrayValue(keyLabel.toCharArray());

        List<Key> keyList = ModuleHelper.findKey(session, key);
        if (keyList.size() != 1) {
            throw new RuntimeException("Key not found or multiple keys found for label: " + keyLabel);
        }

        return HsmKeyFactory.getHsmKey(hsmVendor, session, keyList.get(0));
    }

    @Override
    public HsmKey createTempHsmKey(HsmKeyType keyType, String value) throws TokenException {
        return HsmKeyFactory.createTempHsmKey(hsmVendor, session, keyType, value);
    }

    private Key newVendorKey(HsmKeyType keyType) {
        switch (hsmVendor) {
            case PTK:
                return switch (keyType) {
                    case DES -> new DESSecretKey();
                    case DDES -> new DES2SecretKey();
                    case TDES -> new DES3SecretKey();
                    case AES -> new AESSecretKey();
                    case SEED -> new SEEDSecretKeyPTK();
                };
            case NFAST:
                return switch (keyType) {
                    case DES -> new DESSecretKey();
                    case DDES -> new DES2SecretKey();
                    case TDES -> new DES3SecretKey();
                    case AES -> new AESSecretKey();
                    case SEED -> new SEEDSecretKey();
                };
        }

        return null;
    }
}
