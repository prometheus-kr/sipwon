package io.github.prometheuskr.sipwon.key;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.parameters.KeyDerivationStringDataParameters;
import iaik.pkcs.pkcs11.parameters.Parameters;
import io.github.prometheuskr.sipwon.constant.HsmMechanism;
import io.github.prometheuskr.sipwon.constant.HsmVendor;
import io.github.prometheuskr.sipwon.constant.HsmVendorMechanism;
import io.github.prometheuskr.sipwon.util.Util;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class HsmKey_AES implements HsmKey {
    private static final String AES_INITIAL_VECTOR = "00000000000000000000000000000000";

    private final HsmVendor hsmVendor;
    private final Session session;
    private final AESSecretKey key;

    HsmKey_AES(HsmVendor hsmVendor, Session session, Key key) {
        this.hsmVendor = hsmVendor;
        this.session = session;
        this.key = (AESSecretKey)key;
    }

    @Override
    public String encrypt(String data, HsmMechanism hsmMechanism) throws TokenException {
        log.debug("data to encrypt: [{}]", data);

        Mechanism mechanism = toMechanism(hsmMechanism);
        session.encryptInit(mechanism, key);

        byte[] inputData = Util.hexaString2ByteArray(data);
        byte[] encryptedData = session.encrypt(inputData);
        String result = Util.byteArray2HexaString(encryptedData);
        log.debug("encrypted result [{}]", result);

        return result;
    }

    @Override
    public String decrypt(String data, HsmMechanism hsmMechanism) throws TokenException {
        log.debug("data to decrypt: [{}]", data);

        Mechanism mechanism = toMechanism(hsmMechanism);
        session.decryptInit(mechanism, key);

        byte[] inputData = Util.hexaString2ByteArray(data);
        byte[] decryptedData = session.decrypt(inputData);
        String result = Util.byteArray2HexaString(decryptedData);
        log.debug("decrypted result [{}]", result);

        return result;
    }

    @Override
    public String mac(String data, HsmMechanism hsmMechanism) throws TokenException {
        log.debug("data to sign: [{}]", data);

        Mechanism mechanism = toMechanism(hsmMechanism);
        session.signInit(mechanism, key);

        byte[] inputData = Util.hexaString2ByteArray(data);
        byte[] signedData = session.sign(inputData);
        String result = Util.byteArray2HexaString(signedData).substring(0, 8);
        log.debug("signed result [{}]", result);

        return result;
    }

    @Override
    public HsmKey derive(String data) throws TokenException {
        log.debug("data to derive: [{}]", data);

        AESSecretKey keyTemplate = new AESSecretKey();
        keyTemplate.getToken().setBooleanValue(Boolean.FALSE);
        keyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDerive().setBooleanValue(Boolean.TRUE);
        keyTemplate.getValueLen().setLongValue(16L);

        Mechanism mechanism = toMechanism(HsmMechanism.AES_ECB_ENCRYPT_DATA, data);

        Key dkey = session.deriveKey(mechanism, key, keyTemplate);
        log.debug("derived key [can't read key value]");

        return new HsmKey_AES(hsmVendor, session, dkey);
    }

    @Override
    public String wrapKey(HsmKey targetKey) throws TokenException {
        log.debug("targetKey to wrap: [can't read key value]");

        Mechanism mechanism = toMechanism(HsmMechanism.AES_ECB);

        byte[] wrappedKey = session.wrapKey(mechanism, key, ((HsmKey_AES) targetKey).key);
        String result = Util.byteArray2HexaString(wrappedKey);
        log.debug("wrapped result [{}]", result);

        return result;
    }

    @Override
    public HsmKey createKey(String value) throws TokenException {
        log.debug("value to createKey: [{}]", value);
        byte[] keyValueByteArray = Util.hexaString2ByteArray(value);

        AESSecretKey keyTemplate = new AESSecretKey();
        keyTemplate.getToken().setBooleanValue(Boolean.FALSE);
        keyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        keyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        keyTemplate.getValue().setByteArrayValue(keyValueByteArray);
        AESSecretKey dkey = (AESSecretKey) session.createObject(keyTemplate);

        return new HsmKey_AES(hsmVendor, session, dkey);
    }

    Mechanism toMechanism(HsmMechanism hsmMechanism) {
        return toMechanism(hsmMechanism, AES_INITIAL_VECTOR);
    }

    Mechanism toMechanism(HsmMechanism hsmMechanism, String data) {
        HsmVendorMechanism changedMechanism = hsmMechanism.getMechanism0(hsmVendor);

        Parameters param = switch (changedMechanism) {
            case AES_CBC -> new InitializationVectorParameters(Util.hexaString2ByteArray(data));
            case AES_ECB_ENCRYPT_DATA -> new KeyDerivationStringDataParameters(Util.hexaString2ByteArray(data));
            default -> null;
        };

        return changedMechanism.getMechanism(param);
    }
}
