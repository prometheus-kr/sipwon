package io.github.prometheuskr.sipwon.key;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.DES2SecretKey;
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
public class HsmKey_DDES implements HsmKey {
    private static final String DES_INITIAL_VECTOR = "0000000000000000";

    private final HsmVendor hsmVendor;
    private final Session session;
    private final DES2SecretKey key;

    HsmKey_DDES(HsmVendor hsmVendor, Session session, Key key) {
        this.hsmVendor = hsmVendor;
        this.session = session;
        this.key = (DES2SecretKey)key;
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
        byte[] encryptedData = session.decrypt(inputData);
        String result = Util.byteArray2HexaString(encryptedData);
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

        DES2SecretKey keyTemplate = new DES2SecretKey();
        keyTemplate.getToken().setBooleanValue(Boolean.FALSE);
        keyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDerive().setBooleanValue(Boolean.TRUE);

        Mechanism mechanism = toMechanism(HsmMechanism.DES3_ECB_ENCRYPT_DATA, data);

        Key dkey = session.deriveKey(mechanism, key, keyTemplate);
        log.debug("derived key [can't read key value]");

        return new HsmKey_DDES(hsmVendor, session, dkey);
    }

    @Override
    public String wrapKey(HsmKey targetKey) throws TokenException {
        log.debug("targetKey to derive: [can't read key value]");

        Mechanism mechanism = toMechanism(HsmMechanism.DES3_ECB);

        byte[] wrappedKey = session.wrapKey(mechanism, key, ((HsmKey_DDES) targetKey).key);
        String result = Util.byteArray2HexaString(wrappedKey);
        log.debug("wrapped result [{}]", result);

        return result;
    }

    @Override
    public HsmKey createKey(String value) throws TokenException {
        log.debug("value to createKey: [{}]", value);
        byte[] keyValueByteArray = Util.hexaString2ByteArray(value);

        DES2SecretKey keyTemplate = new DES2SecretKey();
        keyTemplate.getToken().setBooleanValue(Boolean.FALSE);
        keyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        keyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        keyTemplate.getValue().setByteArrayValue(keyValueByteArray);
        DES2SecretKey dkey = (DES2SecretKey) session.createObject(keyTemplate);

        return new HsmKey_DDES(hsmVendor, session, dkey);
    }

    Mechanism toMechanism(HsmMechanism hsmMechanism) {
        return toMechanism(hsmMechanism, DES_INITIAL_VECTOR);
    }

    Mechanism toMechanism(HsmMechanism hsmMechanism, String data) {
        HsmVendorMechanism changedMechanism = hsmMechanism.getMechanism0(hsmVendor);

        Parameters param = switch (changedMechanism) {
            case DES3_CBC -> new InitializationVectorParameters(Util.hexaString2ByteArray(data));
            case DES3_ECB_ENCRYPT_DATA -> new KeyDerivationStringDataParameters(Util.hexaString2ByteArray(data));
            case DES3_CBC_ENCRYPT_DATA -> new KeyDerivationStringDataParameters(Util.hexaString2ByteArray(data));
            case DES3_X919_MAC_PTK -> new InitializationVectorParameters(Util.hexaString2ByteArray(data));
            case DES3_X919_MAC_GENERAL_PTK -> new InitializationVectorParameters(Util.hexaString2ByteArray(data));
            default -> null;
        };

        return changedMechanism.getMechanism(param);
    }
}
