package io.github.prometheuskr.sipwon.key;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.GenericSecretKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.parameters.Parameters;
import io.github.prometheuskr.sipwon.constant.HsmMechanism;
import io.github.prometheuskr.sipwon.constant.HsmVendorMechanism;
import io.github.prometheuskr.sipwon.key.vendor.SEEDSecretKeyPTK;
import io.github.prometheuskr.sipwon.constant.HsmVendor;
import io.github.prometheuskr.sipwon.util.Util;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class HsmKey_SEED implements HsmKey {
    private static final String SEED_INITIAL_VECTOR = "00000000000000000000000000000000";

    private final HsmVendor hsmVendor;
    private final Session session;
    private final GenericSecretKey key;

    HsmKey_SEED(HsmVendor hsmVendor, Session session, Key key) {
        this.hsmVendor = hsmVendor;
        this.session = session;
        this.key = (GenericSecretKey)key;
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

        String keyValue = encrypt(data, HsmMechanism.SEED_ECB);
        return createKey(keyValue);
    }

    @Override
    public String wrapKey(HsmKey targetKey) throws TokenException {
        log.debug("targetKey to wrap: [can't read key value]");

        Mechanism mechanism = toMechanism(HsmMechanism.SEED_ECB);

        byte[] wrappedKey = session.wrapKey(mechanism, key, ((HsmKey_SEED) targetKey).key);
        String result = Util.byteArray2HexaString(wrappedKey);
        log.debug("wrapped result [{}]", result);

        return result;
    }

    @Override
    public HsmKey createKey(String value) throws TokenException {
        log.debug("value to createKey: [{}]", value);
        byte[] keyValueByteArray = Util.hexaString2ByteArray(value);

        GenericSecretKey keyTemplate;
        if (hsmVendor == HsmVendor.PTK) {
            keyTemplate = new SEEDSecretKeyPTK();
        } else {
            throw new TokenException("Unsupported HSM vendor for SEED key creation: " + hsmVendor);
        }

        keyTemplate.getToken().setBooleanValue(Boolean.FALSE);
        keyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        keyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        keyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        keyTemplate.getValue().setByteArrayValue(keyValueByteArray);
        GenericSecretKey dkey = (GenericSecretKey) session.createObject(keyTemplate);

        return new HsmKey_SEED(hsmVendor, session, dkey);
    }

    Mechanism toMechanism(HsmMechanism hsmMechanism) {
        return toMechanism(hsmMechanism, SEED_INITIAL_VECTOR);
    }

    Mechanism toMechanism(HsmMechanism hsmMechanism, String data) {
        HsmVendorMechanism changedMechanism = hsmMechanism.getMechanism0(hsmVendor);

        Parameters param = switch (changedMechanism) {
            case SEED_CBC_PTK -> new InitializationVectorParameters(Util.hexaString2ByteArray(data));
            default -> null;
        };
        return changedMechanism.getMechanism(param);
    }
}
