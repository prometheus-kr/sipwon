package io.github.prometheuskr.sipwon.key;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import io.github.prometheuskr.sipwon.constant.HsmKeyType;
import io.github.prometheuskr.sipwon.constant.HsmMechanism;
import io.github.prometheuskr.sipwon.session.HsmSession;
import io.github.prometheuskr.sipwon.session.HsmSessionFactory;
import io.github.prometheuskr.sipwon.util.Util;

@SpringBootTest
class HsmKey_DDESTest {

    private static final String PLAIN_STRING_FOR_ENCRYPT = "ABCD1234ABCD12341234ABCD1234ABCD";
    private static final String EXPECTED_DOUBLE_ENCRYPTED_STRING = "BA443D2E5BC3BDDE032E1A2F264CA124";

    @Autowired
    HsmSessionFactory hsmSessionFactory;

    private final String tokenLabel = "test";
    private final String keyLabel = "testDes2Key";

    @Test
    void encrypt_decrypt() throws Exception {
        try (HsmSession session = hsmSessionFactory.getHsmSession(tokenLabel)) {
            HsmKey_DDES hsmKey = (HsmKey_DDES) session.findHsmKey(keyLabel, HsmKeyType.DDES);
            String plainHex = PLAIN_STRING_FOR_ENCRYPT;
            String encrypted = hsmKey.encrypt(plainHex, HsmMechanism.DES3_ECB);

            assertThat(hsmKey.encrypt(Util.toOddParityHexString(encrypted), HsmMechanism.DES3_ECB))
                    .isEqualTo(EXPECTED_DOUBLE_ENCRYPTED_STRING);

            String decrypted = hsmKey.decrypt(encrypted, HsmMechanism.DES3_ECB);
            assertThat(decrypted).isEqualTo(plainHex);
        }
    }

    @Test
    void mac() throws Exception {
        try (HsmSession session = hsmSessionFactory.getHsmSession(tokenLabel)) {
            HsmKey_DDES hsmKey = (HsmKey_DDES) session.findHsmKey(keyLabel, HsmKeyType.DDES);
            String data = PLAIN_STRING_FOR_ENCRYPT + PLAIN_STRING_FOR_ENCRYPT;
            String mac = hsmKey.mac(data, HsmMechanism.DES3_MAC);
            assertThat(mac).isEqualTo("A8501F22");

            HsmKey dkey = hsmKey.derive(data);
            mac = dkey.mac(data, HsmMechanism.DES3_MAC);
            assertThat(mac).isEqualTo("95D9452E");

            mac = dkey.mac(data, HsmMechanism.DES3_X919_MAC);
            assertThat(mac).isEqualTo("3B04B207");
        }
    }

    @Test
    void derive() throws Exception {
        try (HsmSession session = hsmSessionFactory.getHsmSession(tokenLabel)) {
            HsmKey_DDES hsmKey = (HsmKey_DDES) session.findHsmKey(keyLabel, HsmKeyType.DDES);
            String data = PLAIN_STRING_FOR_ENCRYPT;
            HsmKey derivedKey = hsmKey.derive(data);
            assertThat(derivedKey).isNotNull();
        }
    }

    @Test
    void wrapKey() throws Exception {
        try (HsmSession session = hsmSessionFactory.getHsmSession(tokenLabel)) {
            HsmKey_DDES hsmKey = (HsmKey_DDES) session.findHsmKey(keyLabel, HsmKeyType.DDES);

            String data = PLAIN_STRING_FOR_ENCRYPT;
            HsmKey dKey = hsmKey.derive(data);

            String wrapped = hsmKey.wrapKey(dKey);
            assertThat(wrapped).isEqualTo(EXPECTED_DOUBLE_ENCRYPTED_STRING);
        }
    }
}