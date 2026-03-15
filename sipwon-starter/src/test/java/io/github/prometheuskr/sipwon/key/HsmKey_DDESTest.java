package io.github.prometheuskr.sipwon.key;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import io.github.prometheuskr.sipwon.autoconfig.HsmSessionFactoryRegistry;
import io.github.prometheuskr.sipwon.constant.HsmKeyType;
import io.github.prometheuskr.sipwon.constant.HsmMechanism.HsmCypherMode;
import io.github.prometheuskr.sipwon.constant.HsmMechanism.HsmMacMode;
import io.github.prometheuskr.sipwon.session.HsmSession;
import io.github.prometheuskr.sipwon.session.HsmSessionFactory;
import io.github.prometheuskr.sipwon.util.Util;

@SpringBootTest
class HsmKey_DDESTest {

    private static final String PLAIN_STRING_FOR_ENCRYPT = "ABCD1234ABCD12341234ABCD1234ABCD";
    private static final String EXPECTED_DOUBLE_ENCRYPTED_STRING = "BA443D2E5BC3BDDE032E1A2F264CA124";

    @Autowired
    HsmSessionFactoryRegistry hsmSessionFactoryRegistry;

    private HsmSessionFactory getHsmSessionFactory() {
        return hsmSessionFactoryRegistry.getFactory(tokenLabel);
    }

    private final String tokenLabel = "test";
    private final String keyLabel = "testDes2Key";

    @Test
    void encrypt_decrypt() throws Exception {
        try (HsmSession session = getHsmSessionFactory().getHsmSession()) {
            HsmKey_DDES hsmKey = (HsmKey_DDES) session.findHsmKey(keyLabel, HsmKeyType.DDES);
            String plainHex = PLAIN_STRING_FOR_ENCRYPT;
            String encrypted = hsmKey.encrypt(plainHex, HsmCypherMode.ECB);

            assertThat(hsmKey.encrypt(Util.toOddParityHexString(encrypted), HsmCypherMode.ECB))
                    .isEqualTo(EXPECTED_DOUBLE_ENCRYPTED_STRING);

            String decrypted = hsmKey.decrypt(encrypted, HsmCypherMode.ECB);
            assertThat(decrypted).isEqualTo(plainHex);
        }
    }

    @Test
    void mac() throws Exception {
        try (HsmSession session = getHsmSessionFactory().getHsmSession()) {
            HsmKey_DDES hsmKey = (HsmKey_DDES) session.findHsmKey(keyLabel, HsmKeyType.DDES);
            String data = PLAIN_STRING_FOR_ENCRYPT + PLAIN_STRING_FOR_ENCRYPT;
            String mac = hsmKey.mac(data, HsmMacMode.MAC);
            assertThat(mac).isEqualTo("A8501F228BF9101C");

            HsmKey dkey = hsmKey.derive(data, HsmCypherMode.ECB);
            mac = dkey.mac(data, HsmMacMode.MAC);
            assertThat(mac).isEqualTo("95D9452E7F963E1D");

            mac = dkey.mac(data, HsmMacMode.X919_MAC);
            assertThat(mac).isEqualTo("3B04B207D67B9608");
        }
    }

    @Test
    void derive() throws Exception {
        try (HsmSession session = getHsmSessionFactory().getHsmSession()) {
            HsmKey_DDES hsmKey = (HsmKey_DDES) session.findHsmKey(keyLabel, HsmKeyType.DDES);
            String data = PLAIN_STRING_FOR_ENCRYPT;
            HsmKey derivedKey = hsmKey.derive(data, HsmCypherMode.CBC);
            derivedKey = derivedKey.derive(data, HsmCypherMode.ECB);
            derivedKey = derivedKey.derive(data, HsmCypherMode.ECB);
            derivedKey = derivedKey.derive(data, HsmCypherMode.CBC);
            assertThat(derivedKey).isNotNull();
        }
    }

    @Test
    void wrapKey() throws Exception {
        try (HsmSession session = getHsmSessionFactory().getHsmSession()) {
            HsmKey_DDES hsmKey = (HsmKey_DDES) session.findHsmKey(keyLabel, HsmKeyType.DDES);

            String data = PLAIN_STRING_FOR_ENCRYPT;
            HsmKey dKey = hsmKey.derive(data, HsmCypherMode.ECB);

            String wrapped = hsmKey.wrapKey(dKey);
            assertThat(wrapped).isEqualTo(EXPECTED_DOUBLE_ENCRYPTED_STRING);
        }
    }
}