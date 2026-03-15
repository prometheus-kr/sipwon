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

@SpringBootTest
class HsmKey_TDESTest {

    private final String tokenLabel = "test";
    private final String keyLabel = "testDes3Key";
    private static final String PLAIN_STRING_FOR_ENCRYPT = "313233343132333435363738313233343132333431323334";

    @Autowired
    HsmSessionFactoryRegistry hsmSessionFactoryRegistry;

    private HsmSessionFactory getHsmSessionFactory() {
        return hsmSessionFactoryRegistry.getFactory(tokenLabel);
    }

    @Test
    void encrypt_decrypt() throws Exception {
        try (HsmSession session = getHsmSessionFactory().getHsmSession()) {
            HsmKey_TDES hsmKey = (HsmKey_TDES) session.findHsmKey(keyLabel, HsmKeyType.TDES);
            String encrypted = hsmKey.encrypt(PLAIN_STRING_FOR_ENCRYPT, HsmCypherMode.CBC);
            assertThat(encrypted).isNotNull();

            String decrypted = hsmKey.decrypt(encrypted, HsmCypherMode.CBC);
            assertThat(decrypted).isEqualTo(PLAIN_STRING_FOR_ENCRYPT);
        }
    }

    @Test
    void mac() throws Exception {
        try (HsmSession session = getHsmSessionFactory().getHsmSession()) {
            HsmKey_TDES hsmKey = (HsmKey_TDES) session.findHsmKey(keyLabel, HsmKeyType.TDES);
            String mac = hsmKey.mac(PLAIN_STRING_FOR_ENCRYPT, HsmMacMode.MAC);
            assertThat(mac).isNotNull();
        }
    }

    @Test
    void derive() throws Exception {
        try (HsmSession session = getHsmSessionFactory().getHsmSession()) {
            HsmKey_TDES hsmKey = (HsmKey_TDES) session.findHsmKey(keyLabel, HsmKeyType.TDES);
            HsmKey derivedKey = hsmKey.derive(PLAIN_STRING_FOR_ENCRYPT, HsmCypherMode.ECB);
            assertThat(derivedKey).isNotNull();
        }
    }

    @Test
    void wrapKey() throws Exception {
        try (HsmSession session = getHsmSessionFactory().getHsmSession()) {
            HsmKey_TDES hsmKey = (HsmKey_TDES) session.findHsmKey(keyLabel, HsmKeyType.TDES);
            HsmKey dKey = hsmKey.derive(PLAIN_STRING_FOR_ENCRYPT, HsmCypherMode.ECB);
            String wrapped = hsmKey.wrapKey(dKey);
            assertThat(wrapped).isNotNull();
        }
    }
}