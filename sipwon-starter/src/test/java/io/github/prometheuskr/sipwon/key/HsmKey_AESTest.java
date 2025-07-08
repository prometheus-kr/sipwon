package io.github.prometheuskr.sipwon.key;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.prometheuskr.sipwon.constant.HsmKeyType;
import io.github.prometheuskr.sipwon.constant.HsmMechanism;
import io.github.prometheuskr.sipwon.session.HsmSession;
import io.github.prometheuskr.sipwon.session.HsmSessionFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class HsmKey_AESTest {

    @Autowired
    HsmSessionFactory hsmSessionFactory;

    private final String tokenLabel = "test";
    private final String keyLabel = "testAesKey";
    private static final String PLAIN_STRING_FOR_ENCRYPT = "31323334353637383132333435363738";

    @Test
    void encrypt_decrypt() throws Exception {
        try (HsmSession session = hsmSessionFactory.getHsmSession(tokenLabel)) {
            HsmKey_AES hsmKey = (HsmKey_AES) session.findHsmKey(keyLabel, HsmKeyType.AES);
            String encrypted = hsmKey.encrypt(PLAIN_STRING_FOR_ENCRYPT, HsmMechanism.AES_CBC);
            assertThat(encrypted).isNotNull();

            String decrypted = hsmKey.decrypt(encrypted, HsmMechanism.AES_CBC);
            assertThat(decrypted).isEqualTo(PLAIN_STRING_FOR_ENCRYPT);
        }
    }

    @Test
    void mac() throws Exception {
        try (HsmSession session = hsmSessionFactory.getHsmSession(tokenLabel)) {
            HsmKey_AES hsmKey = (HsmKey_AES) session.findHsmKey(keyLabel, HsmKeyType.AES);
            String mac = hsmKey.mac(PLAIN_STRING_FOR_ENCRYPT, HsmMechanism.AES_MAC);
            assertThat(mac).isNotNull();
        }
    }

    @Test
    void derive() throws Exception {
        try (HsmSession session = hsmSessionFactory.getHsmSession(tokenLabel)) {
            HsmKey_AES hsmKey = (HsmKey_AES) session.findHsmKey(keyLabel, HsmKeyType.AES);
            HsmKey derivedKey = hsmKey.derive(PLAIN_STRING_FOR_ENCRYPT);
            assertThat(derivedKey).isNotNull();
        }
    }

    @Test
    void wrapKey() throws Exception {
        try (HsmSession session = hsmSessionFactory.getHsmSession(tokenLabel)) {
            HsmKey_AES hsmKey = (HsmKey_AES) session.findHsmKey(keyLabel, HsmKeyType.AES);
            HsmKey dKey = hsmKey.derive(PLAIN_STRING_FOR_ENCRYPT);
            String wrapped = hsmKey.wrapKey(dKey);
            assertThat(wrapped).isNotNull();
        }
    }
}