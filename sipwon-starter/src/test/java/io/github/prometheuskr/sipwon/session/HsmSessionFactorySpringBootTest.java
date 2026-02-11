package io.github.prometheuskr.sipwon.session;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import io.github.prometheuskr.sipwon.autoconfig.HsmSessionFactoryRegistry;
import io.github.prometheuskr.sipwon.constant.HsmKeyType;
import io.github.prometheuskr.sipwon.key.HsmKey;

@SpringBootTest
class HsmSessionFactorySpringBootTest {

    @Autowired
    HsmSessionFactoryRegistry hsmSessionFactoryRegistry;

    @Test
    void contextLoads() {}

    @Test
    void getHsmSession_and_getHsmKey() throws Exception {
        String testTokenLabel = "test";
        String testKeyLabel;
        HsmKeyType testKeyType;

        // Get the first HSM configuration (hsm1)
        HsmSessionFactory hsmSessionFactory = hsmSessionFactoryRegistry.getFactory(testTokenLabel);

        if (hsmSessionFactory != null) {
            testKeyLabel = "testAesKey";
            testKeyType = HsmKeyType.AES;
            try (HsmSession session = hsmSessionFactory.getHsmSession(testTokenLabel)) {
                assertNotNull(session, "HsmSession은 null이 아니어야 합니다.");
                try {
                    HsmKey key = session.findHsmKey(testKeyLabel, testKeyType);
                    assertNotNull(key, "HsmKey는 null이 아니어야 합니다.");
                } catch (Exception e) {
                }
            }

            testKeyLabel = "testSeedKey";
            testKeyType = HsmKeyType.SEED;
            try (HsmSession session = hsmSessionFactory.getHsmSession(testTokenLabel)) {
                assertNotNull(session, "HsmSession은 null이 아니어야 합니다.");
                try {
                    HsmKey key = session.findHsmKey(testKeyLabel, testKeyType);
                    assertNotNull(key, "HsmKey는 null이 아니어야 합니다.");
                } catch (Exception e) {
                }
            }
        }
    }
}
