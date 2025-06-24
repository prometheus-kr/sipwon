package io.github.prometheuskr.sipwon.autoconfig;

import java.io.IOException;
import java.util.stream.Collectors;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import iaik.pkcs.pkcs11.TokenException;
import io.github.prometheuskr.sipwon.config.HsmProperties;
import io.github.prometheuskr.sipwon.session.HsmSessionFactory;
import io.github.prometheuskr.sipwon.session.HsmSessionFactoryImpl;
import io.github.prometheuskr.sipwon.session.ModuleConfig;

@Configuration
@EnableConfigurationProperties(HsmProperties.class)
public class SipwonAutoConfiguration {

    @Bean
    public HsmSessionFactory hsmSessionFactory(HsmProperties hsmProperties) {
        try {
            ModuleConfig moduleConfig = new ModuleConfig(hsmProperties.getPkcs11LibraryPath(),
                    hsmProperties.getExcludedTokenPattern(),
                    hsmProperties.getTarget().stream()
                            .collect(Collectors.toMap(
                                    HsmProperties.TokenPin::getTokenLabel,
                                    HsmProperties.TokenPin::getPin)));
            return new HsmSessionFactoryImpl(moduleConfig);
        } catch (TokenException | IOException e) {
            throw new RuntimeException("Failed to initialize HSM module configuration", e);
        }
    }
}