package io.github.prometheuskr.sipwon.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@ConfigurationProperties(prefix = "sipwon")
public class HsmProperties {
    private String pkcs11LibraryPath;
    private String excludedTokenPattern = "AdminToken.*";
    private List<TokenPin> target = new ArrayList<>();

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TokenPin {
        private String tokenLabel;
        private String pin;
    }
}
