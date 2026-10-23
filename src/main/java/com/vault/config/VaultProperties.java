package com.vault.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "vault")
public record VaultProperties(
        String preloginSecret,
        boolean cookieSecure,
        Kdf kdf,
        Login login,
        Credentials credentials) {

    public record Kdf(int minIterations, int maxIterations, int defaultIterations) {
    }

    public record Login(int maxFailuresPerAccount, int maxFailuresPerIp, Duration window) {
    }

    public record Credentials(int maxPerUser, int staleAfterDays) {
    }
}
