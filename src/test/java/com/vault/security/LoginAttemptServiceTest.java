package com.vault.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.vault.config.VaultProperties;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class LoginAttemptServiceTest {

    private static final class MutableClock extends Clock {
        private Instant now = Instant.parse("2026-01-01T00:00:00Z");

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private final MutableClock clock = new MutableClock();
    private final LoginAttemptService service = new LoginAttemptService(new VaultProperties(null, false, null,
            new VaultProperties.Login(3, 5, Duration.ofMinutes(15)), null), clock);

    @Test
    void blocksAnAccountAfterTooManyFailuresAndRecoversAfterTheWindow() {
        for (int i = 0; i < 3; i++) {
            assertThat(service.isBlocked("a@example.com", "10.0.0.1")).isFalse();
            service.recordFailure("a@example.com", "10.0.0.1");
        }
        assertThat(service.isBlocked("a@example.com", "10.0.0.2")).isTrue();
        assertThat(service.isBlocked("b@example.com", "10.0.0.2")).isFalse();

        clock.now = clock.now.plus(Duration.ofMinutes(16));
        assertThat(service.isBlocked("a@example.com", "10.0.0.1")).isFalse();
    }

    @Test
    void blocksAnIpThatTargetsManyAccounts() {
        for (int i = 0; i < 5; i++) {
            service.recordFailure("user" + i + "@example.com", "10.9.9.9");
        }
        assertThat(service.isBlocked("fresh@example.com", "10.9.9.9")).isTrue();
        assertThat(service.isBlocked("fresh@example.com", "10.0.0.1")).isFalse();
    }

    @Test
    void successClearsAccountFailures() {
        service.recordFailure("c@example.com", "10.0.0.1");
        service.recordFailure("c@example.com", "10.0.0.1");
        service.recordSuccess("c@example.com");
        service.recordFailure("c@example.com", "10.0.0.1");
        assertThat(service.isBlocked("c@example.com", "10.0.0.1")).isFalse();
    }
}
