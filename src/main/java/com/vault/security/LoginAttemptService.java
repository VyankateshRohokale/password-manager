package com.vault.security;

import com.vault.config.VaultProperties;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class LoginAttemptService {

    private final Map<String, Deque<Instant>> accountFailures = new ConcurrentHashMap<>();
    private final Map<String, Deque<Instant>> ipFailures = new ConcurrentHashMap<>();
    private final VaultProperties.Login config;
    private final Clock clock;

    @Autowired
    public LoginAttemptService(VaultProperties properties) {
        this(properties, Clock.systemUTC());
    }

    LoginAttemptService(VaultProperties properties, Clock clock) {
        this.config = properties.login();
        this.clock = clock;
    }

    public boolean isBlocked(String email, String ip) {
        return recentCount(accountFailures, email) >= config.maxFailuresPerAccount()
                || recentCount(ipFailures, ip) >= config.maxFailuresPerIp();
    }

    public void recordFailure(String email, String ip) {
        Instant now = clock.instant();
        record(accountFailures, email, now);
        record(ipFailures, ip, now);
    }

    public void recordSuccess(String email) {
        accountFailures.remove(email);
    }

    public void reset() {
        accountFailures.clear();
        ipFailures.clear();
    }

    private void record(Map<String, Deque<Instant>> store, String key, Instant now) {
        store.compute(key, (k, deque) -> {
            Deque<Instant> attempts = deque == null ? new ArrayDeque<>() : deque;
            prune(attempts);
            attempts.addLast(now);
            return attempts;
        });
    }

    private int recentCount(Map<String, Deque<Instant>> store, String key) {
        Deque<Instant> result = store.computeIfPresent(key, (k, deque) -> {
            prune(deque);
            return deque.isEmpty() ? null : deque;
        });
        return result == null ? 0 : result.size();
    }

    private void prune(Deque<Instant> attempts) {
        Instant cutoff = clock.instant().minus(config.window());
        while (!attempts.isEmpty() && attempts.peekFirst().isBefore(cutoff)) {
            attempts.pollFirst();
        }
    }
}
