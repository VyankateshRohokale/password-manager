package com.vault.dto;

import java.time.Instant;

public record SecurityOverviewResponse(
        long totalCredentials,
        long favoriteCredentials,
        long stalePasswords,
        int staleAfterDays,
        Instant oldestPasswordUpdate,
        Instant lastVaultUpdate,
        String kdfAlgorithm,
        int kdfIterations,
        boolean breachMonitoringAvailable) {
}
