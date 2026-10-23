package com.vault.dto;

import java.time.Instant;

public record SessionInfoResponse(
        Instant createdAt,
        Instant lastAccessedAt,
        int maxInactiveSeconds,
        int activeSessions) {
}
