package com.vault.dto;

import com.vault.model.User;
import java.time.Instant;
import java.util.UUID;

public record UserResponse(
        UUID id,
        String email,
        Instant createdAt,
        Instant updatedAt,
        String kdfAlgorithm,
        String kdfSalt,
        int kdfIterations,
        String protectedVaultKey) {

    public static final String KDF_ALGORITHM = "PBKDF2-HMAC-SHA256";

    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getEmail(), user.getCreatedAt(), user.getUpdatedAt(),
                KDF_ALGORITHM, user.getKdfSalt(), user.getKdfIterations(), user.getProtectedVaultKey());
    }
}
