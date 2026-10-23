package com.vault.dto;

import com.vault.model.Credential;
import java.time.Instant;
import java.util.UUID;

public record CredentialResponse(
        UUID id,
        String encryptedName,
        String encryptedUrl,
        String encryptedUsername,
        String encryptedPassword,
        String encryptedNotes,
        boolean favorite,
        Instant createdAt,
        Instant updatedAt,
        Instant passwordUpdatedAt) {

    public static CredentialResponse from(Credential credential) {
        return new CredentialResponse(credential.getId(), credential.getEncryptedName(),
                credential.getEncryptedUrl(), credential.getEncryptedUsername(),
                credential.getEncryptedPassword(), credential.getEncryptedNotes(), credential.isFavorite(),
                credential.getCreatedAt(), credential.getUpdatedAt(), credential.getPasswordUpdatedAt());
    }
}
