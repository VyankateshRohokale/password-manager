package com.vault.service;

import com.vault.config.VaultProperties;
import com.vault.dto.SecurityOverviewResponse;
import com.vault.dto.UserResponse;
import com.vault.repository.CredentialRepository;
import com.vault.repository.UserRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SecurityOverviewService {

    private final CredentialRepository credentials;
    private final UserRepository users;
    private final int staleAfterDays;

    public SecurityOverviewService(CredentialRepository credentials, UserRepository users,
                                   VaultProperties properties) {
        this.credentials = credentials;
        this.users = users;
        this.staleAfterDays = properties.credentials().staleAfterDays();
    }

    @Transactional(readOnly = true)
    public SecurityOverviewResponse overview(UUID ownerId) {
        Instant threshold = Instant.now().minus(Duration.ofDays(staleAfterDays));
        int iterations = users.findById(ownerId).map(user -> user.getKdfIterations()).orElse(0);
        return new SecurityOverviewResponse(
                credentials.countByOwnerId(ownerId),
                credentials.countByOwnerIdAndFavoriteTrue(ownerId),
                credentials.countByOwnerIdAndPasswordUpdatedAtBefore(ownerId, threshold),
                staleAfterDays,
                credentials.findOldestPasswordUpdate(ownerId).orElse(null),
                credentials.findLatestUpdate(ownerId).orElse(null),
                UserResponse.KDF_ALGORITHM,
                iterations,
                false);
    }
}
