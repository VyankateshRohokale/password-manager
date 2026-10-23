package com.vault.repository;

import com.vault.model.Credential;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface CredentialRepository extends JpaRepository<Credential, UUID> {

    List<Credential> findAllByOwnerIdOrderByUpdatedAtDesc(UUID ownerId);

    Optional<Credential> findByIdAndOwnerId(UUID id, UUID ownerId);

    long countByOwnerId(UUID ownerId);

    long countByOwnerIdAndFavoriteTrue(UUID ownerId);

    long countByOwnerIdAndPasswordUpdatedAtBefore(UUID ownerId, Instant threshold);

    @Query("select min(c.passwordUpdatedAt) from Credential c where c.owner.id = :ownerId")
    Optional<Instant> findOldestPasswordUpdate(UUID ownerId);

    @Query("select max(c.updatedAt) from Credential c where c.owner.id = :ownerId")
    Optional<Instant> findLatestUpdate(UUID ownerId);
}
