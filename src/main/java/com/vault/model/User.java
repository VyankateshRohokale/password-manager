package com.vault.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "users")
public class User {

    @Id
    private UUID id;

    @Column(nullable = false, unique = true, length = 254)
    private String email;

    @Column(name = "auth_hash", nullable = false)
    private String authHash;

    @Column(name = "kdf_salt", nullable = false, length = 64)
    private String kdfSalt;

    @Column(name = "kdf_iterations", nullable = false)
    private int kdfIterations;

    @Column(name = "protected_vault_key", nullable = false, length = 256)
    private String protectedVaultKey;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected User() {
    }

    public User(String email, String authHash, String kdfSalt, int kdfIterations, String protectedVaultKey) {
        this.id = UUID.randomUUID();
        this.email = email;
        this.authHash = authHash;
        this.kdfSalt = kdfSalt;
        this.kdfIterations = kdfIterations;
        this.protectedVaultKey = protectedVaultKey;
        this.createdAt = Instant.now();
        this.updatedAt = this.createdAt;
    }

    public void changeMasterPassword(String authHash, String kdfSalt, int kdfIterations, String protectedVaultKey) {
        this.authHash = authHash;
        this.kdfSalt = kdfSalt;
        this.kdfIterations = kdfIterations;
        this.protectedVaultKey = protectedVaultKey;
        this.updatedAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getAuthHash() {
        return authHash;
    }

    public String getKdfSalt() {
        return kdfSalt;
    }

    public int getKdfIterations() {
        return kdfIterations;
    }

    public String getProtectedVaultKey() {
        return protectedVaultKey;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
