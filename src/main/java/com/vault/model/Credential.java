package com.vault.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "credentials")
public class Credential {

    @Id
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    private User owner;

    @Column(name = "encrypted_name", nullable = false, columnDefinition = "TEXT")
    private String encryptedName;

    @Column(name = "encrypted_url", columnDefinition = "TEXT")
    private String encryptedUrl;

    @Column(name = "encrypted_username", columnDefinition = "TEXT")
    private String encryptedUsername;

    @Column(name = "encrypted_password", nullable = false, columnDefinition = "TEXT")
    private String encryptedPassword;

    @Column(name = "encrypted_notes", columnDefinition = "TEXT")
    private String encryptedNotes;

    @Column(nullable = false)
    private boolean favorite;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "password_updated_at", nullable = false)
    private Instant passwordUpdatedAt;

    protected Credential() {
    }

    public Credential(User owner) {
        this.id = UUID.randomUUID();
        this.owner = owner;
        this.createdAt = Instant.now();
        this.updatedAt = this.createdAt;
        this.passwordUpdatedAt = this.createdAt;
    }

    public void updateContents(String encryptedName, String encryptedUrl, String encryptedUsername,
                               String encryptedPassword, String encryptedNotes, boolean favorite,
                               boolean passwordChanged) {
        this.encryptedName = encryptedName;
        this.encryptedUrl = encryptedUrl;
        this.encryptedUsername = encryptedUsername;
        this.encryptedPassword = encryptedPassword;
        this.encryptedNotes = encryptedNotes;
        this.favorite = favorite;
        this.updatedAt = Instant.now();
        if (passwordChanged) {
            this.passwordUpdatedAt = this.updatedAt;
        }
    }

    public void setFavorite(boolean favorite) {
        this.favorite = favorite;
    }

    public UUID getId() {
        return id;
    }

    public User getOwner() {
        return owner;
    }

    public String getEncryptedName() {
        return encryptedName;
    }

    public String getEncryptedUrl() {
        return encryptedUrl;
    }

    public String getEncryptedUsername() {
        return encryptedUsername;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public String getEncryptedNotes() {
        return encryptedNotes;
    }

    public boolean isFavorite() {
        return favorite;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public Instant getPasswordUpdatedAt() {
        return passwordUpdatedAt;
    }
}
