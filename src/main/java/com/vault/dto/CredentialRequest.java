package com.vault.dto;

import com.vault.crypto.CryptoFormats;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record CredentialRequest(
        @NotBlank @Size(max = 2048) @Pattern(regexp = CryptoFormats.CIPHERTEXT, message = "must be AES-GCM ciphertext") String encryptedName,
        @Size(max = 4096) @Pattern(regexp = CryptoFormats.CIPHERTEXT, message = "must be AES-GCM ciphertext") String encryptedUrl,
        @Size(max = 2048) @Pattern(regexp = CryptoFormats.CIPHERTEXT, message = "must be AES-GCM ciphertext") String encryptedUsername,
        @NotBlank @Size(max = 2048) @Pattern(regexp = CryptoFormats.CIPHERTEXT, message = "must be AES-GCM ciphertext") String encryptedPassword,
        @Size(max = 16384) @Pattern(regexp = CryptoFormats.CIPHERTEXT, message = "must be AES-GCM ciphertext") String encryptedNotes,
        boolean favorite,
        boolean passwordChanged) {
}
