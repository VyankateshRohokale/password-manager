package com.vault.dto;

import com.vault.crypto.CryptoFormats;
import com.vault.service.EmailNormalizer;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank @Email @Size(max = 254) String email,
        @NotBlank @Pattern(regexp = CryptoFormats.AUTH_HASH, message = "must be a 256-bit Base64 value") String authHash,
        @NotBlank @Pattern(regexp = CryptoFormats.KDF_SALT, message = "must be a 128-bit Base64 value") String kdfSalt,
        @NotNull Integer kdfIterations,
        @NotBlank @Pattern(regexp = CryptoFormats.PROTECTED_VAULT_KEY, message = "must be an encrypted vault key") String protectedVaultKey) {

    public RegisterRequest {
        email = EmailNormalizer.normalize(email);
    }

    @Override
    public String toString() {
        return "RegisterRequest[email=" + email + "]";
    }
}
