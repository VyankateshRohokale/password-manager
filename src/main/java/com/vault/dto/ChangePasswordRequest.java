package com.vault.dto;

import com.vault.crypto.CryptoFormats;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public record ChangePasswordRequest(
        @NotBlank @Pattern(regexp = CryptoFormats.AUTH_HASH, message = "must be a 256-bit Base64 value") String currentAuthHash,
        @NotBlank @Pattern(regexp = CryptoFormats.AUTH_HASH, message = "must be a 256-bit Base64 value") String newAuthHash,
        @NotBlank @Pattern(regexp = CryptoFormats.KDF_SALT, message = "must be a 128-bit Base64 value") String newKdfSalt,
        @NotNull Integer newKdfIterations,
        @NotBlank @Pattern(regexp = CryptoFormats.PROTECTED_VAULT_KEY, message = "must be an encrypted vault key") String newProtectedVaultKey) {

    @Override
    public String toString() {
        return "ChangePasswordRequest[redacted]";
    }
}
