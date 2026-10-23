package com.vault.dto;

import com.vault.crypto.CryptoFormats;
import com.vault.service.EmailNormalizer;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank @Email @Size(max = 254) String email,
        @NotBlank @Pattern(regexp = CryptoFormats.AUTH_HASH, message = "must be a 256-bit Base64 value") String authHash) {

    public LoginRequest {
        email = EmailNormalizer.normalize(email);
    }

    @Override
    public String toString() {
        return "LoginRequest[email=" + email + "]";
    }
}
