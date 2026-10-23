package com.vault.dto;

import com.vault.service.EmailNormalizer;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PreloginRequest(
        @NotBlank @Email @Size(max = 254) String email) {

    public PreloginRequest {
        email = EmailNormalizer.normalize(email);
    }
}
