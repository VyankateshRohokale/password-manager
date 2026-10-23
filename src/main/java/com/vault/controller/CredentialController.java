package com.vault.controller;

import com.vault.dto.CredentialRequest;
import com.vault.dto.CredentialResponse;
import com.vault.dto.FavoriteRequest;
import com.vault.security.VaultUserPrincipal;
import com.vault.service.CredentialService;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/credentials")
public class CredentialController {

    private final CredentialService credentialService;

    public CredentialController(CredentialService credentialService) {
        this.credentialService = credentialService;
    }

    @GetMapping
    public List<CredentialResponse> list(@AuthenticationPrincipal VaultUserPrincipal principal) {
        return credentialService.list(principal.getId());
    }

    @GetMapping("/{id}")
    public CredentialResponse get(@AuthenticationPrincipal VaultUserPrincipal principal, @PathVariable UUID id) {
        return credentialService.get(principal.getId(), id);
    }

    @PostMapping
    public ResponseEntity<CredentialResponse> create(@AuthenticationPrincipal VaultUserPrincipal principal,
                                                     @Valid @RequestBody CredentialRequest request) {
        CredentialResponse created = credentialService.create(principal.getId(), request);
        return ResponseEntity.created(URI.create("/api/credentials/" + created.id())).body(created);
    }

    @PutMapping("/{id}")
    public CredentialResponse update(@AuthenticationPrincipal VaultUserPrincipal principal, @PathVariable UUID id,
                                     @Valid @RequestBody CredentialRequest request) {
        return credentialService.update(principal.getId(), id, request);
    }

    @PatchMapping("/{id}/favorite")
    public CredentialResponse favorite(@AuthenticationPrincipal VaultUserPrincipal principal, @PathVariable UUID id,
                                       @Valid @RequestBody FavoriteRequest request) {
        return credentialService.setFavorite(principal.getId(), id, request.favorite());
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@AuthenticationPrincipal VaultUserPrincipal principal, @PathVariable UUID id) {
        credentialService.delete(principal.getId(), id);
    }
}
