package com.vault.service;

import com.vault.config.VaultProperties;
import com.vault.dto.CredentialRequest;
import com.vault.dto.CredentialResponse;
import com.vault.exception.ApiException;
import com.vault.model.Credential;
import com.vault.model.User;
import com.vault.repository.CredentialRepository;
import com.vault.repository.UserRepository;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CredentialService {

    private static final String NOT_FOUND = "Credential not found.";

    private final CredentialRepository credentials;
    private final UserRepository users;
    private final int maxPerUser;

    public CredentialService(CredentialRepository credentials, UserRepository users, VaultProperties properties) {
        this.credentials = credentials;
        this.users = users;
        this.maxPerUser = properties.credentials().maxPerUser();
    }

    @Transactional(readOnly = true)
    public List<CredentialResponse> list(UUID ownerId) {
        return credentials.findAllByOwnerIdOrderByUpdatedAtDesc(ownerId).stream()
                .map(CredentialResponse::from)
                .toList();
    }

    @Transactional(readOnly = true)
    public CredentialResponse get(UUID ownerId, UUID credentialId) {
        return CredentialResponse.from(requireOwned(ownerId, credentialId));
    }

    @Transactional
    public CredentialResponse create(UUID ownerId, CredentialRequest request) {
        if (credentials.countByOwnerId(ownerId) >= maxPerUser) {
            throw ApiException.conflict("Your vault has reached the maximum of " + maxPerUser + " credentials.");
        }
        User owner = users.getReferenceById(ownerId);
        Credential credential = new Credential(owner);
        apply(credential, request, true);
        return CredentialResponse.from(credentials.save(credential));
    }

    @Transactional
    public CredentialResponse update(UUID ownerId, UUID credentialId, CredentialRequest request) {
        Credential credential = requireOwned(ownerId, credentialId);
        apply(credential, request, request.passwordChanged());
        return CredentialResponse.from(credential);
    }

    @Transactional
    public CredentialResponse setFavorite(UUID ownerId, UUID credentialId, boolean favorite) {
        Credential credential = requireOwned(ownerId, credentialId);
        credential.setFavorite(favorite);
        return CredentialResponse.from(credential);
    }

    @Transactional
    public void delete(UUID ownerId, UUID credentialId) {
        credentials.delete(requireOwned(ownerId, credentialId));
    }

    private Credential requireOwned(UUID ownerId, UUID credentialId) {
        return credentials.findByIdAndOwnerId(credentialId, ownerId)
                .orElseThrow(() -> ApiException.notFound(NOT_FOUND));
    }

    private void apply(Credential credential, CredentialRequest request, boolean passwordChanged) {
        credential.updateContents(request.encryptedName(), blankToNull(request.encryptedUrl()),
                blankToNull(request.encryptedUsername()), request.encryptedPassword(),
                blankToNull(request.encryptedNotes()), request.favorite(), passwordChanged);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
