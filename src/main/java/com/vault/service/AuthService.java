package com.vault.service;

import com.vault.config.VaultProperties;
import com.vault.dto.ChangePasswordRequest;
import com.vault.dto.LoginRequest;
import com.vault.dto.PreloginResponse;
import com.vault.dto.RegisterRequest;
import com.vault.dto.UserResponse;
import com.vault.crypto.PreloginSaltGenerator;
import com.vault.exception.ApiException;
import com.vault.exception.InvalidCredentialsException;
import com.vault.exception.TooManyAttemptsException;
import com.vault.model.User;
import com.vault.repository.UserRepository;
import com.vault.security.LoginAttemptService;
import com.vault.security.VaultUserPrincipal;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private static final String DUPLICATE_MESSAGE =
            "An account with this email already exists. Log in instead.";

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final LoginAttemptService loginAttempts;
    private final PreloginSaltGenerator decoySalts;
    private final VaultProperties.Kdf kdf;

    public AuthService(UserRepository users, PasswordEncoder passwordEncoder,
                       AuthenticationManager authenticationManager, LoginAttemptService loginAttempts,
                       PreloginSaltGenerator decoySalts, VaultProperties properties) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.loginAttempts = loginAttempts;
        this.decoySalts = decoySalts;
        this.kdf = properties.kdf();
    }

    @Transactional(readOnly = true)
    public PreloginResponse prelogin(String email) {
        String normalized = EmailNormalizer.normalize(email);
        return users.findByEmail(normalized)
                .map(user -> new PreloginResponse(UserResponse.KDF_ALGORITHM, user.getKdfSalt(), user.getKdfIterations()))
                .orElseGet(() -> new PreloginResponse(UserResponse.KDF_ALGORITHM,
                        decoySalts.decoySaltFor(normalized), kdf.defaultIterations()));
    }

    @Transactional
    public Authentication register(RegisterRequest request) {
        String email = EmailNormalizer.normalize(request.email());
        requireSupportedIterations(request.kdfIterations());
        if (users.existsByEmail(email)) {
            throw ApiException.conflict(DUPLICATE_MESSAGE);
        }
        User user = new User(email, passwordEncoder.encode(request.authHash()), request.kdfSalt(),
                request.kdfIterations(), request.protectedVaultKey());
        try {
            users.saveAndFlush(user);
        } catch (DataIntegrityViolationException e) {
            throw ApiException.conflict(DUPLICATE_MESSAGE);
        }
        VaultUserPrincipal principal = new VaultUserPrincipal(user);
        principal.eraseCredentials();
        return UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
    }

    public Authentication login(LoginRequest request, String clientIp) {
        String email = EmailNormalizer.normalize(request.email());
        if (loginAttempts.isBlocked(email, clientIp)) {
            throw new TooManyAttemptsException();
        }
        try {
            Authentication authentication = authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(email, request.authHash()));
            loginAttempts.recordSuccess(email);
            return authentication;
        } catch (AuthenticationException e) {
            loginAttempts.recordFailure(email, clientIp);
            throw new InvalidCredentialsException();
        }
    }

    @Transactional(readOnly = true)
    public UserResponse currentUser(UUID userId) {
        return UserResponse.from(requireUser(userId));
    }

    @Transactional
    public UserResponse changeMasterPassword(UUID userId, ChangePasswordRequest request, String clientIp) {
        User user = requireUser(userId);
        if (loginAttempts.isBlocked(user.getEmail(), clientIp)) {
            throw new TooManyAttemptsException();
        }
        if (!passwordEncoder.matches(request.currentAuthHash(), user.getAuthHash())) {
            loginAttempts.recordFailure(user.getEmail(), clientIp);
            throw ApiException.badRequest("Your current master password is incorrect.");
        }
        requireSupportedIterations(request.newKdfIterations());
        if (request.newKdfSalt().equals(user.getKdfSalt())) {
            throw ApiException.badRequest("A new key-derivation salt is required.");
        }
        user.changeMasterPassword(passwordEncoder.encode(request.newAuthHash()), request.newKdfSalt(),
                request.newKdfIterations(), request.newProtectedVaultKey());
        return UserResponse.from(user);
    }

    private User requireUser(UUID userId) {
        return users.findById(userId)
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED,
                        "Your session has expired or you are not signed in."));
    }

    private void requireSupportedIterations(Integer iterations) {
        if (iterations == null || iterations < kdf.minIterations() || iterations > kdf.maxIterations()) {
            throw ApiException.badRequest("Key-derivation iterations must be between "
                    + kdf.minIterations() + " and " + kdf.maxIterations() + ".");
        }
    }
}
