package com.vault.controller;

import com.vault.dto.ChangePasswordRequest;
import com.vault.dto.LoginRequest;
import com.vault.dto.PreloginRequest;
import com.vault.dto.PreloginResponse;
import com.vault.dto.RegisterRequest;
import com.vault.dto.SessionInfoResponse;
import com.vault.dto.UserResponse;
import com.vault.security.VaultUserPrincipal;
import com.vault.service.AuthService;
import com.vault.service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final SessionService sessionService;

    public AuthController(AuthService authService, SessionService sessionService) {
        this.authService = authService;
        this.sessionService = sessionService;
    }

    @GetMapping("/csrf")
    public Map<String, String> csrf(CsrfToken token) {
        return Map.of("headerName", token.getHeaderName(), "token", token.getToken());
    }

    @PostMapping("/prelogin")
    public PreloginResponse prelogin(@Valid @RequestBody PreloginRequest request) {
        return authService.prelogin(request.email());
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public UserResponse register(@Valid @RequestBody RegisterRequest request,
                                 HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        Authentication authentication = authService.register(request);
        sessionService.establish(authentication, httpRequest, httpResponse);
        return authService.currentUser(((VaultUserPrincipal) authentication.getPrincipal()).getId());
    }

    @PostMapping("/login")
    public UserResponse login(@Valid @RequestBody LoginRequest request,
                              HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        Authentication authentication = authService.login(request, httpRequest.getRemoteAddr());
        sessionService.establish(authentication, httpRequest, httpResponse);
        return authService.currentUser(((VaultUserPrincipal) authentication.getPrincipal()).getId());
    }

    @GetMapping("/me")
    public UserResponse me(@AuthenticationPrincipal VaultUserPrincipal principal) {
        return authService.currentUser(principal.getId());
    }

    @GetMapping("/session")
    public SessionInfoResponse session(@AuthenticationPrincipal VaultUserPrincipal principal,
                                       HttpServletRequest request) {
        return sessionService.describe(principal, request);
    }

    @PostMapping("/sessions/revoke-others")
    public Map<String, Integer> revokeOtherSessions(@AuthenticationPrincipal VaultUserPrincipal principal,
                                                    HttpServletRequest request) {
        return Map.of("revoked", sessionService.expireOtherSessions(principal, request));
    }

    @PostMapping("/change-password")
    public UserResponse changePassword(@AuthenticationPrincipal VaultUserPrincipal principal,
                                       @Valid @RequestBody ChangePasswordRequest request,
                                       HttpServletRequest httpRequest) {
        UserResponse updated = authService.changeMasterPassword(principal.getId(), request,
                httpRequest.getRemoteAddr());
        sessionService.expireOtherSessions(principal, httpRequest);
        httpRequest.changeSessionId();
        return updated;
    }
}
