package com.vault.service;

import com.vault.dto.SessionInfoResponse;
import com.vault.security.VaultUserPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.time.Instant;
import java.util.List;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;

@Service
public class SessionService {

    private final SecurityContextRepository contextRepository;
    private final SessionRegistry sessionRegistry;

    public SessionService(SecurityContextRepository contextRepository, SessionRegistry sessionRegistry) {
        this.contextRepository = contextRepository;
        this.sessionRegistry = sessionRegistry;
    }

    public void establish(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
        HttpSession previous = request.getSession(false);
        if (previous != null) {
            previous.invalidate();
        }
        HttpSession session = request.getSession(true);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        contextRepository.saveContext(context, request, response);
        sessionRegistry.registerNewSession(session.getId(), authentication.getPrincipal());
    }

    public SessionInfoResponse describe(VaultUserPrincipal principal, HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return new SessionInfoResponse(null, null, 0, activeSessions(principal).size());
        }
        return new SessionInfoResponse(
                Instant.ofEpochMilli(session.getCreationTime()),
                Instant.ofEpochMilli(session.getLastAccessedTime()),
                session.getMaxInactiveInterval(),
                activeSessions(principal).size());
    }

    public int expireOtherSessions(VaultUserPrincipal principal, HttpServletRequest request) {
        HttpSession current = request.getSession(false);
        String currentId = current == null ? null : current.getId();
        int expired = 0;
        for (SessionInformation info : activeSessions(principal)) {
            if (!info.getSessionId().equals(currentId)) {
                info.expireNow();
                expired++;
            }
        }
        return expired;
    }

    private List<SessionInformation> activeSessions(VaultUserPrincipal principal) {
        return sessionRegistry.getAllSessions(principal, false);
    }
}
