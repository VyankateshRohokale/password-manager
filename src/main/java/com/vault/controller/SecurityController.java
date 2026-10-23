package com.vault.controller;

import com.vault.dto.SecurityOverviewResponse;
import com.vault.security.VaultUserPrincipal;
import com.vault.service.SecurityOverviewService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/security")
public class SecurityController {

    private final SecurityOverviewService overviewService;

    public SecurityController(SecurityOverviewService overviewService) {
        this.overviewService = overviewService;
    }

    @GetMapping("/overview")
    public SecurityOverviewResponse overview(@AuthenticationPrincipal VaultUserPrincipal principal) {
        return overviewService.overview(principal.getId());
    }
}
