package com.vault.security;

import com.vault.repository.UserRepository;
import com.vault.service.EmailNormalizer;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class VaultUserDetailsService implements UserDetailsService {

    private final UserRepository users;

    public VaultUserDetailsService(UserRepository users) {
        this.users = users;
    }

    @Override
    public UserDetails loadUserByUsername(String email) {
        return users.findByEmail(EmailNormalizer.normalize(email))
                .map(VaultUserPrincipal::new)
                .orElseThrow(() -> new UsernameNotFoundException("Unknown account"));
    }
}
