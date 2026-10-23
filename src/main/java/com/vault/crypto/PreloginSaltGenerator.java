package com.vault.crypto;

import com.vault.config.VaultProperties;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Produces a stable, secret-keyed decoy salt for emails that have no account so that the
 * prelogin endpoint does not reveal which emails are registered.
 */
@Component
public class PreloginSaltGenerator {

    private static final Logger log = LoggerFactory.getLogger(PreloginSaltGenerator.class);
    private static final String HMAC = "HmacSHA256";

    private final SecretKeySpec key;

    public PreloginSaltGenerator(VaultProperties properties) {
        byte[] secret;
        String configured = properties.preloginSecret();
        if (configured == null || configured.isBlank()) {
            log.warn("VAULT_PRELOGIN_SECRET is not set; using a random per-process secret. "
                    + "Decoy salts will change on restart.");
            secret = new byte[32];
            new SecureRandom().nextBytes(secret);
        } else {
            secret = configured.getBytes(StandardCharsets.UTF_8);
        }
        this.key = new SecretKeySpec(secret, HMAC);
        Arrays.fill(secret, (byte) 0);
    }

    public String decoySaltFor(String normalizedEmail) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(key);
            byte[] digest = mac.doFinal(("prelogin:" + normalizedEmail).getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(Arrays.copyOf(digest, 16));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }
}
