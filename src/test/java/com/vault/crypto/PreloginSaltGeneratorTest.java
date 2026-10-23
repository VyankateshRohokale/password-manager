package com.vault.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import com.vault.config.VaultProperties;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class PreloginSaltGeneratorTest {

    private static PreloginSaltGenerator generator(String secret) {
        return new PreloginSaltGenerator(new VaultProperties(secret, false, null, null, null));
    }

    @Test
    void decoySaltsAreStablePerEmailAndLookLikeRealSalts() {
        PreloginSaltGenerator generator = generator("secret-one");
        String salt = generator.decoySaltFor("ghost@example.com");
        assertThat(salt).isEqualTo(generator.decoySaltFor("ghost@example.com")).matches(CryptoFormats.KDF_SALT);
        assertThat(Base64.getDecoder().decode(salt)).hasSize(16);
        assertThat(generator.decoySaltFor("other@example.com")).isNotEqualTo(salt);
    }

    @Test
    void decoySaltsDependOnTheServerSecret() {
        assertThat(generator("secret-one").decoySaltFor("ghost@example.com"))
                .isNotEqualTo(generator("secret-two").decoySaltFor("ghost@example.com"));
    }
}
