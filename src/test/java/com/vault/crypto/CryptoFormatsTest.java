package com.vault.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import com.vault.support.TestVaultClient;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

class CryptoFormatsTest {

    @Test
    void acceptsWellFormedValues() {
        assertThat(TestVaultClient.fakeCiphertext()).matches(CryptoFormats.CIPHERTEXT);
        assertThat(TestVaultClient.encrypt(TestVaultClient.random(32), new byte[0], "notes")).matches(CryptoFormats.CIPHERTEXT);
        assertThat(TestVaultClient.fakeProtectedVaultKey()).matches(CryptoFormats.PROTECTED_VAULT_KEY);
        assertThat(TestVaultClient.fakeAuthHash()).matches(CryptoFormats.AUTH_HASH);
        assertThat(TestVaultClient.newSalt()).matches(CryptoFormats.KDF_SALT);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "hunter2",
            "aHVudGVyMg==",
            "v1..AAAAAAAAAAAAAAAAAAAAAAAA",
            "v1.AAAAAAAAAAAAAAAA.",
            "v1.AAAAAAAAAAAAAAAA.AAAA",
            "v2.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAA",
            "v1.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAA*",
            "v1.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAA.extra",
            "<script>alert(1)</script>"
    })
    void rejectsPlaintextAndMalformedCiphertext(String value) {
        assertThat(value).doesNotMatch(CryptoFormats.CIPHERTEXT);
    }
}
