package com.vault.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vault.support.TestVaultClient;
import com.vault.support.TestVaultClient.MasterKeys;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import javax.crypto.AEADBadTagException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Verifies that the Java reference client and the browser's crypto.js agree byte-for-byte.
 * crypto-vectors.json is produced by running the real crypto.js under Node (npm run vectors).
 */
class BrowserCompatibilityTest {

    private static JsonNode vector;
    private static MasterKeys keys;
    private static byte[] vaultKey;

    @BeforeAll
    static void loadVector() throws Exception {
        try (InputStream in = BrowserCompatibilityTest.class.getResourceAsStream("/crypto-vectors.json")) {
            vector = new ObjectMapper().readTree(in);
        }
        keys = TestVaultClient.deriveMasterKeys(vector.get("password").asText(), vector.get("kdfSalt").asText(),
                vector.get("kdfIterations").asInt());
        vaultKey = TestVaultClient.unwrapVaultKey(keys.wrapKey(), vector.get("protectedVaultKey").asText());
    }

    @Test
    void javaDerivesTheSameAuthenticationKeyAsTheBrowser() {
        assertThat(keys.authHash()).isEqualTo(vector.get("authHash").asText());
    }

    @Test
    void javaDecryptsEveryFieldTheBrowserEncrypted() throws Exception {
        assertThat(vaultKey).hasSize(32);
        Iterator<Map.Entry<String, JsonNode>> fields = vector.get("fields").fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            assertThat(TestVaultClient.decryptField(vaultKey, field.getKey(), field.getValue().get("ciphertext").asText()))
                    .isEqualTo(field.getValue().get("plaintext").asText());
        }
    }

    @Test
    void browserCiphertextMatchesTheServerSideFormatRules() {
        assertThat(vector.get("protectedVaultKey").asText()).matches(CryptoFormats.PROTECTED_VAULT_KEY);
        assertThat(vector.get("authHash").asText()).matches(CryptoFormats.AUTH_HASH);
        assertThat(vector.get("kdfSalt").asText()).matches(CryptoFormats.KDF_SALT);
        vector.get("fields").forEach(field -> assertThat(field.get("ciphertext").asText()).matches(CryptoFormats.CIPHERTEXT));
    }

    @Test
    void tamperedBrowserCiphertextIsRejected() {
        String ciphertext = vector.get("fields").get("password").get("ciphertext").asText();
        assertThatThrownBy(() -> TestVaultClient.decryptField(vaultKey, "password", TestVaultClient.tamper(ciphertext)))
                .isInstanceOf(AEADBadTagException.class);
    }

    @Test
    void associatedDataPreventsSwappingFields() {
        String passwordCiphertext = vector.get("fields").get("password").get("ciphertext").asText();
        assertThatThrownBy(() -> TestVaultClient.decryptField(vaultKey, "username", passwordCiphertext))
                .isInstanceOf(AEADBadTagException.class);
    }

    @Test
    void javaEncryptionUsesAFreshIvEveryTime() {
        Set<String> ivs = new HashSet<>();
        for (int i = 0; i < 500; i++) {
            ivs.add(TestVaultClient.encryptField(vaultKey, "password", "same").split("\\.")[1]);
        }
        assertThat(ivs).hasSize(500);
    }
}
