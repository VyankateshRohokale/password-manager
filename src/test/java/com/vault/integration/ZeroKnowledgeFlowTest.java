package com.vault.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.vault.support.IntegrationTestBase;
import com.vault.support.TestVaultClient;
import com.vault.support.TestVaultClient.MasterKeys;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.crypto.AEADBadTagException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;

/** Drives the API exactly as the browser does, using real key derivation and AES-GCM. */
class ZeroKnowledgeFlowTest extends IntegrationTestBase {

    private static final String MASTER_PASSWORD = "orbit-Canyon-velvet-71-lantern";
    private static final String SITE_PASSWORD = "Xq7!vR2#pL9$wK4m";

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void serverOnlyEverHandlesDerivedKeysAndCiphertext() throws Exception {
        String salt = TestVaultClient.newSalt();
        MasterKeys keys = TestVaultClient.deriveMasterKeys(MASTER_PASSWORD, salt, TestVaultClient.ITERATIONS);
        byte[] vaultKey = TestVaultClient.random(32);

        Map<String, Object> registration = new LinkedHashMap<>();
        registration.put("email", "zk@example.com");
        registration.put("authHash", keys.authHash());
        registration.put("kdfSalt", salt);
        registration.put("kdfIterations", TestVaultClient.ITERATIONS);
        registration.put("protectedVaultKey", TestVaultClient.wrapVaultKey(keys.wrapKey(), vaultKey));
        mvc.perform(jsonPost("/api/auth/register", registration)).andExpect(status().isCreated());

        JsonNode prelogin = read(mvc.perform(jsonPost("/api/auth/prelogin", Map.of("email", "zk@example.com"))).andReturn());
        MasterKeys again = TestVaultClient.deriveMasterKeys(MASTER_PASSWORD, prelogin.get("kdfSalt").asText(),
                prelogin.get("kdfIterations").asInt());
        JsonNode me = read(mvc.perform(jsonPost("/api/auth/login", Map.of("email", "zk@example.com", "authHash", again.authHash())))
                .andExpect(status().isOk()).andReturn());
        MockHttpSession session = login("zk@example.com", again.authHash());
        byte[] unwrapped = TestVaultClient.unwrapVaultKey(again.wrapKey(), me.get("protectedVaultKey").asText());
        assertThat(unwrapped).isEqualTo(vaultKey);

        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("encryptedName", TestVaultClient.encryptField(unwrapped, "name", "Example Bank"));
        credential.put("encryptedUrl", TestVaultClient.encryptField(unwrapped, "url", "https://bank.example.com"));
        credential.put("encryptedUsername", TestVaultClient.encryptField(unwrapped, "username", "jordan@example.com"));
        credential.put("encryptedPassword", TestVaultClient.encryptField(unwrapped, "password", SITE_PASSWORD));
        credential.put("encryptedNotes", TestVaultClient.encryptField(unwrapped, "notes", "PIN hint: none"));
        credential.put("favorite", false);
        credential.put("passwordChanged", false);
        String id = read(mvc.perform(jsonPost("/api/credentials", credential).session(session))
                .andExpect(status().isCreated()).andReturn()).get("id").asText();

        JsonNode fetched = read(mvc.perform(get("/api/credentials/" + id).session(session)).andReturn());
        assertThat(TestVaultClient.decryptField(unwrapped, "password", fetched.get("encryptedPassword").asText()))
                .isEqualTo(SITE_PASSWORD);
        assertThat(TestVaultClient.decryptField(unwrapped, "name", fetched.get("encryptedName").asText()))
                .isEqualTo("Example Bank");

        String everything = String.join("|", jdbc.queryForList(
                "select concat_ws('|', u.email, u.auth_hash, u.kdf_salt, u.protected_vault_key, c.encrypted_name, "
                        + "c.encrypted_url, c.encrypted_username, c.encrypted_password, c.encrypted_notes) "
                        + "from users u join credentials c on c.user_id = u.id", String.class));
        assertThat(everything)
                .doesNotContain(MASTER_PASSWORD)
                .doesNotContain(SITE_PASSWORD)
                .doesNotContain("Example Bank")
                .doesNotContain("jordan@example.com")
                .doesNotContain(keys.authHash());
    }

    @Test
    void ciphertextModifiedInTheDatabaseFailsAuthentication() throws Exception {
        TestAccount account = register("tamper@example.com");
        byte[] vaultKey = TestVaultClient.random(32);
        Map<String, Object> body = credentialBody(false);
        body.put("encryptedPassword", TestVaultClient.encryptField(vaultKey, "password", SITE_PASSWORD));
        String id = createCredential(account, body);

        jdbc.update("update credentials set encrypted_password = ? where id = ?",
                TestVaultClient.tamper((String) body.get("encryptedPassword")), UUID.fromString(id));

        String stored = read(mvc.perform(get("/api/credentials/" + id).session(account.session())).andReturn())
                .get("encryptedPassword").asText();
        assertThatThrownBy(() -> TestVaultClient.decryptField(vaultKey, "password", stored))
                .isInstanceOf(AEADBadTagException.class);
    }

    @Test
    void unwrappingWithTheWrongMasterPasswordFails() {
        String salt = TestVaultClient.newSalt();
        MasterKeys right = TestVaultClient.deriveMasterKeys(MASTER_PASSWORD, salt, TestVaultClient.ITERATIONS);
        MasterKeys wrong = TestVaultClient.deriveMasterKeys(MASTER_PASSWORD + "!", salt, TestVaultClient.ITERATIONS);
        String wrapped = TestVaultClient.wrapVaultKey(right.wrapKey(), TestVaultClient.random(32));
        assertThat(wrong.authHash()).isNotEqualTo(right.authHash());
        assertThatThrownBy(() -> TestVaultClient.unwrapVaultKey(wrong.wrapKey(), wrapped))
                .isInstanceOf(AEADBadTagException.class);
        assertThat(List.of(right.authHash())).doesNotContain(java.util.Base64.getEncoder().encodeToString(right.wrapKey()));
    }
}
