package com.vault.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.vault.model.User;
import com.vault.support.IntegrationTestBase;
import com.vault.support.TestVaultClient;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MvcResult;

class AuthIntegrationTest extends IntegrationTestBase {

    @Test
    void registrationStoresOnlyAnArgon2HashAndStartsASession() throws Exception {
        String authHash = TestVaultClient.fakeAuthHash();
        MvcResult result = mvc.perform(jsonPost("/api/auth/register", registration("  Alex@Example.COM ", authHash)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value("alex@example.com"))
                .andExpect(jsonPath("$.kdfAlgorithm").value("PBKDF2-HMAC-SHA256"))
                .andExpect(jsonPath("$.kdfIterations").value(600000))
                .andExpect(jsonPath("$.protectedVaultKey").exists())
                .andExpect(jsonPath("$.authHash").doesNotExist())
                .andReturn();

        User stored = users.findByEmail("alex@example.com").orElseThrow();
        assertThat(stored.getAuthHash()).startsWith("$argon2id$").doesNotContain(authHash);

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        mvc.perform(get("/api/auth/me").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("alex@example.com"));
    }

    @Test
    void duplicateRegistrationIsRejectedRegardlessOfCase() throws Exception {
        register("sam@example.com");
        mvc.perform(jsonPost("/api/auth/register", registration("SAM@example.com", TestVaultClient.fakeAuthHash())))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").exists());
        assertThat(users.count()).isEqualTo(1);
    }

    @Test
    void registrationValidatesInput() throws Exception {
        Map<String, Object> body = registration("not-an-email", "plaintext-password");
        body.put("kdfSalt", "short");
        body.put("protectedVaultKey", "v1.not-really");
        mvc.perform(jsonPost("/api/auth/register", body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors[*].field")
                        .value(org.hamcrest.Matchers.containsInAnyOrder("authHash", "email", "kdfSalt", "protectedVaultKey")))
                .andExpect(jsonPath("$.fieldErrors[*].rejectedValue").doesNotExist());

        Map<String, Object> weakKdf = registration("weak@example.com", TestVaultClient.fakeAuthHash());
        weakKdf.put("kdfIterations", 1000);
        mvc.perform(jsonPost("/api/auth/register", weakKdf)).andExpect(status().isBadRequest());
        assertThat(users.count()).isZero();
    }

    @Test
    void malformedJsonIsRejectedWithoutLeakingDetails() throws Exception {
        mvc.perform(post("/api/auth/register").with(csrf()).contentType(MediaType.APPLICATION_JSON).content("{\"email\":"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("The request could not be read."));
    }

    @Test
    void loginSucceedsWithTheCorrectAuthHash() throws Exception {
        TestAccount account = register("lee@example.com");
        MockHttpSession session = login("LEE@example.com", account.authHash());
        mvc.perform(get("/api/auth/me").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("lee@example.com"));
    }

    @Test
    void loginFailuresAreGenericForWrongPasswordAndUnknownEmail() throws Exception {
        register("kim@example.com");
        String wrongPassword = mvc.perform(jsonPost("/api/auth/login",
                        Map.of("email", "kim@example.com", "authHash", TestVaultClient.fakeAuthHash())))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        String unknownEmail = mvc.perform(jsonPost("/api/auth/login",
                        Map.of("email", "nobody@example.com", "authHash", TestVaultClient.fakeAuthHash())))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();

        assertThat(json.readTree(wrongPassword).get("message").asText())
                .isEqualTo(json.readTree(unknownEmail).get("message").asText())
                .isEqualTo("Invalid email or master password.");
    }

    @Test
    void preloginReturnsStableDecoySaltsForUnknownEmails() throws Exception {
        TestAccount account = register("pat@example.com");
        User user = users.findByEmail(account.email()).orElseThrow();

        JsonNode known = read(mvc.perform(jsonPost("/api/auth/prelogin", Map.of("email", "pat@example.com")))
                .andExpect(status().isOk()).andReturn());
        assertThat(known.get("kdfSalt").asText()).isEqualTo(user.getKdfSalt());

        JsonNode first = read(mvc.perform(jsonPost("/api/auth/prelogin", Map.of("email", "ghost@example.com")))
                .andExpect(status().isOk()).andReturn());
        JsonNode second = read(mvc.perform(jsonPost("/api/auth/prelogin", Map.of("email", "Ghost@Example.com")))
                .andExpect(status().isOk()).andReturn());
        assertThat(first.get("kdfSalt").asText()).hasSize(24).isEqualTo(second.get("kdfSalt").asText());
        assertThat(first.get("kdfIterations").asInt()).isEqualTo(known.get("kdfIterations").asInt());
        assertThat(fieldNames(first)).isEqualTo(fieldNames(known));
    }

    private static java.util.Set<String> fieldNames(JsonNode node) {
        java.util.Set<String> names = new java.util.TreeSet<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }

    @Test
    void repeatedFailuresAreThrottled() throws Exception {
        TestAccount account = register("max@example.com");
        Map<String, String> wrong = Map.of("email", account.email(), "authHash", TestVaultClient.fakeAuthHash());
        for (int i = 0; i < 5; i++) {
            mvc.perform(jsonPost("/api/auth/login", wrong)).andExpect(status().isUnauthorized());
        }
        mvc.perform(jsonPost("/api/auth/login", Map.of("email", account.email(), "authHash", account.authHash())))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void protectedEndpointsRequireAuthentication() throws Exception {
        for (String path : new String[] {"/api/credentials", "/api/auth/me", "/api/security/overview", "/api/auth/session"}) {
            mvc.perform(get(path))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.message").exists());
        }
        mvc.perform(jsonPost("/api/credentials", credentialBody(false))).andExpect(status().isUnauthorized());
    }

    @Test
    void stateChangingRequestsRequireACsrfToken() throws Exception {
        TestAccount account = register("csrf@example.com");
        mvc.perform(post("/api/credentials").session(account.session())
                        .contentType(MediaType.APPLICATION_JSON).content(toJson(credentialBody(false))))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(toJson(Map.of("email", account.email(), "authHash", account.authHash()))))
                .andExpect(status().isForbidden());
    }

    @Test
    void logoutInvalidatesTheSession() throws Exception {
        TestAccount account = register("out@example.com");
        mvc.perform(post("/api/auth/logout").with(csrf()).session(account.session()))
                .andExpect(status().isNoContent());
        mvc.perform(get("/api/auth/me").session(account.session())).andExpect(status().isUnauthorized());
    }

    @Test
    void changingTheMasterPasswordRotatesCredentialsAndExpiresOtherSessions() throws Exception {
        TestAccount account = register("rotate@example.com");
        MockHttpSession otherDevice = login(account.email(), account.authHash());
        String newAuthHash = TestVaultClient.fakeAuthHash();
        String newSalt = TestVaultClient.newSalt();

        mvc.perform(jsonPost("/api/auth/change-password", Map.of(
                        "currentAuthHash", TestVaultClient.fakeAuthHash(),
                        "newAuthHash", newAuthHash,
                        "newKdfSalt", newSalt,
                        "newKdfIterations", 600000,
                        "newProtectedVaultKey", TestVaultClient.fakeProtectedVaultKey())).session(account.session()))
                .andExpect(status().isBadRequest());

        mvc.perform(jsonPost("/api/auth/change-password", Map.of(
                        "currentAuthHash", account.authHash(),
                        "newAuthHash", newAuthHash,
                        "newKdfSalt", newSalt,
                        "newKdfIterations", 600000,
                        "newProtectedVaultKey", TestVaultClient.fakeProtectedVaultKey())).session(account.session()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.kdfSalt").value(newSalt));

        mvc.perform(get("/api/auth/me").session(account.session())).andExpect(status().isOk());
        mvc.perform(get("/api/auth/me").session(otherDevice)).andExpect(status().isUnauthorized());
        mvc.perform(jsonPost("/api/auth/login", Map.of("email", account.email(), "authHash", account.authHash())))
                .andExpect(status().isUnauthorized());
        login(account.email(), newAuthHash);
    }

    @Test
    void sessionInfoReportsActiveSessions() throws Exception {
        TestAccount account = register("sessions@example.com");
        login(account.email(), account.authHash());
        mvc.perform(get("/api/auth/session").session(account.session()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeSessions").value(2))
                .andExpect(jsonPath("$.maxInactiveSeconds").isNumber());
        mvc.perform(post("/api/auth/sessions/revoke-others").with(csrf()).session(account.session()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revoked").value(1));
    }

    @Test
    void securityHeadersAreApplied() throws Exception {
        mvc.perform(get("/index.html"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", org.hamcrest.Matchers.containsString("script-src 'self'")))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"));
    }
}
