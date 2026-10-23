package com.vault.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.vault.model.Credential;
import com.vault.support.IntegrationTestBase;
import com.vault.support.TestVaultClient;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;

class CredentialIntegrationTest extends IntegrationTestBase {

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void createStoresCiphertextExactlyAsSent() throws Exception {
        TestAccount account = register("owner@example.com");
        Map<String, Object> body = credentialBody(true);

        String id = mvc.perform(jsonPost("/api/credentials", body).session(account.session()))
                .andExpect(status().isCreated())
                .andExpect(header().string("Location", org.hamcrest.Matchers.startsWith("/api/credentials/")))
                .andExpect(jsonPath("$.encryptedPassword").value(body.get("encryptedPassword")))
                .andExpect(jsonPath("$.favorite").value(true))
                .andExpect(jsonPath("$.encryptedNotes").doesNotExist())
                .andReturn().getResponse().getHeader("Location").replace("/api/credentials/", "");

        Credential stored = credentials.findById(UUID.fromString(id)).orElseThrow();
        assertThat(stored.getEncryptedPassword()).isEqualTo(body.get("encryptedPassword"));
        assertThat(stored.getOwner().getId().toString()).isEqualTo(account.userId());
    }

    @Test
    void listAndGetReturnOnlyTheOwnersCredentials() throws Exception {
        TestAccount alice = register("alice@example.com");
        TestAccount bob = register("bob@example.com");
        String aliceId = createCredential(alice, credentialBody(false));
        createCredential(alice, credentialBody(false));
        String bobId = createCredential(bob, credentialBody(false));

        mvc.perform(get("/api/credentials").session(alice.session()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[*].id").value(org.hamcrest.Matchers.not(org.hamcrest.Matchers.hasItem(bobId))));
        mvc.perform(get("/api/credentials/" + aliceId).session(alice.session()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(aliceId));
    }

    @Test
    void usersCannotReadModifyOrDeleteAnotherUsersCredential() throws Exception {
        TestAccount alice = register("alice@example.com");
        TestAccount mallory = register("mallory@example.com");
        Map<String, Object> original = credentialBody(false);
        String aliceId = createCredential(alice, original);

        mvc.perform(get("/api/credentials/" + aliceId).session(mallory.session()))
                .andExpect(status().isNotFound());
        mvc.perform(put("/api/credentials/" + aliceId).with(csrf()).session(mallory.session())
                        .contentType(MediaType.APPLICATION_JSON).content(toJson(credentialBody(true))))
                .andExpect(status().isNotFound());
        mvc.perform(patch("/api/credentials/" + aliceId + "/favorite").with(csrf()).session(mallory.session())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"favorite\":true}"))
                .andExpect(status().isNotFound());
        mvc.perform(delete("/api/credentials/" + aliceId).with(csrf()).session(mallory.session()))
                .andExpect(status().isNotFound());
        mvc.perform(get("/api/credentials").session(mallory.session()))
                .andExpect(jsonPath("$.length()").value(0));

        Credential untouched = credentials.findById(UUID.fromString(aliceId)).orElseThrow();
        assertThat(untouched.getEncryptedPassword()).isEqualTo(original.get("encryptedPassword"));
        assertThat(untouched.isFavorite()).isFalse();
    }

    @Test
    void updateReplacesFieldsAndTracksPasswordChanges() throws Exception {
        TestAccount account = register("editor@example.com");
        String id = createCredential(account, credentialBody(false));
        UUID uuid = UUID.fromString(id);
        Instant past = Instant.now().minus(400, ChronoUnit.DAYS);
        jdbc.update("update credentials set password_updated_at = ? where id = ?", Timestamp.from(past), uuid);

        Map<String, Object> metadataOnly = credentialBody(true);
        metadataOnly.put("passwordChanged", false);
        mvc.perform(put("/api/credentials/" + id).with(csrf()).session(account.session())
                        .contentType(MediaType.APPLICATION_JSON).content(toJson(metadataOnly)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.favorite").value(true));
        assertThat(credentials.findById(uuid).orElseThrow().getPasswordUpdatedAt())
                .isCloseTo(past, org.assertj.core.api.Assertions.within(1, ChronoUnit.SECONDS));

        Map<String, Object> withPassword = credentialBody(true);
        withPassword.put("passwordChanged", true);
        withPassword.put("encryptedNotes", TestVaultClient.fakeCiphertext());
        mvc.perform(put("/api/credentials/" + id).with(csrf()).session(account.session())
                        .contentType(MediaType.APPLICATION_JSON).content(toJson(withPassword)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.encryptedPassword").value(withPassword.get("encryptedPassword")))
                .andExpect(jsonPath("$.encryptedNotes").value(withPassword.get("encryptedNotes")));
        assertThat(credentials.findById(uuid).orElseThrow().getPasswordUpdatedAt())
                .isAfter(Instant.now().minus(1, ChronoUnit.MINUTES));
    }

    @Test
    void favoriteCanBeToggled() throws Exception {
        TestAccount account = register("fav@example.com");
        String id = createCredential(account, credentialBody(false));
        mvc.perform(patch("/api/credentials/" + id + "/favorite").with(csrf()).session(account.session())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"favorite\":true}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.favorite").value(true));
        assertThat(credentials.findById(UUID.fromString(id)).orElseThrow().isFavorite()).isTrue();
        mvc.perform(patch("/api/credentials/" + id + "/favorite").with(csrf()).session(account.session())
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void deleteRemovesTheCredential() throws Exception {
        TestAccount account = register("cleaner@example.com");
        String id = createCredential(account, credentialBody(false));
        mvc.perform(delete("/api/credentials/" + id).with(csrf()).session(account.session()))
                .andExpect(status().isNoContent());
        mvc.perform(get("/api/credentials/" + id).session(account.session()))
                .andExpect(status().isNotFound());
        assertThat(credentials.count()).isZero();
    }

    @Test
    void plaintextAndMalformedValuesAreRejected() throws Exception {
        TestAccount account = register("strict@example.com");
        Map<String, Object> plaintext = credentialBody(false);
        plaintext.put("encryptedPassword", "hunter2");
        plaintext.put("encryptedName", "v1.AAAAAAAAAAAAAAAA.");
        mvc.perform(jsonPost("/api/credentials", plaintext).session(account.session()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors[*].field")
                        .value(org.hamcrest.Matchers.containsInAnyOrder("encryptedName", "encryptedPassword")));

        Map<String, Object> missing = credentialBody(false);
        missing.remove("encryptedPassword");
        mvc.perform(jsonPost("/api/credentials", missing).session(account.session()))
                .andExpect(status().isBadRequest());

        Map<String, Object> oversized = credentialBody(false);
        oversized.put("encryptedNotes", TestVaultClient.encrypt(TestVaultClient.random(32), new byte[20_000], "notes"));
        mvc.perform(jsonPost("/api/credentials", oversized).session(account.session()))
                .andExpect(status().isBadRequest());

        mvc.perform(get("/api/credentials/not-a-uuid").session(account.session()))
                .andExpect(status().isBadRequest());
        assertThat(credentials.count()).isZero();
    }

    @Test
    void securityOverviewCountsOnlyTheOwnersData() throws Exception {
        TestAccount account = register("overview@example.com");
        TestAccount other = register("other@example.com");
        createCredential(account, credentialBody(true));
        String old = createCredential(account, credentialBody(false));
        createCredential(other, credentialBody(true));
        jdbc.update("update credentials set password_updated_at = ? where id = ?",
                Timestamp.from(Instant.now().minus(365, ChronoUnit.DAYS)), UUID.fromString(old));

        mvc.perform(get("/api/security/overview").session(account.session()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalCredentials").value(2))
                .andExpect(jsonPath("$.favoriteCredentials").value(1))
                .andExpect(jsonPath("$.stalePasswords").value(1))
                .andExpect(jsonPath("$.staleAfterDays").value(180))
                .andExpect(jsonPath("$.breachMonitoringAvailable").value(false));
    }
}
