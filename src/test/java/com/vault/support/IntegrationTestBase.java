package com.vault.support;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vault.repository.CredentialRepository;
import com.vault.repository.UserRepository;
import com.vault.security.LoginAttemptService;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public abstract class IntegrationTestBase {

    @Autowired
    protected MockMvc mvc;

    @Autowired
    protected ObjectMapper json;

    @Autowired
    protected UserRepository users;

    @Autowired
    protected CredentialRepository credentials;

    @Autowired
    protected LoginAttemptService loginAttempts;

    public record TestAccount(String email, String authHash, MockHttpSession session, String userId) {
    }

    @BeforeEach
    void cleanDatabase() {
        credentials.deleteAll();
        users.deleteAll();
        loginAttempts.reset();
    }

    protected String toJson(Object value) throws Exception {
        return json.writeValueAsString(value);
    }

    protected JsonNode read(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString());
    }

    protected MockHttpServletRequestBuilder jsonPost(String path, Object body) throws Exception {
        return post(path).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(toJson(body));
    }

    protected Map<String, Object> registration(String email, String authHash) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("email", email);
        body.put("authHash", authHash);
        body.put("kdfSalt", TestVaultClient.newSalt());
        body.put("kdfIterations", TestVaultClient.ITERATIONS);
        body.put("protectedVaultKey", TestVaultClient.fakeProtectedVaultKey());
        return body;
    }

    protected TestAccount register(String email) throws Exception {
        String authHash = TestVaultClient.fakeAuthHash();
        MvcResult result = mvc.perform(jsonPost("/api/auth/register", registration(email, authHash)))
                .andExpect(status().isCreated())
                .andReturn();
        return new TestAccount(email, authHash, (MockHttpSession) result.getRequest().getSession(false),
                read(result).get("id").asText());
    }

    protected MockHttpSession login(String email, String authHash) throws Exception {
        MvcResult result = mvc.perform(jsonPost("/api/auth/login", Map.of("email", email, "authHash", authHash)))
                .andExpect(status().isOk())
                .andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }

    protected Map<String, Object> credentialBody(boolean favorite) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("encryptedName", TestVaultClient.fakeCiphertext());
        body.put("encryptedUrl", TestVaultClient.fakeCiphertext());
        body.put("encryptedUsername", TestVaultClient.fakeCiphertext());
        body.put("encryptedPassword", TestVaultClient.fakeCiphertext());
        body.put("encryptedNotes", null);
        body.put("favorite", favorite);
        body.put("passwordChanged", false);
        return body;
    }

    protected String createCredential(TestAccount account, Map<String, Object> body) throws Exception {
        MvcResult result = mvc.perform(jsonPost("/api/credentials", body).session(account.session()))
                .andExpect(status().isCreated())
                .andReturn();
        return read(result).get("id").asText();
    }
}
