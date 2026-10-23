package com.vault.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.vault.support.IntegrationTestBase;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Exercises the double-submit cookie flow used by api.js without spring-security-test's csrf()
 * helper, which replaces the token repository. A fresh context keeps the real repository in place.
 */
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
class CsrfFlowTest extends IntegrationTestBase {

    @Test
    void browserStyleCookieAndHeaderAreAccepted() throws Exception {
        MvcResult tokenResult = mvc.perform(get("/api/auth/csrf"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.headerName").value("X-XSRF-TOKEN"))
                .andExpect(cookie().exists("XSRF-TOKEN"))
                .andExpect(cookie().httpOnly("XSRF-TOKEN", false))
                .andReturn();
        Cookie cookie = tokenResult.getResponse().getCookie("XSRF-TOKEN");
        assertThat(cookie.getValue()).isEqualTo(read(tokenResult).get("token").asText());
        assertThat(cookie.getAttribute("SameSite")).isEqualTo("Strict");

        mvc.perform(post("/api/auth/prelogin").cookie(cookie).header("X-XSRF-TOKEN", cookie.getValue())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"email\":\"a@example.com\"}"))
                .andExpect(status().isOk());

        mvc.perform(post("/api/auth/prelogin").cookie(cookie).header("X-XSRF-TOKEN", "forged-token")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"email\":\"a@example.com\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("security token")));

        mvc.perform(post("/api/auth/prelogin").cookie(cookie)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"email\":\"a@example.com\"}"))
                .andExpect(status().isForbidden());
    }
}
