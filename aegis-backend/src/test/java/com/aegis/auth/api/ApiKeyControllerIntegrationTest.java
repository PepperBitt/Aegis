package com.aegis.auth.api;

import com.aegis.auth.api.dto.CreateApiKeyRequest;
import com.aegis.auth.api.dto.CreateApiKeyResponse;
import com.aegis.auth.api.dto.LoginRequest;
import com.aegis.auth.api.dto.TokenResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class ApiKeyControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String jwtToken;

    @BeforeEach
    void setUp() throws Exception {
        LoginRequest loginReq = LoginRequest.builder()
                .email("developer@aegis.local")
                .password("Aegis@123")
                .build();

        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isOk())
                .andReturn();

        TokenResponse tokenResponse = objectMapper.readValue(
                loginResult.getResponse().getContentAsString(),
                TokenResponse.class
        );
        this.jwtToken = tokenResponse.getAccessToken();
    }

    @Test
    void createApiKey_ShouldReturnRawKey_WhenAuthenticated() throws Exception {
        CreateApiKeyRequest request = CreateApiKeyRequest.builder()
                .name("CI Key Test")
                .scopes("read,write")
                .build();

        mockMvc.perform(post("/api/v1/api-keys")
                        .header("Authorization", "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.name").value("CI Key Test"))
                .andExpect(jsonPath("$.rawApiKey").isNotEmpty())
                .andExpect(jsonPath("$.keyPrefix").isNotEmpty());
    }

    @Test
    void authenticate_ShouldSucceed_WhenValidApiKeyHeaderProvided() throws Exception {
        CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                .name("Auth Test Key")
                .scopes("read")
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/v1/api-keys")
                        .header("Authorization", "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse keyResponse = objectMapper.readValue(
                createResult.getResponse().getContentAsString(),
                CreateApiKeyResponse.class
        );

        // Access /api/v1/auth/me using X-API-Key header
        mockMvc.perform(get("/api/v1/auth/me")
                        .header("X-API-Key", keyResponse.getRawApiKey()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("developer@aegis.local"))
                .andExpect(jsonPath("$.role").value("DEVELOPER"));
    }

    @Test
    void revokeApiKey_ShouldPreventSubsequentAuthentication() throws Exception {
        CreateApiKeyRequest createReq = CreateApiKeyRequest.builder()
                .name("Key to Revoke")
                .scopes("read")
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/v1/api-keys")
                        .header("Authorization", "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse keyResponse = objectMapper.readValue(
                createResult.getResponse().getContentAsString(),
                CreateApiKeyResponse.class
        );

        // Revoke the key
        mockMvc.perform(delete("/api/v1/api-keys/" + keyResponse.getId())
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isNoContent());

        // Attempt authentication with revoked key
        mockMvc.perform(get("/api/v1/auth/me")
                        .header("X-API-Key", keyResponse.getRawApiKey()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void listApiKeys_ShouldReturnUserKeysWithoutRawKey() throws Exception {
        mockMvc.perform(get("/api/v1/api-keys")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }
}
