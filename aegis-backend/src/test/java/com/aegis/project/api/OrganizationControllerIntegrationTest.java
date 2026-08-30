package com.aegis.project.api;

import com.aegis.auth.api.dto.CreateApiKeyRequest;
import com.aegis.auth.api.dto.CreateApiKeyResponse;
import com.aegis.auth.api.dto.LoginRequest;
import com.aegis.auth.api.dto.TokenResponse;
import com.aegis.project.api.dto.AddMemberRequest;
import com.aegis.project.api.dto.CreateOrgRequest;
import com.aegis.project.api.dto.OrgResponse;
import com.aegis.project.api.dto.UpdateOrgRequest;
import com.aegis.project.domain.OrgRole;
import com.aegis.project.domain.Plan;
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
class OrganizationControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String adminJwtToken;

    @BeforeEach
    void setUp() throws Exception {
        LoginRequest loginReq = LoginRequest.builder()
                .email("admin@aegis.local")
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
        this.adminJwtToken = tokenResponse.getAccessToken();
    }

    @Test
    void createOrganization_ShouldSucceed_WithJwt() throws Exception {
        CreateOrgRequest request = CreateOrgRequest.builder()
                .name("Security Org")
                .slug("sec-org-1")
                .description("Security Operations")
                .plan(Plan.PRO)
                .build();

        mockMvc.perform(post("/api/v1/organizations")
                        .header("Authorization", "Bearer " + adminJwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.name").value("Security Org"))
                .andExpect(jsonPath("$.slug").value("sec-org-1"))
                .andExpect(jsonPath("$.plan").value("PRO"));
    }

    @Test
    void createOrganization_ShouldReturnBadRequest_WhenSlugIsDuplicate() throws Exception {
        CreateOrgRequest request1 = CreateOrgRequest.builder()
                .name("Dup Org")
                .slug("dup-slug")
                .build();

        mockMvc.perform(post("/api/v1/organizations")
                        .header("Authorization", "Bearer " + adminJwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request1)))
                .andExpect(status().isCreated());

        CreateOrgRequest request2 = CreateOrgRequest.builder()
                .name("Dup Org 2")
                .slug("dup-slug")
                .build();

        mockMvc.perform(post("/api/v1/organizations")
                        .header("Authorization", "Bearer " + adminJwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request2)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void organizationLifecycle_ShouldSucceed_WithApiKeyHeader() throws Exception {
        // Create API Key for admin user
        CreateApiKeyRequest keyReq = CreateApiKeyRequest.builder()
                .name("Org Test Key")
                .scopes("read,write")
                .build();

        MvcResult keyResult = mockMvc.perform(post("/api/v1/api-keys")
                        .header("Authorization", "Bearer " + adminJwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(keyReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse keyResp = objectMapper.readValue(
                keyResult.getResponse().getContentAsString(),
                CreateApiKeyResponse.class
        );
        String apiKey = keyResp.getRawApiKey();

        // Create Org using API Key
        CreateOrgRequest createReq = CreateOrgRequest.builder()
                .name("API Key Org")
                .slug("api-key-org")
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/v1/organizations")
                        .header("X-API-Key", apiKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        OrgResponse orgResp = objectMapper.readValue(
                createResult.getResponse().getContentAsString(),
                OrgResponse.class
        );

        // Add Member
        AddMemberRequest memberReq = AddMemberRequest.builder()
                .email("developer@aegis.local")
                .role(OrgRole.MEMBER)
                .build();

        mockMvc.perform(post("/api/v1/organizations/" + orgResp.getId() + "/members")
                        .header("X-API-Key", apiKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(memberReq)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value("developer@aegis.local"))
                .andExpect(jsonPath("$.role").value("MEMBER"));

        // Update Org
        UpdateOrgRequest updateReq = UpdateOrgRequest.builder()
                .name("API Key Org Updated")
                .build();

        mockMvc.perform(put("/api/v1/organizations/" + orgResp.getId())
                        .header("X-API-Key", apiKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(updateReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("API Key Org Updated"));
    }

    @Test
    void getOrganization_ShouldReturnForbidden_WhenUserIsNotMember() throws Exception {
        // Admin creates org
        CreateOrgRequest createReq = CreateOrgRequest.builder()
                .name("Private Admin Org")
                .slug("private-admin-org")
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/v1/organizations")
                        .header("Authorization", "Bearer " + adminJwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        OrgResponse orgResp = objectMapper.readValue(
                createResult.getResponse().getContentAsString(),
                OrgResponse.class
        );

        // Developer attempts to access org without being a member
        LoginRequest devLogin = LoginRequest.builder()
                .email("developer@aegis.local")
                .password("Aegis@123")
                .build();

        MvcResult devLoginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(devLogin)))
                .andExpect(status().isOk())
                .andReturn();

        TokenResponse devToken = objectMapper.readValue(
                devLoginResult.getResponse().getContentAsString(),
                TokenResponse.class
        );

        mockMvc.perform(get("/api/v1/organizations/" + orgResp.getId())
                        .header("Authorization", "Bearer " + devToken.getAccessToken()))
                .andExpect(status().isForbidden());
    }
}
