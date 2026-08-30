package com.aegis.risk.api;

import com.aegis.auth.api.dto.CreateApiKeyRequest;
import com.aegis.auth.api.dto.CreateApiKeyResponse;
import com.aegis.auth.api.dto.LoginRequest;
import com.aegis.auth.api.dto.TokenResponse;
import com.aegis.project.api.dto.CreateOrgRequest;
import com.aegis.project.api.dto.CreateProjectRequest;
import com.aegis.project.api.dto.OrgResponse;
import com.aegis.project.api.dto.ProjectResponse;
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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RiskControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String adminJwtToken;
    private ProjectResponse testProject;

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

        CreateOrgRequest orgReq = CreateOrgRequest.builder()
                .name("Risk Org " + System.currentTimeMillis())
                .slug("risk-org-" + System.currentTimeMillis())
                .build();

        MvcResult orgResult = mockMvc.perform(post("/api/v1/organizations")
                        .header("Authorization", "Bearer " + adminJwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(orgReq)))
                .andExpect(status().isCreated())
                .andReturn();

        OrgResponse orgResp = objectMapper.readValue(
                orgResult.getResponse().getContentAsString(),
                OrgResponse.class
        );

        CreateProjectRequest projectReq = CreateProjectRequest.builder()
                .name("Risk Test Project")
                .ecosystem("MAVEN")
                .build();

        MvcResult projectResult = mockMvc.perform(post("/api/v1/organizations/" + orgResp.getId() + "/projects")
                        .header("Authorization", "Bearer " + adminJwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(projectReq)))
                .andExpect(status().isCreated())
                .andReturn();

        this.testProject = objectMapper.readValue(
                projectResult.getResponse().getContentAsString(),
                ProjectResponse.class
        );
    }

    @Test
    void getProjectRisk_ShouldReturn200_WhenAuthenticatedAndMember() throws Exception {
        mockMvc.perform(get("/api/v1/projects/" + testProject.getId() + "/risk")
                        .header("Authorization", "Bearer " + adminJwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.projectId").value(testProject.getId().toString()))
                .andExpect(jsonPath("$.riskGrade").exists());
    }

    @Test
    void getProjectRisk_ShouldSucceed_WithApiKeyHeader() throws Exception {
        CreateApiKeyRequest keyReq = CreateApiKeyRequest.builder()
                .name("Risk API Key")
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

        mockMvc.perform(get("/api/v1/projects/" + testProject.getId() + "/risk")
                        .header("X-API-Key", keyResp.getRawApiKey()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.projectId").value(testProject.getId().toString()));
    }

    @Test
    void recalculateProjectRisk_ShouldReturn200_AndCreateHistorySnapshot() throws Exception {
        mockMvc.perform(post("/api/v1/projects/" + testProject.getId() + "/risk/recalculate")
                        .header("Authorization", "Bearer " + adminJwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.projectId").value(testProject.getId().toString()));

        mockMvc.perform(get("/api/v1/projects/" + testProject.getId() + "/risk/history")
                        .header("Authorization", "Bearer " + adminJwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(org.hamcrest.Matchers.greaterThanOrEqualTo(1)));
    }

    @Test
    void getProjectRisk_ShouldReturnForbidden_WhenUserIsNotMember() throws Exception {
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

        mockMvc.perform(get("/api/v1/projects/" + testProject.getId() + "/risk")
                        .header("Authorization", "Bearer " + devToken.getAccessToken()))
                .andExpect(status().isForbidden());
    }
}
