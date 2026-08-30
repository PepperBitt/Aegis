package com.aegis.project.api;

import com.aegis.auth.api.dto.CreateApiKeyRequest;
import com.aegis.auth.api.dto.CreateApiKeyResponse;
import com.aegis.auth.api.dto.LoginRequest;
import com.aegis.auth.api.dto.TokenResponse;
import com.aegis.project.api.dto.*;
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
class ProjectControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String adminJwtToken;
    private OrgResponse testOrg;

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

        // Create org for testing
        CreateOrgRequest orgReq = CreateOrgRequest.builder()
                .name("Project Test Org " + System.currentTimeMillis())
                .slug("prj-test-org-" + System.currentTimeMillis())
                .build();

        MvcResult orgResult = mockMvc.perform(post("/api/v1/organizations")
                        .header("Authorization", "Bearer " + adminJwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(orgReq)))
                .andExpect(status().isCreated())
                .andReturn();

        this.testOrg = objectMapper.readValue(
                orgResult.getResponse().getContentAsString(),
                OrgResponse.class
        );
    }

    @Test
    void projectLifecycle_ShouldSucceed_WithJwt() throws Exception {
        // Create project
        CreateProjectRequest createReq = CreateProjectRequest.builder()
                .name("AEGIS Backend")
                .description("Core Backend Application")
                .ecosystem("MAVEN")
                .repositoryUrl("https://github.com/aegis/backend")
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/v1/organizations/" + testOrg.getId() + "/projects")
                        .header("Authorization", "Bearer " + adminJwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.name").value("AEGIS Backend"))
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andReturn();

        ProjectResponse projectResp = objectMapper.readValue(
                createResult.getResponse().getContentAsString(),
                ProjectResponse.class
        );

        // Get project details
        mockMvc.perform(get("/api/v1/projects/" + projectResp.getId())
                        .header("Authorization", "Bearer " + adminJwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("AEGIS Backend"));

        // List projects
        mockMvc.perform(get("/api/v1/organizations/" + testOrg.getId() + "/projects")
                        .header("Authorization", "Bearer " + adminJwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$[0].id").value(projectResp.getId().toString()));

        // Update project
        UpdateProjectRequest updateReq = UpdateProjectRequest.builder()
                .name("AEGIS Backend Updated")
                .build();

        mockMvc.perform(put("/api/v1/projects/" + projectResp.getId())
                        .header("Authorization", "Bearer " + adminJwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(updateReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("AEGIS Backend Updated"));

        // Archive project
        mockMvc.perform(delete("/api/v1/projects/" + projectResp.getId())
                        .header("Authorization", "Bearer " + adminJwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ARCHIVED"));
    }

    @Test
    void projectAccess_ShouldBeForbidden_WhenUserIsNotMemberOfOrg() throws Exception {
        // Admin creates project in Admin Org
        CreateProjectRequest createReq = CreateProjectRequest.builder()
                .name("Secret Admin Project")
                .build();

        MvcResult createResult = mockMvc.perform(post("/api/v1/organizations/" + testOrg.getId() + "/projects")
                        .header("Authorization", "Bearer " + adminJwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andReturn();

        ProjectResponse projectResp = objectMapper.readValue(
                createResult.getResponse().getContentAsString(),
                ProjectResponse.class
        );

        // Login as developer (who is not a member of testOrg)
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

        // Developer attempts to access project by UUID
        mockMvc.perform(get("/api/v1/projects/" + projectResp.getId())
                        .header("Authorization", "Bearer " + devToken.getAccessToken()))
                .andExpect(status().isForbidden());
    }

    @Test
    void projectLifecycle_ShouldSucceed_WithApiKeyHeader() throws Exception {
        // Create API key
        CreateApiKeyRequest keyReq = CreateApiKeyRequest.builder()
                .name("Project Test Key")
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

        // Create project using X-API-Key header
        CreateProjectRequest createReq = CreateProjectRequest.builder()
                .name("API Key Project")
                .ecosystem("NPM")
                .build();

        mockMvc.perform(post("/api/v1/organizations/" + testOrg.getId() + "/projects")
                        .header("X-API-Key", apiKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("API Key Project"));
    }
}
