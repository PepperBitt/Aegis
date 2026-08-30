package com.aegis.sbom.api;

import com.aegis.auth.api.dto.CreateApiKeyRequest;
import com.aegis.auth.api.dto.CreateApiKeyResponse;
import com.aegis.auth.api.dto.LoginRequest;
import com.aegis.auth.api.dto.TokenResponse;
import com.aegis.project.api.dto.CreateOrgRequest;
import com.aegis.project.api.dto.CreateProjectRequest;
import com.aegis.project.api.dto.OrgResponse;
import com.aegis.project.api.dto.ProjectResponse;
import com.aegis.sbom.api.dto.SbomDocumentResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.InputStream;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SbomControllerIntegrationTest {

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

        // Create Org
        CreateOrgRequest orgReq = CreateOrgRequest.builder()
                .name("SBOM Test Org " + System.currentTimeMillis())
                .slug("sbom-test-org-" + System.currentTimeMillis())
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

        // Create Project
        CreateProjectRequest projectReq = CreateProjectRequest.builder()
                .name("SBOM Test Project")
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
    void uploadSbom_ShouldSucceed_ForCycloneDxWithJwt() throws Exception {
        byte[] fileBytes;
        try (InputStream is = getClass().getResourceAsStream("/sample-cyclonedx.json")) {
            fileBytes = is.readAllBytes();
        }

        MockMultipartFile file = new MockMultipartFile("file", "sample-cyclonedx.json", "application/json", fileBytes);

        MvcResult result = mockMvc.perform(multipart("/api/v1/projects/" + testProject.getId() + "/sboms")
                        .file(file)
                        .header("Authorization", "Bearer " + adminJwtToken))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.format").value("CYCLONEDX"))
                .andExpect(jsonPath("$.status").value("COMPLETED"))
                .andExpect(jsonPath("$.componentCount").value(2))
                .andReturn();

        SbomDocumentResponse sbomResp = objectMapper.readValue(
                result.getResponse().getContentAsString(),
                SbomDocumentResponse.class
        );

        // List SBOMs
        mockMvc.perform(get("/api/v1/projects/" + testProject.getId() + "/sboms")
                        .header("Authorization", "Bearer " + adminJwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$[0].id").value(sbomResp.getId().toString()));

        // Get Details
        mockMvc.perform(get("/api/v1/projects/" + testProject.getId() + "/sboms/" + sbomResp.getId())
                        .header("Authorization", "Bearer " + adminJwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.format").value("CYCLONEDX"));

        // Get Components
        mockMvc.perform(get("/api/v1/projects/" + testProject.getId() + "/sboms/" + sbomResp.getId() + "/components")
                        .header("Authorization", "Bearer " + adminJwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(2));

        // Get Dependencies
        mockMvc.perform(get("/api/v1/projects/" + testProject.getId() + "/sboms/" + sbomResp.getId() + "/dependencies")
                        .header("Authorization", "Bearer " + adminJwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(1));
    }

    @Test
    void uploadSbom_ShouldSucceed_ForSpdxWithApiKey() throws Exception {
        // Create API key
        CreateApiKeyRequest keyReq = CreateApiKeyRequest.builder()
                .name("Spdx Upload Key")
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

        byte[] fileBytes;
        try (InputStream is = getClass().getResourceAsStream("/sample-spdx.json")) {
            fileBytes = is.readAllBytes();
        }

        MockMultipartFile file = new MockMultipartFile("file", "sample-spdx.json", "application/json", fileBytes);

        mockMvc.perform(multipart("/api/v1/projects/" + testProject.getId() + "/sboms")
                        .file(file)
                        .header("X-API-Key", apiKey))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.format").value("SPDX"))
                .andExpect(jsonPath("$.status").value("COMPLETED"))
                .andExpect(jsonPath("$.componentCount").value(2));
    }

    @Test
    void uploadSbom_ShouldReturnForbidden_WhenUserIsNotMemberOfProjectOrg() throws Exception {
        // Developer login
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

        byte[] fileBytes = "{\"bomFormat\":\"CycloneDX\"}".getBytes();
        MockMultipartFile file = new MockMultipartFile("file", "sbom.json", "application/json", fileBytes);

        // Developer attempts to upload to admin project
        mockMvc.perform(multipart("/api/v1/projects/" + testProject.getId() + "/sboms")
                        .file(file)
                        .header("Authorization", "Bearer " + devToken.getAccessToken()))
                .andExpect(status().isForbidden());
    }
}
