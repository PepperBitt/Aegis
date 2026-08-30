package com.aegis.auth.api;

import com.aegis.auth.api.dto.CreateApiKeyRequest;
import com.aegis.auth.api.dto.CreateApiKeyResponse;
import com.aegis.auth.api.dto.LoginRequest;
import com.aegis.auth.api.dto.TokenResponse;
import com.aegis.gate.api.dto.GateCheckRequest;
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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class ApiKeyScopeIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String jwtToken;
    private ProjectResponse project;

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

        jwtToken = objectMapper.readValue(loginResult.getResponse().getContentAsString(), TokenResponse.class)
                .getAccessToken();

        CreateOrgRequest orgReq = CreateOrgRequest.builder()
                .name("Scope Org " + System.currentTimeMillis())
                .slug("scope-org-" + System.currentTimeMillis())
                .build();

        OrgResponse org = objectMapper.readValue(
                mockMvc.perform(post("/api/v1/organizations")
                                .header("Authorization", "Bearer " + jwtToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(orgReq)))
                        .andExpect(status().isCreated())
                        .andReturn().getResponse().getContentAsString(),
                OrgResponse.class);

        project = objectMapper.readValue(
                mockMvc.perform(post("/api/v1/organizations/" + org.getId() + "/projects")
                                .header("Authorization", "Bearer " + jwtToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(
                                        CreateProjectRequest.builder().name("Scope Project").ecosystem("MAVEN").build())))
                        .andExpect(status().isCreated())
                        .andReturn().getResponse().getContentAsString(),
                ProjectResponse.class);
    }

    @Test
    void readScope_ShouldAllowGet_AndRejectWrite() throws Exception {
        String rawKey = createKey("read-only", "read");

        mockMvc.perform(get("/api/v1/projects/" + project.getId() + "/risk")
                        .header("X-API-Key", rawKey))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/v1/projects/" + project.getId() + "/risk/recalculate")
                        .header("X-API-Key", rawKey))
                .andExpect(status().isForbidden());
    }

    @Test
    void readScope_ShouldRejectGateCheck() throws Exception {
        String rawKey = createKey("read-gate", "read");

        GateCheckRequest gateReq = GateCheckRequest.builder()
                .projectId(project.getId())
                .build();

        mockMvc.perform(post("/api/v1/gates/check")
                        .header("X-API-Key", rawKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(gateReq)))
                .andExpect(status().isForbidden());
    }

    @Test
    void gateScope_ShouldAllowGateCheck() throws Exception {
        String rawKey = createKey("gate-key", "gate");

        GateCheckRequest gateReq = GateCheckRequest.builder()
                .projectId(project.getId())
                .build();

        mockMvc.perform(post("/api/v1/gates/check")
                        .header("X-API-Key", rawKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(gateReq)))
                .andExpect(status().isOk());
    }

    @Test
    void jwtAccess_ShouldRemainUnaffectedByScopeRules() throws Exception {
        mockMvc.perform(post("/api/v1/projects/" + project.getId() + "/risk/recalculate")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk());
    }

    private String createKey(String name, String scopes) throws Exception {
        CreateApiKeyRequest keyReq = CreateApiKeyRequest.builder()
                .name(name)
                .scopes(scopes)
                .build();

        MvcResult keyResult = mockMvc.perform(post("/api/v1/api-keys")
                        .header("Authorization", "Bearer " + jwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(keyReq)))
                .andExpect(status().isCreated())
                .andReturn();

        return objectMapper.readValue(keyResult.getResponse().getContentAsString(), CreateApiKeyResponse.class)
                .getRawApiKey();
    }
}
