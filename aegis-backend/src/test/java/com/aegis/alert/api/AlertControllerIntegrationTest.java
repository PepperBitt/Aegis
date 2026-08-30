package com.aegis.alert.api;

import com.aegis.alert.application.AlertService;
import com.aegis.alert.domain.AlertSeverity;
import com.aegis.alert.domain.AlertType;
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

import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AlertControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AlertService alertService;

    private String adminJwtToken;
    private ProjectResponse testProject;
    private UUID alertId;

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
                .name("Alert Org " + System.currentTimeMillis())
                .slug("alert-org-" + System.currentTimeMillis())
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
                .name("Alert Test Project")
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

        this.alertId = alertService.createAlert(
                testProject.getId(),
                AlertType.GATE_FAILURE,
                AlertSeverity.HIGH,
                "Gate failed",
                "Test gate failure alert",
                "{}"
        ).getId();
    }

    @Test
    void listAndAcknowledgeAlerts_ShouldSucceed() throws Exception {
        mockMvc.perform(get("/api/v1/projects/" + testProject.getId() + "/alerts")
                        .header("Authorization", "Bearer " + adminJwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(org.hamcrest.Matchers.greaterThanOrEqualTo(1)));

        mockMvc.perform(get("/api/v1/projects/" + testProject.getId() + "/alerts/unread")
                        .header("Authorization", "Bearer " + adminJwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(org.hamcrest.Matchers.greaterThanOrEqualTo(1)));

        mockMvc.perform(post("/api/v1/projects/" + testProject.getId() + "/alerts/" + alertId + "/acknowledge")
                        .header("Authorization", "Bearer " + adminJwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(alertId.toString()))
                .andExpect(jsonPath("$.acknowledged").value(true));

        mockMvc.perform(get("/api/v1/projects/" + testProject.getId() + "/alerts/unread")
                        .header("Authorization", "Bearer " + adminJwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    void listAlerts_ShouldReturnForbidden_WhenUserIsNotMember() throws Exception {
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

        mockMvc.perform(get("/api/v1/projects/" + testProject.getId() + "/alerts")
                        .header("Authorization", "Bearer " + devToken.getAccessToken()))
                .andExpect(status().isForbidden());
    }
}
