package com.aegis.policy.api;

import com.aegis.auth.api.dto.LoginRequest;
import com.aegis.auth.api.dto.TokenResponse;
import com.aegis.policy.api.dto.CreatePolicyRequest;
import com.aegis.policy.domain.PolicyType;
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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PolicyControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String adminJwtToken;
    private OrgResponse testOrg;
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
                .name("Policy Org " + System.currentTimeMillis())
                .slug("policy-org-" + System.currentTimeMillis())
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

        CreateProjectRequest projectReq = CreateProjectRequest.builder()
                .name("Policy Test Project")
                .ecosystem("MAVEN")
                .build();

        MvcResult projectResult = mockMvc.perform(post("/api/v1/organizations/" + testOrg.getId() + "/projects")
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
    void createAndListPolicies_ShouldSucceed() throws Exception {
        CreatePolicyRequest request = CreatePolicyRequest.builder()
                .name("No Critical CVEs")
                .description("Block critical vulns")
                .policyType(PolicyType.NO_CRITICAL_CVE)
                .configJson("{}")
                .enabled(true)
                .build();

        mockMvc.perform(post("/api/v1/projects/" + testProject.getId() + "/policies")
                        .header("Authorization", "Bearer " + adminJwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("No Critical CVEs"))
                .andExpect(jsonPath("$.policyType").value("NO_CRITICAL_CVE"));

        mockMvc.perform(get("/api/v1/projects/" + testProject.getId() + "/policies")
                        .header("Authorization", "Bearer " + adminJwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(org.hamcrest.Matchers.greaterThanOrEqualTo(1)));
    }

    @Test
    void createOrganizationPolicy_ShouldSucceed() throws Exception {
        CreatePolicyRequest request = CreatePolicyRequest.builder()
                .name("Org CVSS Cap")
                .policyType(PolicyType.CVSS_THRESHOLD)
                .configJson("{\"maxCvss\":7.0}")
                .enabled(true)
                .build();

        mockMvc.perform(post("/api/v1/organizations/" + testOrg.getId() + "/policies")
                        .header("Authorization", "Bearer " + adminJwtToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.organizationId").value(testOrg.getId().toString()))
                .andExpect(jsonPath("$.policyType").value("CVSS_THRESHOLD"));
    }

    @Test
    void evaluatePolicies_ShouldReturnOverallPassed_WhenNoFindings() throws Exception {
        mockMvc.perform(post("/api/v1/projects/" + testProject.getId() + "/policies/evaluate")
                        .header("Authorization", "Bearer " + adminJwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.projectId").value(testProject.getId().toString()))
                .andExpect(jsonPath("$.overallPassed").value(true))
                .andExpect(jsonPath("$.evaluations").isArray())
                .andExpect(jsonPath("$.evaluations.length()").value(org.hamcrest.Matchers.greaterThanOrEqualTo(1)));
    }

    @Test
    void evaluatePolicies_ShouldReturnForbidden_WhenUserIsNotMember() throws Exception {
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

        mockMvc.perform(get("/api/v1/projects/" + testProject.getId() + "/policies/evaluate")
                        .header("Authorization", "Bearer " + devToken.getAccessToken()))
                .andExpect(status().isForbidden());
    }
}
