package com.aegis.auth.api;

import com.aegis.auth.api.dto.CreateApiKeyRequest;
import com.aegis.auth.api.dto.CreateApiKeyResponse;
import com.aegis.auth.api.dto.LoginRequest;
import com.aegis.auth.api.dto.TokenResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(SecurityRoleIntegrationTest.TestRbacController.class)
class SecurityRoleIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void adminUser_ShouldAccessAdminEndpoint_WithJwt() throws Exception {
        String token = loginAndGetToken("admin@aegis.local", "Aegis@123");

        mockMvc.perform(get("/api/v1/test-rbac/admin")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("ADMIN_ACCESS"));
    }

    @Test
    void developerUser_ShouldBeForbiddenFromAdminEndpoint_WithJwt() throws Exception {
        String token = loginAndGetToken("developer@aegis.local", "Aegis@123");

        mockMvc.perform(get("/api/v1/test-rbac/admin")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    void analystUser_ShouldAccessAnalystEndpoint_WithJwt() throws Exception {
        String token = loginAndGetToken("analyst@aegis.local", "Aegis@123");

        mockMvc.perform(get("/api/v1/test-rbac/analyst")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("ANALYST_ACCESS"));
    }

    @Test
    void auditorUser_ShouldAccessAuditorEndpoint_WithJwt() throws Exception {
        String token = loginAndGetToken("auditor@aegis.local", "Aegis@123");

        mockMvc.perform(get("/api/v1/test-rbac/auditor")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("AUDITOR_ACCESS"));
    }

    @Test
    void apiKeyUser_ShouldInheritOwningUserAuthorities() throws Exception {
        // Admin creates API key
        String adminJwt = loginAndGetToken("admin@aegis.local", "Aegis@123");
        CreateApiKeyRequest adminKeyReq = CreateApiKeyRequest.builder()
                .name("Admin Key")
                .scopes("read,write")
                .build();

        MvcResult adminKeyResult = mockMvc.perform(post("/api/v1/api-keys")
                        .header("Authorization", "Bearer " + adminJwt)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(adminKeyReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse adminKeyResp = objectMapper.readValue(
                adminKeyResult.getResponse().getContentAsString(),
                CreateApiKeyResponse.class
        );

        // Developer creates API key
        String devJwt = loginAndGetToken("developer@aegis.local", "Aegis@123");
        CreateApiKeyRequest devKeyReq = CreateApiKeyRequest.builder()
                .name("Dev Key")
                .scopes("read")
                .build();

        MvcResult devKeyResult = mockMvc.perform(post("/api/v1/api-keys")
                        .header("Authorization", "Bearer " + devJwt)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(devKeyReq)))
                .andExpect(status().isCreated())
                .andReturn();

        CreateApiKeyResponse devKeyResp = objectMapper.readValue(
                devKeyResult.getResponse().getContentAsString(),
                CreateApiKeyResponse.class
        );

        // Admin API key can access admin endpoint
        mockMvc.perform(get("/api/v1/test-rbac/admin")
                        .header("X-API-Key", adminKeyResp.getRawApiKey()))
                .andExpect(status().isOk())
                .andExpect(content().string("ADMIN_ACCESS"));

        // Developer API key is forbidden from admin endpoint
        mockMvc.perform(get("/api/v1/test-rbac/admin")
                        .header("X-API-Key", devKeyResp.getRawApiKey()))
                .andExpect(status().isForbidden());
    }

    private String loginAndGetToken(String email, String password) throws Exception {
        LoginRequest loginReq = LoginRequest.builder()
                .email(email)
                .password(password)
                .build();

        MvcResult result = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isOk())
                .andReturn();

        TokenResponse tokenResponse = objectMapper.readValue(
                result.getResponse().getContentAsString(),
                TokenResponse.class
        );
        return tokenResponse.getAccessToken();
    }

    @RestController
    @RequestMapping("/api/v1/test-rbac")
    static class TestRbacController {

        @GetMapping("/admin")
        @PreAuthorize("hasRole('ADMIN')")
        public String adminEndpoint() {
            return "ADMIN_ACCESS";
        }

        @GetMapping("/analyst")
        @PreAuthorize("hasRole('ANALYST')")
        public String analystEndpoint() {
            return "ANALYST_ACCESS";
        }

        @GetMapping("/auditor")
        @PreAuthorize("hasRole('AUDITOR')")
        public String auditorEndpoint() {
            return "AUDITOR_ACCESS";
        }
    }
}
