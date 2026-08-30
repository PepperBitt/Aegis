package com.aegis.report.application;

import com.aegis.auth.domain.Role;
import com.aegis.auth.domain.User;
import com.aegis.policy.api.dto.ProjectPolicyEvaluationResponse;
import com.aegis.policy.application.PolicyService;
import com.aegis.project.application.OrganizationService;
import com.aegis.project.domain.Organization;
import com.aegis.project.domain.Project;
import com.aegis.project.infrastructure.ProjectRepository;
import com.aegis.risk.api.dto.RiskResponse;
import com.aegis.risk.application.RiskService;
import com.aegis.risk.domain.RiskGrade;
import com.aegis.vulnerability.api.dto.ProjectVulnerabilityResponse;
import com.aegis.vulnerability.application.VulnerabilityService;
import com.aegis.vulnerability.domain.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ReportServiceTest {

    @Mock
    private ProjectRepository projectRepository;
    @Mock
    private OrganizationService organizationService;
    @Mock
    private RiskService riskService;
    @Mock
    private VulnerabilityService vulnerabilityService;

    @Mock
    private PolicyService policyService;

    @InjectMocks
    private ReportService reportService;

    private User user;
    private Organization org;
    private Project project;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id(UUID.randomUUID())
                .email("analyst@aegis.local")
                .role(Role.ANALYST)
                .build();
        org = Organization.builder().id(UUID.randomUUID()).name("Org").build();
        project = Project.builder()
                .id(UUID.randomUUID())
                .organization(org)
                .name("Secure App")
                .build();
    }

    @Test
    void generateSecurityPdf_ShouldReturnPdfBytes() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        doNothing().when(organizationService).verifyMembership(org.getId(), user.getId());
        when(riskService.getProjectRisk(user, project.getId())).thenReturn(RiskResponse.builder()
                .projectId(project.getId())
                .riskScore(new BigDecimal("42.50"))
                .riskGrade(RiskGrade.C)
                .criticalCount(1)
                .highCount(2)
                .mediumCount(3)
                .lowCount(4)
                .build());
        when(policyService.evaluateProjectPolicies(user, project.getId())).thenReturn(
                ProjectPolicyEvaluationResponse.builder()
                        .projectId(project.getId())
                        .overallPassed(true)
                        .evaluations(List.of())
                        .build());

        byte[] pdf = reportService.generateSecurityPdf(user, project.getId());

        assertNotNull(pdf);
        assertTrue(pdf.length > 100);
        assertEquals("%PDF", new String(pdf, 0, 4, StandardCharsets.US_ASCII));
    }

    @Test
    void generateVulnerabilityCsv_ShouldIncludeHeaderAndRows() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        doNothing().when(organizationService).verifyMembership(org.getId(), user.getId());
        when(vulnerabilityService.getProjectVulnerabilities(user, project.getId(), null)).thenReturn(List.of(
                ProjectVulnerabilityResponse.builder()
                        .cveId("CVE-2024-0001")
                        .osvId("OSV-1")
                        .title("Example Vuln")
                        .severity(Severity.HIGH)
                        .cvssScore(new BigDecimal("8.1"))
                        .componentName("libfoo")
                        .componentVersion("1.2.3")
                        .suppressed(false)
                        .build()
        ));

        byte[] csvBytes = reportService.generateVulnerabilityCsv(user, project.getId());
        String csv = new String(csvBytes, StandardCharsets.UTF_8);

        assertTrue(csv.startsWith("cveId,osvId,title,severity,cvssScore,componentName,componentVersion,suppressed"));
        assertTrue(csv.contains("CVE-2024-0001"));
        assertTrue(csv.contains("libfoo"));
        assertTrue(csv.contains("false"));
    }

    @Test
    void generateSecurityPdf_ShouldDenyWhenNotMember() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        doThrow(new AccessDeniedException("Forbidden"))
                .when(organizationService).verifyMembership(org.getId(), user.getId());

        assertThrows(AccessDeniedException.class,
                () -> reportService.generateSecurityPdf(user, project.getId()));
    }
}
