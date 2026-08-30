package com.aegis.policy.application;

import com.aegis.auth.domain.Role;
import com.aegis.auth.domain.User;
import com.aegis.policy.api.dto.CreatePolicyRequest;
import com.aegis.policy.api.dto.PolicyResponse;
import com.aegis.policy.api.dto.ProjectPolicyEvaluationResponse;
import com.aegis.policy.api.dto.UpdatePolicyRequest;
import com.aegis.policy.domain.PolicyType;
import com.aegis.policy.domain.SecurityPolicy;
import com.aegis.policy.infrastructure.repository.PolicyEvaluationResultRepository;
import com.aegis.policy.infrastructure.repository.SecurityPolicyRepository;
import com.aegis.project.application.OrganizationService;
import com.aegis.project.domain.Organization;
import com.aegis.project.domain.Project;
import com.aegis.project.infrastructure.OrganizationRepository;
import com.aegis.project.infrastructure.ProjectRepository;
import com.aegis.sbom.domain.SbomComponent;
import com.aegis.sbom.infrastructure.SbomComponentRepository;
import com.aegis.vulnerability.domain.ComponentVulnerability;
import com.aegis.vulnerability.domain.Severity;
import com.aegis.vulnerability.domain.Vulnerability;
import com.aegis.vulnerability.infrastructure.repository.ComponentVulnerabilityRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import java.math.BigDecimal;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PolicyServiceTest {

    @Mock
    private SecurityPolicyRepository securityPolicyRepository;

    @Mock
    private PolicyEvaluationResultRepository evaluationResultRepository;

    @Mock
    private ComponentVulnerabilityRepository componentVulnerabilityRepository;

    @Mock
    private SbomComponentRepository sbomComponentRepository;

    @Mock
    private ProjectRepository projectRepository;

    @Mock
    private OrganizationRepository organizationRepository;

    @Mock
    private OrganizationService organizationService;

    @Spy
    private ObjectMapper objectMapper = new ObjectMapper();

    @InjectMocks
    private PolicyService policyService;

    private User user;
    private Organization org;
    private Project project;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id(UUID.randomUUID())
                .email("admin@aegis.local")
                .role(Role.ADMIN)
                .build();

        org = Organization.builder()
                .id(UUID.randomUUID())
                .name("Policy Org")
                .build();

        project = Project.builder()
                .id(UUID.randomUUID())
                .organization(org)
                .name("Policy Project")
                .build();
    }

    @Test
    void createProjectPolicy_ShouldPersistAndReturnResponse() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        doNothing().when(organizationService).verifyMembership(org.getId(), user.getId());
        when(securityPolicyRepository.save(any())).thenAnswer(inv -> {
            SecurityPolicy p = inv.getArgument(0);
            p.setId(UUID.randomUUID());
            return p;
        });

        CreatePolicyRequest request = CreatePolicyRequest.builder()
                .name("No Critical")
                .policyType(PolicyType.NO_CRITICAL_CVE)
                .configJson("{}")
                .enabled(true)
                .build();

        PolicyResponse response = policyService.createProjectPolicy(user, project.getId(), request);

        assertNotNull(response.getId());
        assertEquals("No Critical", response.getName());
        assertEquals(PolicyType.NO_CRITICAL_CVE, response.getPolicyType());
        assertEquals(project.getId(), response.getProjectId());
    }

    @Test
    void evaluateProjectPolicies_ShouldPass_WhenNoFindings() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        when(securityPolicyRepository.findEnabledForProject(project.getId(), org.getId()))
                .thenReturn(Collections.emptyList());
        when(securityPolicyRepository.saveAll(anyList())).thenAnswer(inv -> {
            List<SecurityPolicy> policies = inv.getArgument(0);
            policies.forEach(p -> p.setId(UUID.randomUUID()));
            return policies;
        });
        when(componentVulnerabilityRepository.findByProjectId(project.getId())).thenReturn(Collections.emptyList());
        when(sbomComponentRepository.findByProjectId(project.getId())).thenReturn(Collections.emptyList());
        when(evaluationResultRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        ProjectPolicyEvaluationResponse response = policyService.evaluateProjectPolicies(project.getId());

        assertTrue(response.isOverallPassed());
        assertEquals(3, response.getEvaluations().size());
        verify(evaluationResultRepository, times(3)).save(any());
    }

    @Test
    void evaluateProjectPolicies_ShouldFail_WhenCriticalCvePresent() {
        SecurityPolicy policy = SecurityPolicy.builder()
                .id(UUID.randomUUID())
                .name("No Critical CVEs")
                .policyType(PolicyType.NO_CRITICAL_CVE)
                .enabled(true)
                .configJson("{}")
                .project(project)
                .organization(org)
                .build();

        Vulnerability vuln = Vulnerability.builder()
                .id(UUID.randomUUID())
                .cveId("CVE-2024-0001")
                .severity(Severity.CRITICAL)
                .cvssScore(new BigDecimal("9.8"))
                .build();

        ComponentVulnerability cv = ComponentVulnerability.builder()
                .id(UUID.randomUUID())
                .vulnerability(vuln)
                .suppressed(false)
                .build();

        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        when(securityPolicyRepository.findEnabledForProject(project.getId(), org.getId()))
                .thenReturn(List.of(policy));
        when(componentVulnerabilityRepository.findByProjectId(project.getId())).thenReturn(List.of(cv));
        when(sbomComponentRepository.findByProjectId(project.getId())).thenReturn(Collections.emptyList());
        when(evaluationResultRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        ProjectPolicyEvaluationResponse response = policyService.evaluateProjectPolicies(project.getId());

        assertFalse(response.isOverallPassed());
        assertFalse(response.getEvaluations().get(0).isPassed());
        assertNotNull(response.getEvaluations().get(0).getFailureReason());
    }

    @Test
    void evaluateProjectPolicies_ShouldFail_WhenLicenseNotAllowed() {
        SecurityPolicy policy = SecurityPolicy.builder()
                .id(UUID.randomUUID())
                .name("Allowed Licenses")
                .policyType(PolicyType.ALLOWED_LICENSES)
                .enabled(true)
                .configJson("{\"allowed\":[\"MIT\",\"Apache-2.0\"]}")
                .project(project)
                .organization(org)
                .build();

        SbomComponent component = SbomComponent.builder()
                .id(UUID.randomUUID())
                .name("gpl-lib")
                .licenseExpression("GPL-3.0")
                .build();

        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        when(securityPolicyRepository.findEnabledForProject(project.getId(), org.getId()))
                .thenReturn(List.of(policy));
        when(componentVulnerabilityRepository.findByProjectId(project.getId())).thenReturn(Collections.emptyList());
        when(sbomComponentRepository.findByProjectId(project.getId())).thenReturn(List.of(component));
        when(evaluationResultRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        ProjectPolicyEvaluationResponse response = policyService.evaluateProjectPolicies(project.getId());

        assertFalse(response.isOverallPassed());
        assertTrue(response.getEvaluations().get(0).getFailureReason().contains("GPL-3.0"));
    }

    @Test
    void evaluateProjectPolicies_ShouldPass_WhenAllowedLicensesAliasKeyUsed() {
        SecurityPolicy policy = SecurityPolicy.builder()
                .id(UUID.randomUUID())
                .name("Allowed Licenses")
                .policyType(PolicyType.ALLOWED_LICENSES)
                .enabled(true)
                .configJson("{\"allowedLicenses\":[\"MIT\",\"Apache-2.0\"]}")
                .project(project)
                .organization(org)
                .build();

        SbomComponent component = SbomComponent.builder()
                .id(UUID.randomUUID())
                .name("mit-lib")
                .licenseExpression("MIT")
                .build();

        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        when(securityPolicyRepository.findEnabledForProject(project.getId(), org.getId()))
                .thenReturn(List.of(policy));
        when(componentVulnerabilityRepository.findByProjectId(project.getId())).thenReturn(Collections.emptyList());
        when(sbomComponentRepository.findByProjectId(project.getId())).thenReturn(List.of(component));
        when(evaluationResultRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        ProjectPolicyEvaluationResponse response = policyService.evaluateProjectPolicies(project.getId());

        assertTrue(response.isOverallPassed());
    }

    @Test
    void evaluateProjectPolicies_ShouldPass_WhenLicenseNull() {
        SecurityPolicy policy = SecurityPolicy.builder()
                .id(UUID.randomUUID())
                .name("Allowed Licenses")
                .policyType(PolicyType.ALLOWED_LICENSES)
                .enabled(true)
                .configJson("{\"allowed\":[\"MIT\"]}")
                .project(project)
                .organization(org)
                .build();

        SbomComponent component = SbomComponent.builder()
                .id(UUID.randomUUID())
                .name("unknown-lib")
                .licenseExpression(null)
                .build();

        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        when(securityPolicyRepository.findEnabledForProject(project.getId(), org.getId()))
                .thenReturn(List.of(policy));
        when(componentVulnerabilityRepository.findByProjectId(project.getId())).thenReturn(Collections.emptyList());
        when(sbomComponentRepository.findByProjectId(project.getId())).thenReturn(List.of(component));
        when(evaluationResultRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        ProjectPolicyEvaluationResponse response = policyService.evaluateProjectPolicies(project.getId());

        assertTrue(response.isOverallPassed());
    }

    @Test
    void evaluateProjectPolicies_ShouldFail_WhenCvssExceedsThreshold() {
        SecurityPolicy policy = SecurityPolicy.builder()
                .id(UUID.randomUUID())
                .name("CVSS Threshold")
                .policyType(PolicyType.CVSS_THRESHOLD)
                .enabled(true)
                .configJson("{\"maxCvss\":7.0}")
                .project(project)
                .organization(org)
                .build();

        Vulnerability vuln = Vulnerability.builder()
                .id(UUID.randomUUID())
                .severity(Severity.HIGH)
                .cvssScore(new BigDecimal("8.5"))
                .build();

        ComponentVulnerability cv = ComponentVulnerability.builder()
                .id(UUID.randomUUID())
                .vulnerability(vuln)
                .suppressed(false)
                .build();

        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        when(securityPolicyRepository.findEnabledForProject(project.getId(), org.getId()))
                .thenReturn(List.of(policy));
        when(componentVulnerabilityRepository.findByProjectId(project.getId())).thenReturn(List.of(cv));
        when(sbomComponentRepository.findByProjectId(project.getId())).thenReturn(Collections.emptyList());
        when(evaluationResultRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        ProjectPolicyEvaluationResponse response = policyService.evaluateProjectPolicies(project.getId());

        assertFalse(response.isOverallPassed());
    }

    @Test
    void updatePolicy_ShouldThrowAccessDenied_WhenUserIsNotMember() {
        SecurityPolicy policy = SecurityPolicy.builder()
                .id(UUID.randomUUID())
                .name("Policy")
                .policyType(PolicyType.NO_CRITICAL_CVE)
                .organization(org)
                .build();

        when(securityPolicyRepository.findById(policy.getId())).thenReturn(Optional.of(policy));
        doThrow(new AccessDeniedException("Forbidden"))
                .when(organizationService).verifyMembership(org.getId(), user.getId());

        assertThrows(AccessDeniedException.class,
                () -> policyService.updatePolicy(user, policy.getId(), UpdatePolicyRequest.builder().name("X").build()));
    }

    @Test
    void deletePolicy_ShouldDisablePolicy() {
        SecurityPolicy policy = SecurityPolicy.builder()
                .id(UUID.randomUUID())
                .name("Policy")
                .policyType(PolicyType.NO_CRITICAL_CVE)
                .enabled(true)
                .organization(org)
                .build();

        when(securityPolicyRepository.findById(policy.getId())).thenReturn(Optional.of(policy));
        doNothing().when(organizationService).verifyMembership(org.getId(), user.getId());
        when(securityPolicyRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        policyService.deletePolicy(user, policy.getId());

        assertFalse(policy.isEnabled());
        verify(securityPolicyRepository).save(policy);
    }
}
