package com.aegis.risk.application;

import com.aegis.auth.domain.Role;
import com.aegis.auth.domain.User;
import com.aegis.project.application.OrganizationService;
import com.aegis.project.domain.Organization;
import com.aegis.project.domain.Project;
import com.aegis.project.infrastructure.ProjectRepository;
import com.aegis.risk.api.dto.RiskHistoryResponse;
import com.aegis.risk.api.dto.RiskResponse;
import com.aegis.risk.domain.ProjectRisk;
import com.aegis.risk.domain.ProjectRiskHistory;
import com.aegis.risk.domain.RiskGrade;
import com.aegis.risk.infrastructure.repository.ProjectRiskHistoryRepository;
import com.aegis.risk.infrastructure.repository.ProjectRiskRepository;
import com.aegis.sbom.domain.SbomComponent;
import com.aegis.sbom.domain.SbomDocument;
import com.aegis.vulnerability.domain.ComponentVulnerability;
import com.aegis.vulnerability.domain.Severity;
import com.aegis.vulnerability.domain.Vulnerability;
import com.aegis.vulnerability.infrastructure.repository.ComponentVulnerabilityRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.access.AccessDeniedException;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RiskServiceTest {

    @Mock
    private ProjectRiskRepository projectRiskRepository;

    @Mock
    private ProjectRiskHistoryRepository riskHistoryRepository;

    @Mock
    private ComponentVulnerabilityRepository componentVulnerabilityRepository;

    @Mock
    private ProjectRepository projectRepository;

    @Mock
    private OrganizationService organizationService;

    @Mock
    private ApplicationEventPublisher eventPublisher;

    @InjectMocks
    private RiskService riskService;

    private User user;
    private Organization org;
    private Project project;
    private SbomDocument sbom;
    private SbomComponent component;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id(UUID.randomUUID())
                .email("auditor@aegis.local")
                .role(Role.AUDITOR)
                .build();

        org = Organization.builder()
                .id(UUID.randomUUID())
                .name("Risk Test Org")
                .build();

        project = Project.builder()
                .id(UUID.randomUUID())
                .organization(org)
                .name("Risk Test Project")
                .build();

        sbom = SbomDocument.builder()
                .id(UUID.randomUUID())
                .project(project)
                .build();

        component = SbomComponent.builder()
                .id(UUID.randomUUID())
                .sbom(sbom)
                .name("spring-core")
                .version("6.1.0")
                .build();
    }

    @Test
    void calculateProjectRisk_ShouldReturnGradeA_WhenNoVulnerabilitiesExist() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        when(componentVulnerabilityRepository.findByProjectId(project.getId())).thenReturn(Collections.emptyList());
        when(projectRiskRepository.findByProjectId(project.getId())).thenReturn(Optional.empty());
        when(projectRiskRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        RiskResponse response = riskService.calculateProjectRisk(project.getId());

        assertNotNull(response);
        assertEquals(0, BigDecimal.ZERO.compareTo(response.getRiskScore()));
        assertEquals(RiskGrade.A, response.getRiskGrade());
        verify(riskHistoryRepository, times(1)).save(any());
    }

    @Test
    void calculateProjectRisk_ShouldExcludeSuppressedVulnerabilities() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));

        Vulnerability vuln = Vulnerability.builder()
                .id(UUID.randomUUID())
                .cveId("CVE-2023-1111")
                .severity(Severity.CRITICAL)
                .cvssScore(new BigDecimal("9.8"))
                .build();

        ComponentVulnerability suppressedCv = ComponentVulnerability.builder()
                .id(UUID.randomUUID())
                .component(component)
                .vulnerability(vuln)
                .suppressed(true)
                .build();

        when(componentVulnerabilityRepository.findByProjectId(project.getId())).thenReturn(List.of(suppressedCv));
        when(projectRiskRepository.findByProjectId(project.getId())).thenReturn(Optional.empty());
        when(projectRiskRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        RiskResponse response = riskService.calculateProjectRisk(project.getId());

        assertEquals(0, BigDecimal.ZERO.compareTo(response.getRiskScore()));
        assertEquals(RiskGrade.A, response.getRiskGrade());
    }

    @Test
    void calculateProjectRisk_ShouldCalculateScoreAndGradeCorrectly_ForCriticalVulnerability() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));

        Vulnerability vuln = Vulnerability.builder()
                .id(UUID.randomUUID())
                .cveId("CVE-2021-44228")
                .severity(Severity.CRITICAL)
                .cvssScore(new BigDecimal("10.0"))
                .epssScore(new BigDecimal("0.95"))
                .build();

        ComponentVulnerability activeCv = ComponentVulnerability.builder()
                .id(UUID.randomUUID())
                .component(component)
                .vulnerability(vuln)
                .suppressed(false)
                .build();

        when(componentVulnerabilityRepository.findByProjectId(project.getId())).thenReturn(List.of(activeCv));
        when(projectRiskRepository.findByProjectId(project.getId())).thenReturn(Optional.empty());
        when(projectRiskRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        RiskResponse response = riskService.calculateProjectRisk(project.getId());

        assertTrue(response.getRiskScore().doubleValue() > 20.0);
        assertNotEquals(RiskGrade.A, response.getRiskGrade());
    }

    @Test
    void calculateProjectRisk_ShouldUseNumericCvssWhenPresent() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));

        Vulnerability withScore = Vulnerability.builder()
                .id(UUID.randomUUID())
                .cveId("CVE-2024-0001")
                .severity(Severity.HIGH)
                .cvssScore(new BigDecimal("7.5"))
                .build();
        Vulnerability vectorOnlyFallback = Vulnerability.builder()
                .id(UUID.randomUUID())
                .cveId("CVE-2024-0002")
                .severity(Severity.UNKNOWN)
                .cvssScore(null)
                .build();

        when(componentVulnerabilityRepository.findByProjectId(project.getId())).thenReturn(List.of(
                ComponentVulnerability.builder().id(UUID.randomUUID()).component(component).vulnerability(withScore).suppressed(false).build(),
                ComponentVulnerability.builder().id(UUID.randomUUID()).component(component).vulnerability(vectorOnlyFallback).suppressed(false).build()
        ));
        when(projectRiskRepository.findByProjectId(project.getId())).thenReturn(Optional.empty());
        when(projectRiskRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        RiskResponse withBoth = riskService.calculateProjectRisk(project.getId());

        when(componentVulnerabilityRepository.findByProjectId(project.getId())).thenReturn(List.of(
                ComponentVulnerability.builder().id(UUID.randomUUID()).component(component).vulnerability(withScore).suppressed(false).build()
        ));
        RiskResponse numericOnly = riskService.calculateProjectRisk(project.getId());

        assertTrue(withBoth.getRiskScore().compareTo(numericOnly.getRiskScore()) > 0);
        assertTrue(numericOnly.getRiskScore().doubleValue() > 0);
    }

    @Test
    void calculateProjectRisk_ShouldUseSeverityFallback_WhenCvssMissing() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));

        Vulnerability unknown = Vulnerability.builder()
                .id(UUID.randomUUID())
                .osvId("GHSA-unknown")
                .severity(Severity.UNKNOWN)
                .cvssScore(null)
                .build();
        Vulnerability criticalNoScore = Vulnerability.builder()
                .id(UUID.randomUUID())
                .osvId("GHSA-crit")
                .severity(Severity.CRITICAL)
                .cvssScore(null)
                .build();

        when(componentVulnerabilityRepository.findByProjectId(project.getId())).thenReturn(List.of(
                ComponentVulnerability.builder().id(UUID.randomUUID()).component(component).vulnerability(unknown).suppressed(false).build()
        ));
        when(projectRiskRepository.findByProjectId(project.getId())).thenReturn(Optional.empty());
        when(projectRiskRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        RiskResponse unknownRisk = riskService.calculateProjectRisk(project.getId());

        when(componentVulnerabilityRepository.findByProjectId(project.getId())).thenReturn(List.of(
                ComponentVulnerability.builder().id(UUID.randomUUID()).component(component).vulnerability(criticalNoScore).suppressed(false).build()
        ));
        RiskResponse criticalRisk = riskService.calculateProjectRisk(project.getId());

        assertTrue(criticalRisk.getRiskScore().compareTo(unknownRisk.getRiskScore()) > 0);
        assertEquals(1, criticalRisk.getCriticalCount());
    }

    @Test
    void getRiskHistory_ShouldReturnChronologicalHistory() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        doNothing().when(organizationService).verifyMembership(org.getId(), user.getId());

        ProjectRiskHistory historyEntry = ProjectRiskHistory.builder()
                .id(UUID.randomUUID())
                .project(project)
                .riskScore(new BigDecimal("45.00"))
                .riskGrade(RiskGrade.C)
                .calculatedAt(Instant.now())
                .build();

        when(riskHistoryRepository.findByProjectIdOrderByCalculatedAtDesc(project.getId()))
                .thenReturn(List.of(historyEntry));

        List<RiskHistoryResponse> history = riskService.getRiskHistory(user, project.getId());

        assertNotNull(history);
        assertEquals(1, history.size());
        assertEquals(RiskGrade.C, history.get(0).getRiskGrade());
    }

    @Test
    void getProjectRisk_ShouldThrowAccessDenied_WhenUserIsNotMember() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        doThrow(new AccessDeniedException("Forbidden")).when(organizationService).verifyMembership(org.getId(), user.getId());

        assertThrows(AccessDeniedException.class, () -> riskService.getProjectRisk(user, project.getId()));
    }
}
