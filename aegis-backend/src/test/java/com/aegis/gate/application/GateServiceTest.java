package com.aegis.gate.application;

import com.aegis.auth.domain.Role;
import com.aegis.auth.domain.User;
import com.aegis.gate.api.dto.GateCheckRequest;
import com.aegis.gate.api.dto.GateCheckResponse;
import com.aegis.gate.domain.GateCheck;
import com.aegis.gate.domain.GateResult;
import com.aegis.gate.domain.event.GateCheckCompletedEvent;
import com.aegis.gate.infrastructure.repository.GateCheckRepository;
import com.aegis.policy.api.dto.PolicyEvaluationResponse;
import com.aegis.policy.api.dto.ProjectPolicyEvaluationResponse;
import com.aegis.policy.application.PolicyService;
import com.aegis.policy.domain.PolicyType;
import com.aegis.project.application.OrganizationService;
import com.aegis.project.domain.Organization;
import com.aegis.project.domain.Project;
import com.aegis.project.infrastructure.ProjectRepository;
import com.aegis.risk.api.dto.RiskResponse;
import com.aegis.risk.application.RiskService;
import com.aegis.risk.domain.RiskGrade;
import com.aegis.risk.infrastructure.repository.ProjectRiskRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.access.AccessDeniedException;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class GateServiceTest {

    @Mock
    private GateCheckRepository gateCheckRepository;

    @Mock
    private PolicyService policyService;

    @Mock
    private ProjectRiskRepository projectRiskRepository;

    @Mock
    private RiskService riskService;

    @Mock
    private ProjectRepository projectRepository;

    @Mock
    private OrganizationService organizationService;

    @Mock
    private ApplicationEventPublisher eventPublisher;

    @Spy
    private ObjectMapper objectMapper = new ObjectMapper();

    @InjectMocks
    private GateService gateService;

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
                .name("Gate Org")
                .build();

        project = Project.builder()
                .id(UUID.randomUUID())
                .organization(org)
                .name("Gate Project")
                .build();
    }

    @Test
    void checkGate_ShouldPass_WhenPoliciesPass() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        doNothing().when(organizationService).verifyMembership(org.getId(), user.getId());

        ProjectPolicyEvaluationResponse evaluation = ProjectPolicyEvaluationResponse.builder()
                .projectId(project.getId())
                .overallPassed(true)
                .evaluations(List.of(PolicyEvaluationResponse.builder()
                        .policyId(UUID.randomUUID())
                        .policyName("No Critical")
                        .policyType(PolicyType.NO_CRITICAL_CVE)
                        .passed(true)
                        .evaluatedAt(Instant.now())
                        .build()))
                .build();

        when(policyService.evaluateProjectPolicies(project.getId())).thenReturn(evaluation);
        when(projectRiskRepository.findByProjectId(project.getId())).thenReturn(Optional.empty());
        when(riskService.calculateProjectRisk(project.getId())).thenReturn(RiskResponse.builder()
                .projectId(project.getId())
                .riskScore(new BigDecimal("10.00"))
                .riskGrade(RiskGrade.A)
                .build());
        when(gateCheckRepository.save(any())).thenAnswer(inv -> {
            GateCheck gc = inv.getArgument(0);
            gc.setId(UUID.randomUUID());
            gc.setCreatedAt(Instant.now());
            return gc;
        });

        GateCheckResponse response = gateService.checkGate(user, GateCheckRequest.builder()
                .projectId(project.getId())
                .metadata("{\"pipeline\":\"ci\"}")
                .build());

        assertEquals(GateResult.PASS, response.getResult());
        assertEquals(0, response.getPoliciesFailed());
        assertEquals(1, response.getPoliciesEvaluated());
        assertTrue(response.getFailureReasons().isEmpty());

        ArgumentCaptor<GateCheckCompletedEvent> eventCaptor = ArgumentCaptor.forClass(GateCheckCompletedEvent.class);
        verify(eventPublisher).publishEvent(eventCaptor.capture());
        assertEquals(GateResult.PASS, eventCaptor.getValue().getResult());
    }

    @Test
    void checkGate_ShouldFail_WhenPoliciesFail() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        doNothing().when(organizationService).verifyMembership(org.getId(), user.getId());

        ProjectPolicyEvaluationResponse evaluation = ProjectPolicyEvaluationResponse.builder()
                .projectId(project.getId())
                .overallPassed(false)
                .evaluations(List.of(PolicyEvaluationResponse.builder()
                        .policyId(UUID.randomUUID())
                        .policyName("No Critical")
                        .policyType(PolicyType.NO_CRITICAL_CVE)
                        .passed(false)
                        .failureReason("Found 1 CRITICAL")
                        .evaluatedAt(Instant.now())
                        .build()))
                .build();

        when(policyService.evaluateProjectPolicies(project.getId())).thenReturn(evaluation);
        when(projectRiskRepository.findByProjectId(project.getId())).thenReturn(Optional.empty());
        when(riskService.calculateProjectRisk(project.getId())).thenReturn(RiskResponse.builder()
                .projectId(project.getId())
                .riskScore(new BigDecimal("80.00"))
                .riskGrade(RiskGrade.D)
                .build());
        when(gateCheckRepository.save(any())).thenAnswer(inv -> {
            GateCheck gc = inv.getArgument(0);
            gc.setId(UUID.randomUUID());
            gc.setCreatedAt(Instant.now());
            return gc;
        });

        GateCheckResponse response = gateService.checkGate(user, GateCheckRequest.builder()
                .projectId(project.getId())
                .build());

        assertEquals(GateResult.FAIL, response.getResult());
        assertEquals(1, response.getPoliciesFailed());
        assertFalse(response.getFailureReasons().isEmpty());
    }

    @Test
    void checkGate_ShouldThrowAccessDenied_WhenUserIsNotMember() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        doThrow(new AccessDeniedException("Forbidden"))
                .when(organizationService).verifyMembership(org.getId(), user.getId());

        assertThrows(AccessDeniedException.class, () -> gateService.checkGate(user,
                GateCheckRequest.builder().projectId(project.getId()).build()));
    }

    @Test
    void listGateChecks_ShouldReturnHistory() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        doNothing().when(organizationService).verifyMembership(org.getId(), user.getId());

        GateCheck gateCheck = GateCheck.builder()
                .id(UUID.randomUUID())
                .project(project)
                .result(GateResult.PASS)
                .failureReasons("[]")
                .policiesEvaluated(2)
                .policiesFailed(0)
                .riskScore(new BigDecimal("5.00"))
                .riskGrade(RiskGrade.A)
                .createdAt(Instant.now())
                .build();

        when(gateCheckRepository.findByProjectIdOrderByCreatedAtDesc(project.getId()))
                .thenReturn(List.of(gateCheck));

        List<GateCheckResponse> results = gateService.listGateChecks(user, project.getId());

        assertEquals(1, results.size());
        assertEquals(GateResult.PASS, results.get(0).getResult());
    }
}
