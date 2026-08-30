package com.aegis.gate.application;

import com.aegis.audit.annotation.AuditAction;
import com.aegis.auth.domain.User;
import com.aegis.gate.api.dto.GateCheckRequest;
import com.aegis.gate.api.dto.GateCheckResponse;
import com.aegis.gate.domain.GateCheck;
import com.aegis.gate.domain.GateResult;
import com.aegis.gate.domain.event.GateCheckCompletedEvent;
import com.aegis.gate.infrastructure.repository.GateCheckRepository;
import com.aegis.policy.api.dto.ProjectPolicyEvaluationResponse;
import com.aegis.policy.application.PolicyService;
import com.aegis.project.application.OrganizationService;
import com.aegis.project.domain.Project;
import com.aegis.project.infrastructure.ProjectRepository;
import com.aegis.risk.api.dto.RiskResponse;
import com.aegis.risk.application.RiskService;
import com.aegis.risk.domain.RiskGrade;
import com.aegis.risk.infrastructure.repository.ProjectRiskRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
@org.springframework.transaction.annotation.Transactional(transactionManager = "transactionManager")
public class GateService {

    private final GateCheckRepository gateCheckRepository;
    private final PolicyService policyService;
    private final ProjectRiskRepository projectRiskRepository;
    private final RiskService riskService;
    private final ProjectRepository projectRepository;
    private final OrganizationService organizationService;
    private final ApplicationEventPublisher eventPublisher;
    private final ObjectMapper objectMapper;

    @Transactional
    @AuditAction(action = "GATE_CHECK", resourceType = "GATE")
    public GateCheckResponse checkGate(User user, GateCheckRequest request) {
        Project project = projectRepository.findById(request.getProjectId())
                .orElseThrow(() -> new IllegalArgumentException("Project not found"));
        organizationService.verifyMembership(project.getOrganization().getId(), user.getId());

        ProjectPolicyEvaluationResponse evaluation = policyService.evaluateProjectPolicies(project.getId());

        RiskSnapshot risk = resolveRisk(project.getId());

        List<String> failureReasons = evaluation.getEvaluations().stream()
                .filter(e -> !e.isPassed())
                .map(e -> e.getPolicyName() + ": " + (e.getFailureReason() != null ? e.getFailureReason() : "failed"))
                .collect(Collectors.toList());

        int policiesEvaluated = evaluation.getEvaluations() != null ? evaluation.getEvaluations().size() : 0;
        int policiesFailed = (int) evaluation.getEvaluations().stream().filter(e -> !e.isPassed()).count();

        GateResult result = evaluation.isOverallPassed() ? GateResult.PASS : GateResult.FAIL;

        GateCheck gateCheck = GateCheck.builder()
                .project(project)
                .requestedBy(user)
                .result(result)
                .failureReasons(serializeFailureReasons(failureReasons))
                .riskScore(risk.score())
                .riskGrade(risk.grade())
                .policiesEvaluated(policiesEvaluated)
                .policiesFailed(policiesFailed)
                .metadataJson(request.getMetadata())
                .build();

        GateCheck saved = gateCheckRepository.save(gateCheck);

        eventPublisher.publishEvent(new GateCheckCompletedEvent(
                this, saved.getId(), project.getId(), saved.getResult()));

        log.info("Gate check {} for project {}: result={}, failedPolicies={}",
                saved.getId(), project.getId(), result, policiesFailed);

        return mapToResponse(saved);
    }

    @Transactional(readOnly = true)
    public List<GateCheckResponse> listGateChecks(User user, UUID projectId) {
        verifyProjectAccess(user, projectId);
        return gateCheckRepository.findByProjectIdOrderByCreatedAtDesc(projectId).stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public GateCheckResponse getGateCheck(User user, UUID projectId, UUID gateId) {
        verifyProjectAccess(user, projectId);
        GateCheck gateCheck = gateCheckRepository.findByIdAndProjectId(gateId, projectId)
                .orElseThrow(() -> new IllegalArgumentException("Gate check not found"));
        return mapToResponse(gateCheck);
    }

    private RiskSnapshot resolveRisk(UUID projectId) {
        return projectRiskRepository.findByProjectId(projectId)
                .map(r -> new RiskSnapshot(r.getRiskScore(), r.getRiskGrade()))
                .orElseGet(() -> {
                    RiskResponse calculated = riskService.calculateProjectRisk(projectId);
                    return new RiskSnapshot(calculated.getRiskScore(), calculated.getRiskGrade());
                });
    }

    private void verifyProjectAccess(User user, UUID projectId) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new IllegalArgumentException("Project not found"));
        organizationService.verifyMembership(project.getOrganization().getId(), user.getId());
    }

    private String serializeFailureReasons(List<String> reasons) {
        try {
            return objectMapper.writeValueAsString(reasons != null ? reasons : Collections.emptyList());
        } catch (Exception e) {
            return "[]";
        }
    }

    private List<String> deserializeFailureReasons(String raw) {
        if (raw == null || raw.isBlank()) {
            return Collections.emptyList();
        }
        try {
            return objectMapper.readValue(raw, new TypeReference<List<String>>() {});
        } catch (Exception e) {
            return List.of(raw);
        }
    }

    private GateCheckResponse mapToResponse(GateCheck gateCheck) {
        return GateCheckResponse.builder()
                .id(gateCheck.getId())
                .projectId(gateCheck.getProject().getId())
                .result(gateCheck.getResult())
                .failureReasons(deserializeFailureReasons(gateCheck.getFailureReasons()))
                .riskScore(gateCheck.getRiskScore())
                .riskGrade(gateCheck.getRiskGrade())
                .policiesEvaluated(gateCheck.getPoliciesEvaluated())
                .policiesFailed(gateCheck.getPoliciesFailed())
                .createdAt(gateCheck.getCreatedAt())
                .build();
    }

    private record RiskSnapshot(BigDecimal score, RiskGrade grade) {}
}
