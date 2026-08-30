package com.aegis.risk.application;

import com.aegis.auth.domain.User;
import com.aegis.project.application.OrganizationService;
import com.aegis.project.domain.Project;
import com.aegis.project.infrastructure.ProjectRepository;
import com.aegis.risk.api.dto.RiskHistoryResponse;
import com.aegis.risk.api.dto.RiskResponse;
import com.aegis.risk.domain.ProjectRisk;
import com.aegis.risk.domain.ProjectRiskHistory;
import com.aegis.risk.domain.RiskGrade;
import com.aegis.risk.domain.event.RiskCalculatedEvent;
import com.aegis.risk.infrastructure.repository.ProjectRiskHistoryRepository;
import com.aegis.risk.infrastructure.repository.ProjectRiskRepository;
import com.aegis.vulnerability.domain.ComponentVulnerability;
import com.aegis.vulnerability.domain.Severity;
import com.aegis.vulnerability.domain.Vulnerability;
import com.aegis.vulnerability.infrastructure.repository.ComponentVulnerabilityRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(transactionManager = "transactionManager")
public class RiskService {

    private final ProjectRiskRepository projectRiskRepository;
    private final ProjectRiskHistoryRepository riskHistoryRepository;
    private final ComponentVulnerabilityRepository componentVulnerabilityRepository;
    private final ProjectRepository projectRepository;
    private final OrganizationService organizationService;
    private final ApplicationEventPublisher eventPublisher;

    @Transactional
    public RiskResponse calculateProjectRisk(UUID projectId) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new IllegalArgumentException("Project not found"));

        List<ComponentVulnerability> allFindings = componentVulnerabilityRepository.findByProjectId(projectId);

        // Filter out suppressed findings
        List<ComponentVulnerability> activeFindings = allFindings.stream()
                .filter(cv -> !cv.isSuppressed())
                .collect(Collectors.toList());

        // Group by unique vulnerability ID to prevent artificial inflation
        Map<UUID, Vulnerability> uniqueVulns = new HashMap<>();
        Map<UUID, Long> findingCounts = new HashMap<>();
        for (ComponentVulnerability cv : activeFindings) {
            Vulnerability v = cv.getVulnerability();
            uniqueVulns.put(v.getId(), v);
            findingCounts.merge(v.getId(), 1L, Long::sum);
        }

        int criticalCount = 0;
        int highCount = 0;
        int mediumCount = 0;
        int lowCount = 0;
        for (Vulnerability v : uniqueVulns.values()) {
            Severity s = v.getSeverity() != null ? v.getSeverity() : Severity.UNKNOWN;
            switch (s) {
                case CRITICAL -> criticalCount++;
                case HIGH -> highCount++;
                case MEDIUM -> mediumCount++;
                case LOW -> lowCount++;
                default -> {}
            }
        }

        double totalRiskScore = 0.0;

        for (Vulnerability v : uniqueVulns.values()) {
            Severity severity = v.getSeverity() != null ? v.getSeverity() : Severity.UNKNOWN;
            double baseWeight = getSeverityWeight(severity);

            double normalizedCvss = v.getCvssScore() != null
                    ? v.getCvssScore().doubleValue() / 10.0
                    : getFallbackCvss(severity);

            // Use stored EPSS only; when absent apply a documented low unknown-exploitability default
            double epssContrib = v.getEpssScore() != null
                    ? Math.min(1.0, Math.max(0.0, v.getEpssScore().doubleValue()))
                    : 0.10;

            // Blast-radius factor from how many components share this finding (bounded 1.0–1.5)
            long sharedFindings = findingCounts.getOrDefault(v.getId(), 1L);
            double dependencyImpact = Math.min(1.5, 1.0 + (sharedFindings - 1) * 0.05);

            double vulnRisk = baseWeight * (0.6 * normalizedCvss + 0.2 * epssContrib + 0.2 * dependencyImpact);
            totalRiskScore += vulnRisk;
        }

        double clampedScore = Math.min(100.00, Math.max(0.00, totalRiskScore));
        BigDecimal finalScore = BigDecimal.valueOf(clampedScore).setScale(2, RoundingMode.HALF_UP);
        RiskGrade grade = RiskGrade.fromScore(finalScore.doubleValue());

        Instant now = Instant.now();

        ProjectRisk projectRisk = projectRiskRepository.findByProjectId(projectId)
                .orElseGet(() -> ProjectRisk.builder().project(project).build());

        projectRisk.setRiskScore(finalScore);
        projectRisk.setRiskGrade(grade);
        projectRisk.setCriticalCount(criticalCount);
        projectRisk.setHighCount(highCount);
        projectRisk.setMediumCount(mediumCount);
        projectRisk.setLowCount(lowCount);
        projectRisk.setCalculatedAt(now);

        ProjectRisk savedRisk = projectRiskRepository.save(projectRisk);

        // Record history snapshot
        ProjectRiskHistory history = ProjectRiskHistory.builder()
                .project(project)
                .riskScore(finalScore)
                .riskGrade(grade)
                .calculatedAt(now)
                .build();
        riskHistoryRepository.save(history);

        eventPublisher.publishEvent(new RiskCalculatedEvent(this, projectId, finalScore, grade));

        log.info("Calculated risk for project {}: score={}, grade={}", projectId, finalScore, grade);
        return mapToRiskResponse(savedRisk);
    }

    @Transactional
    public RiskResponse getProjectRisk(User user, UUID projectId) {
        verifyProjectAccess(user, projectId);
        Optional<ProjectRisk> riskOpt = projectRiskRepository.findByProjectId(projectId);
        if (riskOpt.isPresent()) {
            return mapToRiskResponse(riskOpt.get());
        }
        return calculateProjectRisk(projectId);
    }

    @Transactional(readOnly = true)
    public List<RiskHistoryResponse> getRiskHistory(User user, UUID projectId) {
        verifyProjectAccess(user, projectId);
        return riskHistoryRepository.findByProjectIdOrderByCalculatedAtDesc(projectId)
                .stream()
                .map(this::mapToHistoryResponse)
                .collect(Collectors.toList());
    }

    @Transactional
    public RiskResponse recalculateProjectRisk(User user, UUID projectId) {
        verifyProjectAccess(user, projectId);
        return calculateProjectRisk(projectId);
    }

    private void verifyProjectAccess(User user, UUID projectId) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new IllegalArgumentException("Project not found"));
        organizationService.verifyMembership(project.getOrganization().getId(), user.getId());
    }

    private double getSeverityWeight(Severity severity) {
        return switch (severity) {
            case CRITICAL -> 25.0;
            case HIGH -> 15.0;
            case MEDIUM -> 5.0;
            case LOW -> 1.5;
            case INFO, UNKNOWN -> 0.5;
        };
    }

    private double getFallbackCvss(Severity severity) {
        return switch (severity) {
            case CRITICAL -> 0.95;
            case HIGH -> 0.75;
            case MEDIUM -> 0.50;
            case LOW -> 0.20;
            case INFO, UNKNOWN -> 0.10;
        };
    }

    private RiskResponse mapToRiskResponse(ProjectRisk r) {
        return RiskResponse.builder()
                .id(r.getId())
                .projectId(r.getProject().getId())
                .riskScore(r.getRiskScore())
                .riskGrade(r.getRiskGrade())
                .criticalCount(r.getCriticalCount())
                .highCount(r.getHighCount())
                .mediumCount(r.getMediumCount())
                .lowCount(r.getLowCount())
                .calculatedAt(r.getCalculatedAt())
                .build();
    }

    private RiskHistoryResponse mapToHistoryResponse(ProjectRiskHistory h) {
        return RiskHistoryResponse.builder()
                .id(h.getId())
                .projectId(h.getProject().getId())
                .riskScore(h.getRiskScore())
                .riskGrade(h.getRiskGrade())
                .calculatedAt(h.getCalculatedAt())
                .build();
    }
}
