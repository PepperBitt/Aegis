package com.aegis.alert.application;

import com.aegis.alert.api.dto.AlertResponse;
import com.aegis.alert.domain.Alert;
import com.aegis.alert.domain.AlertSeverity;
import com.aegis.alert.domain.AlertType;
import com.aegis.alert.infrastructure.repository.AlertRepository;
import com.aegis.auth.domain.User;
import com.aegis.project.application.OrganizationService;
import com.aegis.project.domain.Organization;
import com.aegis.project.domain.Project;
import com.aegis.project.infrastructure.ProjectRepository;
import com.aegis.risk.domain.RiskGrade;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(transactionManager = "transactionManager")
public class AlertService {

    private final AlertRepository alertRepository;
    private final ProjectRepository projectRepository;
    private final OrganizationService organizationService;

    @Transactional
    public Alert createAlert(
            UUID projectId,
            AlertType alertType,
            AlertSeverity severity,
            String title,
            String message,
            String metadataJson
    ) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new IllegalArgumentException("Project not found"));
        Organization organization = project.getOrganization();

        Alert alert = Alert.builder()
                .project(project)
                .organization(organization)
                .alertType(alertType)
                .severity(severity)
                .title(title)
                .message(message)
                .acknowledged(false)
                .metadataJson(metadataJson)
                .build();

        Alert saved = alertRepository.save(alert);
        log.info("Created {} alert for project {}: {}", alertType, projectId, title);
        return saved;
    }

    @Transactional(readOnly = true)
    public List<AlertResponse> listAlerts(User user, UUID projectId) {
        verifyProjectAccess(user, projectId);
        return alertRepository.findByProjectIdOrderByCreatedAtDesc(projectId).stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<AlertResponse> listUnread(User user, UUID projectId) {
        verifyProjectAccess(user, projectId);
        return alertRepository.findByProjectIdAndAcknowledgedFalse(projectId).stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    @Transactional
    public AlertResponse acknowledge(User user, UUID projectId, UUID alertId) {
        verifyProjectAccess(user, projectId);
        Alert alert = alertRepository.findByIdAndProjectId(alertId, projectId)
                .orElseThrow(() -> new IllegalArgumentException("Alert not found"));

        alert.setAcknowledged(true);
        alert.setAcknowledgedBy(user);
        alert.setAcknowledgedAt(Instant.now());

        return mapToResponse(alertRepository.save(alert));
    }

    @Transactional
    public void createCriticalVulnerabilityAlert(UUID projectId, long criticalCount) {
        if (alertRepository.existsByProjectIdAndAlertTypeAndAcknowledgedFalse(
                projectId, AlertType.CRITICAL_VULNERABILITY)) {
            log.debug("Skipping duplicate unacknowledged CRITICAL_VULNERABILITY alert for project {}", projectId);
            return;
        }
        createAlert(
                projectId,
                AlertType.CRITICAL_VULNERABILITY,
                AlertSeverity.CRITICAL,
                "Critical vulnerabilities detected",
                "Project has " + criticalCount + " non-suppressed CRITICAL vulnerability finding(s).",
                "{\"criticalCount\":" + criticalCount + "}"
        );
    }

    @Transactional
    public void createGateFailureAlert(UUID projectId, UUID gateCheckId) {
        String fragment = "%\"gateCheckId\":\"" + gateCheckId + "\"%";
        if (alertRepository.existsUnacknowledgedWithMetadata(
                projectId, AlertType.GATE_FAILURE, fragment)) {
            log.debug("Skipping duplicate GATE_FAILURE alert for gateCheckId {}", gateCheckId);
            return;
        }
        createAlert(
                projectId,
                AlertType.GATE_FAILURE,
                AlertSeverity.HIGH,
                "Gate check failed",
                "A CI/CD gate check failed for this project.",
                "{\"gateCheckId\":\"" + gateCheckId + "\"}"
        );
    }

    @Transactional
    public void createRiskThresholdAlert(UUID projectId, BigDecimal riskScore, RiskGrade riskGrade) {
        if (alertRepository.existsByProjectIdAndAlertTypeAndAcknowledgedFalse(
                projectId, AlertType.RISK_THRESHOLD)) {
            log.debug("Skipping duplicate unacknowledged RISK_THRESHOLD alert for project {}", projectId);
            return;
        }
        createAlert(
                projectId,
                AlertType.RISK_THRESHOLD,
                AlertSeverity.HIGH,
                "Risk score threshold exceeded",
                "Project risk score is " + riskScore + " (grade " + riskGrade + "), which meets or exceeds the alert threshold of 70.",
                "{\"riskScore\":" + riskScore + ",\"riskGrade\":\"" + riskGrade + "\"}"
        );
    }

    private void verifyProjectAccess(User user, UUID projectId) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new IllegalArgumentException("Project not found"));
        organizationService.verifyMembership(project.getOrganization().getId(), user.getId());
    }

    private AlertResponse mapToResponse(Alert alert) {
        return AlertResponse.builder()
                .id(alert.getId())
                .projectId(alert.getProject().getId())
                .organizationId(alert.getOrganization() != null ? alert.getOrganization().getId() : null)
                .alertType(alert.getAlertType())
                .severity(alert.getSeverity())
                .title(alert.getTitle())
                .message(alert.getMessage())
                .acknowledged(alert.isAcknowledged())
                .acknowledgedBy(alert.getAcknowledgedBy() != null ? alert.getAcknowledgedBy().getId() : null)
                .acknowledgedAt(alert.getAcknowledgedAt())
                .metadataJson(alert.getMetadataJson())
                .createdAt(alert.getCreatedAt())
                .build();
    }
}
