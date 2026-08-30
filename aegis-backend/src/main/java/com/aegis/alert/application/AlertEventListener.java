package com.aegis.alert.application;

import com.aegis.gate.domain.GateResult;
import com.aegis.gate.domain.event.GateCheckCompletedEvent;
import com.aegis.risk.domain.event.RiskCalculatedEvent;
import com.aegis.vulnerability.domain.ComponentVulnerability;
import com.aegis.vulnerability.domain.Severity;
import com.aegis.vulnerability.domain.event.VulnerabilityCorrelatedEvent;
import com.aegis.vulnerability.infrastructure.repository.ComponentVulnerabilityRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.math.BigDecimal;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class AlertEventListener {

    private static final BigDecimal RISK_ALERT_THRESHOLD = new BigDecimal("70");

    private final AlertService alertService;
    private final ComponentVulnerabilityRepository componentVulnerabilityRepository;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void handleVulnerabilityCorrelated(VulnerabilityCorrelatedEvent event) {
        try {
            List<ComponentVulnerability> findings = componentVulnerabilityRepository.findByProjectId(event.getProjectId());
            long criticalCount = findings.stream()
                    .filter(cv -> !cv.isSuppressed())
                    .filter(cv -> cv.getVulnerability() != null
                            && cv.getVulnerability().getSeverity() == Severity.CRITICAL)
                    .count();

            if (criticalCount > 0) {
                alertService.createCriticalVulnerabilityAlert(event.getProjectId(), criticalCount);
            }
        } catch (Exception e) {
            log.error("Failed to create critical vulnerability alert for project {}", event.getProjectId(), e);
        }
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void handleGateCheckCompleted(GateCheckCompletedEvent event) {
        try {
            if (event.getResult() == GateResult.FAIL) {
                alertService.createGateFailureAlert(event.getProjectId(), event.getGateCheckId());
            }
        } catch (Exception e) {
            log.error("Failed to create gate failure alert for project {}", event.getProjectId(), e);
        }
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void handleRiskCalculated(RiskCalculatedEvent event) {
        try {
            if (event.getRiskScore() != null
                    && event.getRiskScore().compareTo(RISK_ALERT_THRESHOLD) >= 0) {
                alertService.createRiskThresholdAlert(
                        event.getProjectId(),
                        event.getRiskScore(),
                        event.getRiskGrade()
                );
            }
        } catch (Exception e) {
            log.error("Failed to create risk threshold alert for project {}", event.getProjectId(), e);
        }
    }
}
