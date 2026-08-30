package com.aegis.risk.application;

import com.aegis.vulnerability.domain.event.VulnerabilityCorrelatedEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Slf4j
@Component
@RequiredArgsConstructor
public class RiskEventListener {

    private final RiskService riskService;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void handleVulnerabilityCorrelated(VulnerabilityCorrelatedEvent event) {
        log.info("Handling VulnerabilityCorrelatedEvent AFTER_COMMIT for risk calculation, projectId: {}", event.getProjectId());
        try {
            riskService.calculateProjectRisk(event.getProjectId());
        } catch (Exception e) {
            log.error("Failed to calculate project risk for project {} in event listener", event.getProjectId(), e);
        }
    }
}
