package com.aegis.risk.application;

import com.aegis.vulnerability.domain.event.VulnerabilityCorrelatedEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class RiskEventListenerTest {

    @Mock
    private RiskService riskService;

    @InjectMocks
    private RiskEventListener eventListener;

    @Test
    void handleVulnerabilityCorrelated_ShouldDelegateToRiskService() {
        UUID sbomId = UUID.randomUUID();
        UUID projectId = UUID.randomUUID();

        VulnerabilityCorrelatedEvent event = new VulnerabilityCorrelatedEvent(this, sbomId, projectId);

        eventListener.handleVulnerabilityCorrelated(event);

        verify(riskService, times(1)).calculateProjectRisk(projectId);
    }
}
