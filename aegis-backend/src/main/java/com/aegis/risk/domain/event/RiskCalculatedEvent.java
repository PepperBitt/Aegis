package com.aegis.risk.domain.event;

import com.aegis.risk.domain.RiskGrade;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.math.BigDecimal;
import java.util.UUID;

@Getter
public class RiskCalculatedEvent extends ApplicationEvent {

    private final UUID projectId;
    private final BigDecimal riskScore;
    private final RiskGrade riskGrade;

    public RiskCalculatedEvent(Object source, UUID projectId, BigDecimal riskScore, RiskGrade riskGrade) {
        super(source);
        this.projectId = projectId;
        this.riskScore = riskScore;
        this.riskGrade = riskGrade;
    }
}
