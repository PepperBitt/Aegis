package com.aegis.gate.api.dto;

import com.aegis.gate.domain.GateResult;
import com.aegis.risk.domain.RiskGrade;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GateCheckResponse {

    private UUID id;
    private UUID projectId;
    private GateResult result;
    private List<String> failureReasons;
    private BigDecimal riskScore;
    private RiskGrade riskGrade;
    private int policiesEvaluated;
    private int policiesFailed;
    private Instant createdAt;
}
