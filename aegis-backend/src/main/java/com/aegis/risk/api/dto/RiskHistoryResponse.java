package com.aegis.risk.api.dto;

import com.aegis.risk.domain.RiskGrade;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RiskHistoryResponse {

    private UUID id;
    private UUID projectId;
    private BigDecimal riskScore;
    private RiskGrade riskGrade;
    private Instant calculatedAt;
}
