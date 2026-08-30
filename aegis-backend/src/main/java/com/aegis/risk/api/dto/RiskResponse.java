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
public class RiskResponse {

    private UUID id;
    private UUID projectId;
    private BigDecimal riskScore;
    private RiskGrade riskGrade;
    private int criticalCount;
    private int highCount;
    private int mediumCount;
    private int lowCount;
    private Instant calculatedAt;
}
