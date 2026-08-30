package com.aegis.policy.api.dto;

import com.aegis.policy.domain.PolicyType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PolicyEvaluationResponse {

    private UUID policyId;
    private String policyName;
    private PolicyType policyType;
    private boolean passed;
    private String failureReason;
    private Instant evaluatedAt;
}
