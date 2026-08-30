package com.aegis.policy.api.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProjectPolicyEvaluationResponse {

    private UUID projectId;
    private boolean overallPassed;
    private List<PolicyEvaluationResponse> evaluations;
}
