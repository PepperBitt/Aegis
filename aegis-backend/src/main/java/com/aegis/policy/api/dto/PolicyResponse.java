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
public class PolicyResponse {

    private UUID id;
    private UUID organizationId;
    private UUID projectId;
    private String name;
    private String description;
    private PolicyType policyType;
    private boolean enabled;
    private String configJson;
    private Instant createdAt;
    private Instant updatedAt;
}
