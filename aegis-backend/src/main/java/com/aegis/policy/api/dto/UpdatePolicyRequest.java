package com.aegis.policy.api.dto;

import com.aegis.policy.domain.PolicyType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdatePolicyRequest {

    private String name;

    private String description;

    private PolicyType policyType;

    private String configJson;

    private Boolean enabled;
}
