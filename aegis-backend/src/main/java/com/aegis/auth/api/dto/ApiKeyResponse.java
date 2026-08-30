package com.aegis.auth.api.dto;

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
public class ApiKeyResponse {

    private UUID id;
    private String name;
    private String keyPrefix;
    private String scopes;
    private boolean revoked;
    private Instant expiresAt;
    private Instant lastUsedAt;
    private Instant createdAt;
}
