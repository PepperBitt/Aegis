package com.aegis.alert.api.dto;

import com.aegis.alert.domain.AlertSeverity;
import com.aegis.alert.domain.AlertType;
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
public class AlertResponse {

    private UUID id;
    private UUID projectId;
    private UUID organizationId;
    private AlertType alertType;
    private AlertSeverity severity;
    private String title;
    private String message;
    private boolean acknowledged;
    private UUID acknowledgedBy;
    private Instant acknowledgedAt;
    private String metadataJson;
    private Instant createdAt;
}
