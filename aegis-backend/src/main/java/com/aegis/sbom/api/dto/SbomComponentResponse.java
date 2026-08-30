package com.aegis.sbom.api.dto;

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
public class SbomComponentResponse {

    private UUID id;
    private UUID sbomId;
    private String name;
    private String version;
    private String purl;
    private String cpe;
    private String componentType;
    private String groupName;
    private String supplier;
    private String licenseExpression;
    private String hashSha256;
    private String hashSha1;
    private String hashMd5;
    private String description;
    private Instant createdAt;
}
