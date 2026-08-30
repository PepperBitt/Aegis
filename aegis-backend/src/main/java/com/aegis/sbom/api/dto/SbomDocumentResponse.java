package com.aegis.sbom.api.dto;

import com.aegis.sbom.domain.SbomFormat;
import com.aegis.sbom.domain.SbomStatus;
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
public class SbomDocumentResponse {

    private UUID id;
    private UUID projectId;
    private String name;
    private String version;
    private SbomFormat format;
    private String specVersion;
    private String serialNumber;
    private String supplier;
    private SbomStatus status;
    private int componentCount;
    private String filePath;
    private Long fileSizeBytes;
    private UUID createdById;
    private Instant createdAt;
    private Instant updatedAt;
}
