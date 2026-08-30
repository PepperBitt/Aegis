package com.aegis.sbom.api.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SbomDependencyResponse {

    private UUID id;
    private UUID sbomId;
    private UUID parentComponentId;
    private String parentComponentName;
    private UUID childComponentId;
    private String childComponentName;
}
