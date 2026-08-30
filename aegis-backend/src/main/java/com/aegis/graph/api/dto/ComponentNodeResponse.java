package com.aegis.graph.api.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ComponentNodeResponse {

    private String graphNodeId;
    private UUID componentId;
    private UUID projectId;
    private UUID sbomId;
    private String name;
    private String version;
    private String purl;
    private String cpe;
    private String groupName;
    private String ecosystem;
}
