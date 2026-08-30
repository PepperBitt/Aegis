package com.aegis.graph.api.dto;

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
public class DependencyPathResponse {

    private UUID sourceComponentId;
    private UUID targetComponentId;
    private List<ComponentNodeResponse> path;
    private int pathLength;
}
