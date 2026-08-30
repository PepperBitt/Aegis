package com.aegis.graph.domain;

import lombok.*;
import org.springframework.data.neo4j.core.schema.Id;
import org.springframework.data.neo4j.core.schema.Node;
import org.springframework.data.neo4j.core.schema.Property;
import org.springframework.data.neo4j.core.schema.Relationship;

import java.util.HashSet;
import java.util.Set;

@Node("ComponentNode")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ComponentNode {

    @Id
    private String id; // Project-scoped id: projectId:name:version or projectId:componentId

    @Property("componentId")
    private String componentId; // PostgreSQL component UUID

    @Property("projectId")
    private String projectId; // PostgreSQL project UUID

    @Property("sbomId")
    private String sbomId; // PostgreSQL sbom UUID

    @Property("name")
    private String name;

    @Property("version")
    private String version;

    @Property("purl")
    private String purl;

    @Property("cpe")
    private String cpe;

    @Property("groupName")
    private String groupName;

    @Property("ecosystem")
    private String ecosystem;

    @Builder.Default
    @Relationship(type = "DEPENDS_ON", direction = Relationship.Direction.OUTGOING)
    private Set<ComponentNode> dependencies = new HashSet<>();
}
