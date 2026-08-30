package com.aegis.graph.application;

import com.aegis.auth.domain.User;
import com.aegis.project.application.OrganizationService;
import com.aegis.project.domain.Project;
import com.aegis.project.infrastructure.ProjectRepository;
import com.aegis.graph.api.dto.ComponentNodeResponse;
import com.aegis.graph.api.dto.DependencyPathResponse;
import com.aegis.graph.domain.ComponentNode;
import com.aegis.sbom.domain.SbomComponent;
import com.aegis.sbom.domain.SbomDependency;
import com.aegis.sbom.domain.SbomDocument;
import com.aegis.sbom.infrastructure.SbomComponentRepository;
import com.aegis.sbom.infrastructure.SbomDependencyRepository;
import com.aegis.sbom.infrastructure.SbomDocumentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.neo4j.core.Neo4jClient;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class DependencyGraphService {

    private final SbomDocumentRepository sbomDocumentRepository;
    private final SbomComponentRepository sbomComponentRepository;
    private final SbomDependencyRepository sbomDependencyRepository;
    private final ProjectRepository projectRepository;
    private final OrganizationService organizationService;
    private final Neo4jClient neo4jClient;

    public void syncSbomToGraph(UUID sbomId) {
        try {
            Optional<SbomDocument> sbomOpt = sbomDocumentRepository.findById(sbomId);
            if (sbomOpt.isEmpty()) {
                log.warn("Cannot sync SBOM to Neo4j graph: SBOM not found {}", sbomId);
                return;
            }

            SbomDocument sbom = sbomOpt.get();
            Project project = sbom.getProject();
            String projectIdStr = project.getId().toString();
            String sbomIdStr = sbom.getId().toString();
            String ecosystem = project.getEcosystem() != null ? project.getEcosystem() : "GENERIC";

            List<SbomComponent> components = sbomComponentRepository.findBySbomId(sbomId);
            List<SbomDependency> dependencies = sbomDependencyRepository.findBySbomId(sbomId);

            // Replace project graph with this SBOM's nodes only (do not touch other projects)
            neo4jClient.query(
                    "MATCH (c:ComponentNode {projectId: $projectId}) " +
                    "WHERE c.sbomId IS NULL OR c.sbomId <> $sbomId " +
                    "DETACH DELETE c"
            )
            .bind(projectIdStr).to("projectId")
            .bind(sbomIdStr).to("sbomId")
            .run();

            // Clear prior relationships for this SBOM's nodes before re-MERGE (idempotent rebuild)
            neo4jClient.query(
                    "MATCH (c:ComponentNode {projectId: $projectId, sbomId: $sbomId})-[r:DEPENDS_ON]-() DELETE r"
            )
            .bind(projectIdStr).to("projectId")
            .bind(sbomIdStr).to("sbomId")
            .run();

            Map<UUID, String> componentGraphIdMap = new HashMap<>();

            for (SbomComponent comp : components) {
                String nodeGraphId = buildNodeId(projectIdStr, comp);
                componentGraphIdMap.put(comp.getId(), nodeGraphId);

                neo4jClient.query(
                        "MERGE (c:ComponentNode {id: $id}) " +
                        "SET c.componentId = $componentId, " +
                        "    c.projectId = $projectId, " +
                        "    c.sbomId = $sbomId, " +
                        "    c.name = $name, " +
                        "    c.version = $version, " +
                        "    c.purl = $purl, " +
                        "    c.cpe = $cpe, " +
                        "    c.groupName = $groupName, " +
                        "    c.ecosystem = $ecosystem"
                )
                .bind(nodeGraphId).to("id")
                .bind(comp.getId().toString()).to("componentId")
                .bind(projectIdStr).to("projectId")
                .bind(sbomIdStr).to("sbomId")
                .bind(comp.getName()).to("name")
                .bind(comp.getVersion() != null ? comp.getVersion() : "").to("version")
                .bind(comp.getPurl() != null ? comp.getPurl() : "").to("purl")
                .bind(comp.getCpe() != null ? comp.getCpe() : "").to("cpe")
                .bind(comp.getGroupName() != null ? comp.getGroupName() : "").to("groupName")
                .bind(ecosystem).to("ecosystem")
                .run();
            }

            for (SbomDependency dep : dependencies) {
                String parentGraphId = componentGraphIdMap.get(dep.getParentComponent().getId());
                String childGraphId = componentGraphIdMap.get(dep.getChildComponent().getId());

                if (parentGraphId != null && childGraphId != null && !parentGraphId.equals(childGraphId)) {
                    neo4jClient.query(
                            "MATCH (parent:ComponentNode {id: $parentId}) " +
                            "MATCH (child:ComponentNode {id: $childId}) " +
                            "MERGE (parent)-[:DEPENDS_ON]->(child)"
                    )
                    .bind(parentGraphId).to("parentId")
                    .bind(childGraphId).to("childId")
                    .run();
                }
            }

            log.info("Successfully synchronized SBOM {} ({} components, {} dependencies) to Neo4j graph",
                    sbomId, components.size(), dependencies.size());

        } catch (Exception e) {
            log.warn("Failed to synchronize SBOM {} to Neo4j graph: {}", sbomId, e.getMessage());
            // Graph sync failure is logged without failing/rolling back PostgreSQL transaction
        }
    }

    public List<ComponentNodeResponse> getDirectDependencies(User user, UUID projectId, UUID componentId) {
        verifyProjectAccess(user, projectId);
        return queryRelatedNodes(
                "MATCH (c:ComponentNode {projectId: $projectId, componentId: $componentId})-[:DEPENDS_ON]->(d:ComponentNode) RETURN d AS n",
                projectId, componentId, "Neo4j direct dependencies query failed");
    }

    public List<ComponentNodeResponse> getDirectDependents(User user, UUID projectId, UUID componentId) {
        verifyProjectAccess(user, projectId);
        return queryRelatedNodes(
                "MATCH (c:ComponentNode {projectId: $projectId, componentId: $componentId})<-[:DEPENDS_ON]-(p:ComponentNode) RETURN p AS n",
                projectId, componentId, "Neo4j direct dependents query failed");
    }

    public List<ComponentNodeResponse> getTransitiveDependencies(User user, UUID projectId, UUID componentId) {
        verifyProjectAccess(user, projectId);
        return queryRelatedNodes(
                "MATCH (c:ComponentNode {projectId: $projectId, componentId: $componentId})-[:DEPENDS_ON*1..15]->(d:ComponentNode) RETURN DISTINCT d AS n",
                projectId, componentId, "Neo4j transitive dependencies query failed");
    }

    public List<ComponentNodeResponse> getTransitiveDependents(User user, UUID projectId, UUID componentId) {
        verifyProjectAccess(user, projectId);
        return queryRelatedNodes(
                "MATCH (c:ComponentNode {projectId: $projectId, componentId: $componentId})<-[:DEPENDS_ON*1..15]-(p:ComponentNode) RETURN DISTINCT p AS n",
                projectId, componentId, "Neo4j transitive dependents query failed");
    }

    private List<ComponentNodeResponse> queryRelatedNodes(String cypher, UUID projectId, UUID componentId, String warnPrefix) {
        try {
            Collection<ComponentNode> nodes = neo4jClient.query(cypher)
                    .bind(projectId.toString()).to("projectId")
                    .bind(componentId.toString()).to("componentId")
                    .fetchAs(ComponentNode.class)
                    .mappedBy((typeSystem, record) -> mapNode(record.get("n").asNode()))
                    .all();
            if (nodes == null || nodes.isEmpty()) {
                return Collections.emptyList();
            }
            List<ComponentNodeResponse> responses = new ArrayList<>();
            for (ComponentNode node : nodes) {
                if (node != null) {
                    responses.add(mapToResponse(node));
                }
            }
            return responses;
        } catch (Exception e) {
            log.warn("{}: {}", warnPrefix, e.getMessage());
            return Collections.emptyList();
        }
    }

    private ComponentNode mapNode(org.neo4j.driver.types.Node node) {
        ComponentNode cn = new ComponentNode();
        cn.setId(node.get("id").asString(null));
        cn.setComponentId(node.get("componentId").asString(null));
        cn.setProjectId(node.get("projectId").asString(null));
        cn.setSbomId(node.get("sbomId").asString(null));
        cn.setName(node.get("name").asString(null));
        cn.setVersion(node.get("version").asString(null));
        cn.setPurl(node.get("purl").asString(null));
        cn.setCpe(node.get("cpe").asString(null));
        cn.setGroupName(node.get("groupName").asString(null));
        cn.setEcosystem(node.get("ecosystem").asString(null));
        return cn;
    }

    public DependencyPathResponse getDependencyPath(User user, UUID projectId, UUID sourceComponentId, UUID targetComponentId) {
        verifyProjectAccess(user, projectId);
        try {
            @SuppressWarnings("unchecked")
            Collection<List<ComponentNode>> pathResults = (Collection<List<ComponentNode>>) (Collection<?>) neo4jClient.query(
                    "MATCH p = shortestPath((source:ComponentNode {projectId: $projectId, componentId: $sourceId})-[:DEPENDS_ON*1..15]->(target:ComponentNode {projectId: $projectId, componentId: $targetId})) " +
                    "RETURN nodes(p) AS path"
            )
            .bind(projectId.toString()).to("projectId")
            .bind(sourceComponentId.toString()).to("sourceId")
            .bind(targetComponentId.toString()).to("targetId")
            .fetchAs(List.class)
            .mappedBy((typeSystem, record) -> {
                List<ComponentNode> resultList = new ArrayList<>();
                var pathValue = record.get("path");
                if (pathValue == null || pathValue.isNull()) {
                    return resultList;
                }
                pathValue.asList(nodeValue -> {
                    ComponentNode cn = mapNode(nodeValue.asNode());
                    resultList.add(cn);
                    return cn;
                });
                return resultList;
            })
            .all();

            List<ComponentNodeResponse> pathResponses = new ArrayList<>();
            if (!pathResults.isEmpty()) {
                List<ComponentNode> firstPath = pathResults.iterator().next();
                if (firstPath != null) {
                    for (ComponentNode node : firstPath) {
                        if (node != null) {
                            pathResponses.add(mapToResponse(node));
                        }
                    }
                }
            }

            int length = pathResponses.isEmpty() ? 0 : pathResponses.size() - 1;

            return DependencyPathResponse.builder()
                    .sourceComponentId(sourceComponentId)
                    .targetComponentId(targetComponentId)
                    .path(pathResponses)
                    .pathLength(length)
                    .build();

        } catch (Exception e) {
            log.warn("Neo4j shortest path query failed: {}", e.getMessage());
            return DependencyPathResponse.builder()
                    .sourceComponentId(sourceComponentId)
                    .targetComponentId(targetComponentId)
                    .path(Collections.emptyList())
                    .pathLength(0)
                    .build();
        }
    }

    private void verifyProjectAccess(User user, UUID projectId) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new IllegalArgumentException("Project not found"));
        organizationService.verifyMembership(project.getOrganization().getId(), user.getId());
    }

    private String buildNodeId(String projectId, SbomComponent comp) {
        return projectId + ":" + (comp.getId() != null ? comp.getId().toString() : comp.getName() + ":" + comp.getVersion());
    }

    private ComponentNodeResponse mapToResponse(ComponentNode node) {
        return ComponentNodeResponse.builder()
                .graphNodeId(node.getId())
                .componentId(node.getComponentId() != null ? UUID.fromString(node.getComponentId()) : null)
                .projectId(node.getProjectId() != null ? UUID.fromString(node.getProjectId()) : null)
                .sbomId(node.getSbomId() != null ? UUID.fromString(node.getSbomId()) : null)
                .name(node.getName())
                .version(node.getVersion())
                .purl(node.getPurl())
                .cpe(node.getCpe())
                .groupName(node.getGroupName())
                .ecosystem(node.getEcosystem())
                .build();
    }
}
