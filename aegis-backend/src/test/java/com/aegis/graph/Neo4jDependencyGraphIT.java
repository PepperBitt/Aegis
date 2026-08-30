package com.aegis.graph;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import org.neo4j.driver.Session;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.Neo4jContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Real Neo4j integration tests. Skipped automatically when Docker is unavailable.
 */
@Testcontainers(disabledWithoutDocker = true)
class Neo4jDependencyGraphIT {

    @BeforeAll
    static void requireDocker() {
        Assumptions.assumeTrue(
                DockerClientFactory.instance().isDockerAvailable(),
                "Docker is required for Neo4j integration tests"
        );
    }

    @Container
    @SuppressWarnings("resource")
    static Neo4jContainer<?> neo4j = new Neo4jContainer<>(DockerImageName.parse("neo4j:5.24-community"))
            .withAdminPassword("aegis_test");

    @Test
    void mergeNodesAndRelationships_ShouldSupportTraversalAndShortestPath() {
        try (Driver driver = GraphDatabase.driver(
                neo4j.getBoltUrl(),
                AuthTokens.basic("neo4j", "aegis_test")
        ); Session session = driver.session()) {

            String projectId = "project-1";
            String a = projectId + ":comp-a";
            String b = projectId + ":comp-b";
            String c = projectId + ":comp-c";

            session.run("""
                    MERGE (n:ComponentNode {id: $id})
                    SET n.componentId = $componentId, n.projectId = $projectId, n.name = $name
                    """, Map.of("id", a, "componentId", "comp-a", "projectId", projectId, "name", "A"));
            session.run("""
                    MERGE (n:ComponentNode {id: $id})
                    SET n.componentId = $componentId, n.projectId = $projectId, n.name = $name
                    """, Map.of("id", b, "componentId", "comp-b", "projectId", projectId, "name", "B"));
            session.run("""
                    MERGE (n:ComponentNode {id: $id})
                    SET n.componentId = $componentId, n.projectId = $projectId, n.name = $name
                    """, Map.of("id", c, "componentId", "comp-c", "projectId", projectId, "name", "C"));

            session.run("""
                    MATCH (parent:ComponentNode {id: $parentId})
                    MATCH (child:ComponentNode {id: $childId})
                    MERGE (parent)-[:DEPENDS_ON]->(child)
                    """, Map.of("parentId", a, "childId", b));
            session.run("""
                    MATCH (parent:ComponentNode {id: $parentId})
                    MATCH (child:ComponentNode {id: $childId})
                    MERGE (parent)-[:DEPENDS_ON]->(child)
                    """, Map.of("parentId", b, "childId", c));

            // Idempotent MERGE
            session.run("""
                    MATCH (parent:ComponentNode {id: $parentId})
                    MATCH (child:ComponentNode {id: $childId})
                    MERGE (parent)-[:DEPENDS_ON]->(child)
                    """, Map.of("parentId", a, "childId", b));

            Long nodeCount = session.run(
                    "MATCH (n:ComponentNode {projectId: $projectId}) RETURN count(n) AS cnt",
                    Map.of("projectId", projectId)
            ).single().get("cnt").asLong();
            assertEquals(3L, nodeCount);

            Long relCount = session.run(
                    "MATCH (:ComponentNode {projectId: $projectId})-[r:DEPENDS_ON]->(:ComponentNode) RETURN count(r) AS cnt",
                    Map.of("projectId", projectId)
            ).single().get("cnt").asLong();
            assertEquals(2L, relCount);

            List<String> directDeps = session.run("""
                    MATCH (c:ComponentNode {projectId: $projectId, componentId: $componentId})-[:DEPENDS_ON]->(d)
                    RETURN d.componentId AS id
                    """, Map.of("projectId", projectId, "componentId", "comp-a"))
                    .list(r -> r.get("id").asString());
            assertEquals(List.of("comp-b"), directDeps);

            List<String> transitive = session.run("""
                    MATCH (c:ComponentNode {projectId: $projectId, componentId: $componentId})-[:DEPENDS_ON*1..15]->(d)
                    RETURN DISTINCT d.componentId AS id ORDER BY id
                    """, Map.of("projectId", projectId, "componentId", "comp-a"))
                    .list(r -> r.get("id").asString());
            assertEquals(List.of("comp-b", "comp-c"), transitive);

            List<String> path = session.run("""
                    MATCH p = shortestPath((s:ComponentNode {projectId: $projectId, componentId: $source})
                        -[:DEPENDS_ON*1..15]->(t:ComponentNode {projectId: $projectId, componentId: $target}))
                    RETURN [n IN nodes(p) | n.componentId] AS path
                    """, Map.of("projectId", projectId, "source", "comp-a", "target", "comp-c"))
                    .single().get("path").asList(v -> v.asString());
            assertEquals(List.of("comp-a", "comp-b", "comp-c"), path);

            // Project isolation: other project untouched
            Long otherProject = session.run("""
                    MATCH (n:ComponentNode {projectId: $projectId}) RETURN count(n) AS cnt
                    """, Map.of("projectId", "other-project")).single().get("cnt").asLong();
            assertEquals(0L, otherProject);

            // Stale prune: sync a second "SBOM" for same project should remove prior sbom nodes
            String sbom2 = "sbom-2";
            session.run("""
                    MATCH (c:ComponentNode {projectId: $projectId})
                    WHERE c.sbomId IS NULL OR c.sbomId <> $sbomId
                    DETACH DELETE c
                    """, Map.of("projectId", projectId, "sbomId", sbom2));
            session.run("""
                    MERGE (n:ComponentNode {id: $id})
                    SET n.componentId = $componentId, n.projectId = $projectId, n.sbomId = $sbomId, n.name = $name
                    """, Map.of("id", projectId + ":comp-z", "componentId", "comp-z",
                    "projectId", projectId, "sbomId", sbom2, "name", "Z"));

            Long afterPrune = session.run(
                    "MATCH (n:ComponentNode {projectId: $projectId}) RETURN count(n) AS cnt",
                    Map.of("projectId", projectId)
            ).single().get("cnt").asLong();
            assertEquals(1L, afterPrune);

            String remainingSbom = session.run(
                    "MATCH (n:ComponentNode {projectId: $projectId}) RETURN n.sbomId AS sbomId",
                    Map.of("projectId", projectId)
            ).single().get("sbomId").asString();
            assertEquals(sbom2, remainingSbom);
        }
    }
}
