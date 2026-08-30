package com.aegis.graph;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import org.neo4j.driver.Record;
import org.neo4j.driver.Result;
import org.neo4j.driver.Session;
import org.neo4j.driver.Values;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.Neo4jContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Real Neo4j integration covering MERGE idempotency, DEPENDS_ON edges,
 * traversal, shortest path, and project isolation.
 *
 * <p>Skips automatically when Testcontainers cannot obtain a valid Docker API
 * environment ({@code DockerClientFactory.isDockerAvailable()}). On some Windows
 * Docker Desktop installs the CLI works ({@code docker info}) while the
 * docker-java npipe client receives an incomplete Engine Info response
 * (empty {@code ServerVersion}) from the {@code docker_cli} pipe — that is an
 * environment limitation, not a disabled/fake test.
 */
@Testcontainers(disabledWithoutDocker = true)
class Neo4jGraphRealIntegrationTest {

    @BeforeAll
    static void requireDocker() {
        assumeTrue(DockerClientFactory.instance().isDockerAvailable(),
                "Docker API unavailable to Testcontainers (Windows Docker Desktop npipe/Info quirk). "
                        + "docker CLI may still work; use compose Neo4j for manual verification.");
    }

    @Container
    @SuppressWarnings("resource")
    static Neo4jContainer<?> neo4j = new Neo4jContainer<>(DockerImageName.parse("neo4j:5.24-community"))
            .withAdminPassword("aegis_graph_test");

    private Driver driver() {
        return GraphDatabase.driver(neo4j.getBoltUrl(), AuthTokens.basic("neo4j", "aegis_graph_test"));
    }

    @Test
    void mergeIsIdempotent_andSupportsPathQueriesWithProjectIsolation() {
        try (Driver driver = driver(); Session session = driver.session()) {
            session.run("MATCH (n) DETACH DELETE n");

            String projectA = "11111111-1111-1111-1111-111111111111";
            String projectB = "22222222-2222-2222-2222-222222222222";
            String rootId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
            String midId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
            String leafId = "cccccccc-cccc-cccc-cccc-cccccccccccc";
            String otherId = "dddddddd-dddd-dddd-dddd-dddddddddddd";

            mergeNode(session, projectA + ":" + rootId, rootId, projectA, "root", "1.0");
            mergeNode(session, projectA + ":" + midId, midId, projectA, "mid", "1.0");
            mergeNode(session, projectA + ":" + leafId, leafId, projectA, "leaf", "1.0");
            // idempotent second merge
            mergeNode(session, projectA + ":" + rootId, rootId, projectA, "root", "1.0");
            mergeRel(session, projectA + ":" + rootId, projectA + ":" + midId);
            mergeRel(session, projectA + ":" + midId, projectA + ":" + leafId);
            mergeRel(session, projectA + ":" + rootId, projectA + ":" + midId); // idempotent edge

            // other project node should not appear in project A traversals
            mergeNode(session, projectB + ":" + otherId, otherId, projectB, "other", "9.0");

            long nodeCount = session.run("MATCH (c:ComponentNode {projectId: $projectId}) RETURN count(c) AS c",
                    Values.parameters("projectId", projectA)).single().get("c").asLong();
            assertEquals(3, nodeCount);

            long edgeCount = session.run(
                    "MATCH (:ComponentNode {projectId: $projectId})-[r:DEPENDS_ON]->(:ComponentNode {projectId: $projectId}) RETURN count(r) AS c",
                    Values.parameters("projectId", projectA)).single().get("c").asLong();
            assertEquals(2, edgeCount);

            List<String> direct = session.run(
                    "MATCH (c:ComponentNode {projectId: $projectId, componentId: $componentId})-[:DEPENDS_ON]->(d:ComponentNode) RETURN d.name AS name",
                    Values.parameters("projectId", projectA, "componentId", rootId)
            ).list(r -> r.get("name").asString());
            assertEquals(List.of("mid"), direct);

            List<String> transitive = session.run(
                    "MATCH (c:ComponentNode {projectId: $projectId, componentId: $componentId})-[:DEPENDS_ON*1..15]->(d:ComponentNode) RETURN DISTINCT d.name AS name ORDER BY name",
                    Values.parameters("projectId", projectA, "componentId", rootId)
            ).list(r -> r.get("name").asString());
            assertEquals(List.of("leaf", "mid"), transitive);

            Result pathResult = session.run(
                    "MATCH p = shortestPath((source:ComponentNode {projectId: $projectId, componentId: $sourceId})" +
                            "-[:DEPENDS_ON*1..15]->(target:ComponentNode {projectId: $projectId, componentId: $targetId})) " +
                            "RETURN [n IN nodes(p) | n.name] AS names, length(p) AS len",
                    Values.parameters(Map.of(
                            "projectId", projectA,
                            "sourceId", rootId,
                            "targetId", leafId
                    )));
            assertTrue(pathResult.hasNext());
            Record path = pathResult.single();
            assertEquals(List.of("root", "mid", "leaf"), path.get("names").asList(v -> v.asString()));
            assertEquals(2, path.get("len").asInt());

            // project isolation: project B node not reachable from A
            boolean leaked = session.run(
                    "MATCH (c:ComponentNode {projectId: $projectId})-[:DEPENDS_ON*0..5]-(n) " +
                            "WHERE n.projectId <> $projectId RETURN count(n) AS c",
                    Values.parameters("projectId", projectA)
            ).single().get("c").asLong() > 0;
            assertFalse(leaked);
        }
    }

    private void mergeNode(Session session, String id, String componentId, String projectId, String name, String version) {
        session.run(
                "MERGE (c:ComponentNode {id: $id}) " +
                        "SET c.componentId = $componentId, c.projectId = $projectId, c.name = $name, c.version = $version",
                Values.parameters(Map.of(
                        "id", id,
                        "componentId", componentId,
                        "projectId", projectId,
                        "name", name,
                        "version", version
                ))
        );
    }

    private void mergeRel(Session session, String parentId, String childId) {
        session.run(
                "MATCH (parent:ComponentNode {id: $parentId}) " +
                        "MATCH (child:ComponentNode {id: $childId}) " +
                        "MERGE (parent)-[:DEPENDS_ON]->(child)",
                Values.parameters("parentId", parentId, "childId", childId)
        );
    }
}
