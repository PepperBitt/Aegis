package com.aegis.graph.infrastructure.neo4j.repository;

import com.aegis.graph.domain.ComponentNode;
import org.springframework.data.neo4j.repository.Neo4jRepository;
import org.springframework.data.neo4j.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ComponentNodeRepository extends Neo4jRepository<ComponentNode, String> {

    @Query("MATCH (c:ComponentNode {projectId: $projectId, componentId: $componentId})-[:DEPENDS_ON]->(d:ComponentNode) RETURN d")
    List<ComponentNode> findDirectDependencies(@Param("projectId") String projectId, @Param("componentId") String componentId);

    @Query("MATCH (c:ComponentNode {projectId: $projectId, componentId: $componentId})<-[:DEPENDS_ON]-(p:ComponentNode) RETURN p")
    List<ComponentNode> findDirectDependents(@Param("projectId") String projectId, @Param("componentId") String componentId);

    @Query("MATCH (c:ComponentNode {projectId: $projectId, componentId: $componentId})-[:DEPENDS_ON*1..15]->(d:ComponentNode) RETURN DISTINCT d")
    List<ComponentNode> findTransitiveDependencies(@Param("projectId") String projectId, @Param("componentId") String componentId);

    @Query("MATCH (c:ComponentNode {projectId: $projectId, componentId: $componentId})<-[:DEPENDS_ON*1..15]-(p:ComponentNode) RETURN DISTINCT p")
    List<ComponentNode> findTransitiveDependents(@Param("projectId") String projectId, @Param("componentId") String componentId);
}
