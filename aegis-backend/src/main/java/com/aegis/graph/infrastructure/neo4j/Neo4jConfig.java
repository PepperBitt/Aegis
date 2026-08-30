package com.aegis.graph.infrastructure.neo4j;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.neo4j.repository.config.EnableNeo4jRepositories;

@Configuration
@ConditionalOnProperty(name = "spring.neo4j.enabled", havingValue = "true", matchIfMissing = true)
@EnableNeo4jRepositories(basePackages = "com.aegis.graph.infrastructure.neo4j.repository")
public class Neo4jConfig {
}
