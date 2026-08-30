package com.aegis.graph;

import com.aegis.graph.infrastructure.neo4j.repository.ComponentNodeRepository;
import org.mockito.Answers;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.neo4j.core.Neo4jClient;

@Configuration
@ConditionalOnProperty(name = "spring.neo4j.enabled", havingValue = "false")
public class TestNeo4jConfig {

    @Bean
    public Neo4jClient neo4jClient() {
        Neo4jClient client = Mockito.mock(Neo4jClient.class, Answers.RETURNS_DEEP_STUBS);
        // Avoid Mockito deep-stub stream().collect() returning null in graph query helpers
        Mockito.when(client.query(Mockito.anyString())
                        .bind(Mockito.any()).to(Mockito.anyString())
                        .bind(Mockito.any()).to(Mockito.anyString())
                        .fetchAs(Mockito.<Class<?>>any())
                        .mappedBy(Mockito.any())
                        .all())
                .thenReturn(java.util.Collections.emptyList());
        Mockito.when(client.query(Mockito.anyString())
                        .bind(Mockito.any()).to(Mockito.anyString())
                        .bind(Mockito.any()).to(Mockito.anyString())
                        .bind(Mockito.any()).to(Mockito.anyString())
                        .fetchAs(Mockito.<Class<?>>any())
                        .mappedBy(Mockito.any())
                        .all())
                .thenReturn(java.util.Collections.emptyList());
        return client;
    }

    @Bean
    public ComponentNodeRepository componentNodeRepository() {
        return Mockito.mock(ComponentNodeRepository.class);
    }
}
