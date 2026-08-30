package com.aegis.shared.infrastructure.storage;

import io.minio.MinioClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class MinioConfig {

    @Value("${aegis.minio.endpoint:http://localhost:9000}")
    private String endpoint;

    @Value("${aegis.minio.access-key:aegis_minio}")
    private String accessKey;

    @Value("${aegis.minio.secret-key:}")
    private String secretKey;

    @Bean
    public MinioClient minioClient() {
        return MinioClient.builder()
                .endpoint(endpoint)
                .credentials(accessKey, secretKey)
                .build();
    }
}
