package com.aegis.shared.infrastructure.storage;

import io.minio.BucketExistsArgs;
import io.minio.MakeBucketArgs;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import io.minio.GetObjectArgs;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.MinIOContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Real MinIO integration tests. Skipped automatically when Docker is unavailable.
 */
@Testcontainers(disabledWithoutDocker = true)
class MinioStorageIT {

    private static final String BUCKET = "aegis-sboms";

    @BeforeAll
    static void requireDocker() {
        Assumptions.assumeTrue(
                DockerClientFactory.instance().isDockerAvailable(),
                "Docker is required for MinIO integration tests"
        );
    }

    @Container
    @SuppressWarnings("resource")
    static MinIOContainer minio = new MinIOContainer("minio/minio:RELEASE.2024-09-22T00-33-43Z")
            .withUserName("aegis_minio")
            .withPassword("test_minio_secret_key");

    @Test
    void uploadAndDownload_ShouldRoundTrip() throws Exception {
        MinioClient client = MinioClient.builder()
                .endpoint(minio.getS3URL())
                .credentials(minio.getUserName(), minio.getPassword())
                .build();

        boolean exists = client.bucketExists(BucketExistsArgs.builder().bucket(BUCKET).build());
        if (!exists) {
            client.makeBucket(MakeBucketArgs.builder().bucket(BUCKET).build());
        }

        byte[] payload = "{\"bomFormat\":\"CycloneDX\"}".getBytes(StandardCharsets.UTF_8);
        String objectKey = "projects/demo/sbom.json";

        client.putObject(PutObjectArgs.builder()
                .bucket(BUCKET)
                .object(objectKey)
                .stream(new ByteArrayInputStream(payload), payload.length, -1)
                .contentType("application/json")
                .build());

        try (var stream = client.getObject(GetObjectArgs.builder()
                .bucket(BUCKET)
                .object(objectKey)
                .build())) {
            byte[] downloaded = stream.readAllBytes();
            assertArrayEquals(payload, downloaded);
        }
    }
}
