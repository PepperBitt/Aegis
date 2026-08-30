package com.aegis.shared.infrastructure.storage;

import com.aegis.shared.exception.StorageException;
import io.minio.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class StorageService {

    private final MinioClient minioClient;

    @Value("${aegis.minio.bucket-name:aegis-sboms}")
    private String bucketName;

    /**
     * Stores raw SBOM bytes in MinIO.
     * Failures are not swallowed — callers must treat storage as required for successful ingestion.
     */
    public String storeSbomFile(byte[] contentBytes, String originalFilename) {
        String safeName = (originalFilename == null || originalFilename.isBlank()) ? "sbom.json" : originalFilename;
        // Prevent path traversal in object key metadata; object key itself is UUID-based
        if (safeName.contains("..") || safeName.contains("/") || safeName.contains("\\")) {
            safeName = "sbom.json";
        }
        String objectKey = "sboms/" + UUID.randomUUID() + ".json";
        try {
            ensureBucketExists();
            minioClient.putObject(
                    PutObjectArgs.builder()
                            .bucket(bucketName)
                            .object(objectKey)
                            .stream(new ByteArrayInputStream(contentBytes), contentBytes.length, -1)
                            .contentType("application/json")
                            .build()
            );
            log.info("Successfully stored SBOM file in MinIO: {}", objectKey);
            return objectKey;
        } catch (StorageException e) {
            throw e;
        } catch (Exception e) {
            log.error("MinIO storage failed for SBOM upload (objectKey={}): {}", objectKey, e.getMessage());
            throw new StorageException("Failed to store SBOM in object storage", e);
        }
    }

    public InputStream downloadSbomFile(String objectKey) {
        try {
            return minioClient.getObject(
                    GetObjectArgs.builder()
                            .bucket(bucketName)
                            .object(objectKey)
                            .build()
            );
        } catch (Exception e) {
            log.error("Failed to download SBOM file from MinIO: {}", objectKey);
            throw new StorageException("Could not download file from storage", e);
        }
    }

    private void ensureBucketExists() {
        try {
            boolean found = minioClient.bucketExists(
                    BucketExistsArgs.builder().bucket(bucketName).build()
            );
            if (!found) {
                minioClient.makeBucket(
                        MakeBucketArgs.builder().bucket(bucketName).build()
                );
                log.info("Created MinIO bucket: {}", bucketName);
            }
        } catch (Exception e) {
            throw new StorageException("Could not access or create MinIO bucket: " + bucketName, e);
        }
    }
}
