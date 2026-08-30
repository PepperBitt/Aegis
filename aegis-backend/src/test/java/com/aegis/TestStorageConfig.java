package com.aegis;

import com.aegis.shared.infrastructure.storage.StorageService;
import org.mockito.Mockito;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Provides a working StorageService stub so SBOM integration tests do not require MinIO.
 * Production uses the real {@link StorageService} which fails hard when MinIO is unavailable.
 */
@Configuration
@Profile("test")
public class TestStorageConfig {

    @Bean
    @Primary
    public StorageService storageService() {
        StorageService storageService = Mockito.mock(StorageService.class);
        when(storageService.storeSbomFile(any(), any())).thenAnswer(invocation ->
                "sboms/test-" + UUID.randomUUID() + ".json");
        return storageService;
    }
}
