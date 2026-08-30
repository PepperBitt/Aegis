package com.aegis.graph.application;

import com.aegis.sbom.domain.SbomFormat;
import com.aegis.sbom.domain.event.SbomUploadedEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.UUID;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class DependencyGraphEventListenerTest {

    @Mock
    private DependencyGraphService dependencyGraphService;

    @InjectMocks
    private DependencyGraphEventListener eventListener;

    @Test
    void handleSbomUploaded_ShouldDelegateToService() {
        UUID sbomId = UUID.randomUUID();
        UUID projectId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();

        SbomUploadedEvent event = new SbomUploadedEvent(
                this, sbomId, projectId, SbomFormat.CYCLONEDX, 5, Instant.now(), userId
        );

        eventListener.handleSbomUploaded(event);

        verify(dependencyGraphService, times(1)).syncSbomToGraph(sbomId);
    }
}
