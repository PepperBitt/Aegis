package com.aegis.graph.application;

import com.aegis.sbom.domain.event.SbomUploadedEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Slf4j
@Component
@Order(1)
@RequiredArgsConstructor
public class DependencyGraphEventListener {

    private final DependencyGraphService dependencyGraphService;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void handleSbomUploaded(SbomUploadedEvent event) {
        log.info("Handling SbomUploadedEvent AFTER_COMMIT for sbomId: {}", event.getSbomId());
        try {
            dependencyGraphService.syncSbomToGraph(event.getSbomId());
        } catch (Exception e) {
            log.error("Failed to sync SBOM {} to graph in event listener", event.getSbomId(), e);
        }
    }
}
