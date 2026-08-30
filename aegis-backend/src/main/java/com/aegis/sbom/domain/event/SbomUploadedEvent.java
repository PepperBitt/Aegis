package com.aegis.sbom.domain.event;

import com.aegis.sbom.domain.SbomFormat;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.time.Instant;
import java.util.UUID;

@Getter
public class SbomUploadedEvent extends ApplicationEvent {

    private final UUID sbomId;
    private final UUID projectId;
    private final SbomFormat format;
    private final int componentCount;
    private final Instant uploadedAt;
    private final UUID uploadedByUserId;

    public SbomUploadedEvent(Object source, UUID sbomId, UUID projectId, SbomFormat format, int componentCount, Instant uploadedAt, UUID uploadedByUserId) {
        super(source);
        this.sbomId = sbomId;
        this.projectId = projectId;
        this.format = format;
        this.componentCount = componentCount;
        this.uploadedAt = uploadedAt;
        this.uploadedByUserId = uploadedByUserId;
    }
}
