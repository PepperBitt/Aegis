package com.aegis.sbom.domain;

import com.aegis.auth.domain.User;
import com.aegis.project.domain.Project;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "sbom_documents")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SbomDocument {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "project_id", nullable = false)
    private Project project;

    @Column(nullable = false)
    private String name;

    @Column(length = 100)
    private String version;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private SbomFormat format;

    @Column(name = "spec_version", length = 20)
    private String specVersion;

    @Column(name = "serial_number")
    private String serialNumber;

    @Column
    private String supplier;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private SbomStatus status;

    @Column(name = "component_count", nullable = false)
    private int componentCount;

    @Column(name = "file_path", length = 500)
    private String filePath;

    @Column(name = "file_size_bytes")
    private Long fileSizeBytes;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by")
    private User createdBy;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
        if (this.format == null) {
            this.format = SbomFormat.CYCLONEDX;
        }
        if (this.status == null) {
            this.status = SbomStatus.PROCESSING;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = Instant.now();
    }
}
