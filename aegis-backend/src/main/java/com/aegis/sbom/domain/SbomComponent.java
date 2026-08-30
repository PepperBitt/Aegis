package com.aegis.sbom.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "sbom_components")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SbomComponent {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "sbom_id", nullable = false)
    private SbomDocument sbom;

    @Column(nullable = false, length = 500)
    private String name;

    @Column(length = 200)
    private String version;

    @Column(length = 1000)
    private String purl;

    @Column(length = 500)
    private String cpe;

    @Column(name = "component_type", length = 100)
    private String componentType;

    @Column(name = "group_name")
    private String groupName;

    @Column
    private String supplier;

    @Column(name = "license_expression", length = 500)
    private String licenseExpression;

    @Column(name = "hash_sha256", length = 64)
    private String hashSha256;

    @Column(name = "hash_sha1", length = 40)
    private String hashSha1;

    @Column(name = "hash_md5", length = 32)
    private String hashMd5;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = Instant.now();
        if (this.componentType == null) {
            this.componentType = "LIBRARY";
        }
    }
}
