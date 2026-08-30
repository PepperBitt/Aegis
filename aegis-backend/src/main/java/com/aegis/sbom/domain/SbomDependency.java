package com.aegis.sbom.domain;

import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

@Entity
@Table(name = "sbom_dependencies")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SbomDependency {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "sbom_id", nullable = false)
    private SbomDocument sbom;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_component_id", nullable = false)
    private SbomComponent parentComponent;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "child_component_id", nullable = false)
    private SbomComponent childComponent;
}
