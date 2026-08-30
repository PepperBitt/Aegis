package com.aegis.gate.domain;

import com.aegis.auth.domain.User;
import com.aegis.project.domain.Project;
import com.aegis.risk.domain.RiskGrade;
import jakarta.persistence.*;
import lombok.*;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "gate_checks")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GateCheck {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "project_id", nullable = false)
    private Project project;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "requested_by")
    private User requestedBy;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private GateResult result;

    @Column(name = "failure_reasons", columnDefinition = "TEXT")
    private String failureReasons;

    @Column(name = "risk_score", precision = 5, scale = 2)
    private BigDecimal riskScore;

    @Enumerated(EnumType.STRING)
    @Column(name = "risk_grade", length = 5)
    private RiskGrade riskGrade;

    @Column(name = "policies_evaluated", nullable = false)
    @Builder.Default
    private int policiesEvaluated = 0;

    @Column(name = "policies_failed", nullable = false)
    @Builder.Default
    private int policiesFailed = 0;

    @Column(name = "metadata_json", columnDefinition = "TEXT")
    private String metadataJson;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = Instant.now();
        }
    }
}
