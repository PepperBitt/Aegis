package com.aegis.project.domain;

import com.aegis.auth.domain.User;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "org_members")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrgMember {

    @EmbeddedId
    private OrgMemberId id;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("orgId")
    @JoinColumn(name = "org_id", nullable = false)
    private Organization organization;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("userId")
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private OrgRole role;

    @Column(name = "joined_at", nullable = false, updatable = false)
    private Instant joinedAt;

    @PrePersist
    protected void onCreate() {
        this.joinedAt = Instant.now();
        if (this.role == null) {
            this.role = OrgRole.MEMBER;
        }
    }
}
