package com.aegis.project.api.dto;

import com.aegis.project.domain.OrgRole;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MemberResponse {

    private UUID userId;
    private String email;
    private String fullName;
    private OrgRole role;
    private Instant joinedAt;
}
