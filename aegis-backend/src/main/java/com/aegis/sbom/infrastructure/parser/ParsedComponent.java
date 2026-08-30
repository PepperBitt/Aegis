package com.aegis.sbom.infrastructure.parser;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ParsedComponent {

    private String refId; // bom-ref or SPDXID for dependency mapping
    private String name;
    private String version;
    private String purl;
    private String cpe;
    private String componentType;
    private String groupName;
    private String supplier;
    private String licenseExpression;
    private String hashSha256;
    private String hashSha1;
    private String hashMd5;
    private String description;
}
