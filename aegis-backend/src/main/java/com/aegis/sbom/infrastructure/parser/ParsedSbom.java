package com.aegis.sbom.infrastructure.parser;

import com.aegis.sbom.domain.SbomFormat;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ParsedSbom {

    private SbomFormat format;
    private String name;
    private String version;
    private String specVersion;
    private String serialNumber;
    private String supplier;

    @Builder.Default
    private List<ParsedComponent> components = new ArrayList<>();

    @Builder.Default
    private List<ParsedDependency> dependencies = new ArrayList<>();
}
