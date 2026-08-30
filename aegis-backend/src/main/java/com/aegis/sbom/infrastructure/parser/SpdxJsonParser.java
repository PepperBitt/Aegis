package com.aegis.sbom.infrastructure.parser;

import com.aegis.sbom.domain.SbomFormat;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class SpdxJsonParser implements SbomParser {

    private final ObjectMapper objectMapper;

    @Override
    public boolean supports(byte[] contentBytes) {
        if (contentBytes == null || contentBytes.length == 0) {
            return false;
        }
        try {
            String text = new String(contentBytes, StandardCharsets.UTF_8);
            if (!text.trim().startsWith("{")) {
                return false;
            }
            JsonNode root = objectMapper.readTree(contentBytes);
            return root.has("spdxVersion") && root.get("spdxVersion").asText().startsWith("SPDX-");
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public ParsedSbom parse(byte[] contentBytes) {
        try {
            JsonNode root = objectMapper.readTree(contentBytes);
            if (!root.has("spdxVersion") || !root.get("spdxVersion").asText().startsWith("SPDX-")) {
                throw new IllegalArgumentException("Invalid SPDX document: missing or invalid 'spdxVersion'");
            }

            String specVersion = root.get("spdxVersion").asText();
            String name = root.has("name") ? root.get("name").asText() : "SPDX-SBOM";
            String documentNamespace = root.has("documentNamespace") ? root.get("documentNamespace").asText() : null;

            String supplier = null;
            if (root.has("creationInfo") && root.get("creationInfo").has("creators") && root.get("creationInfo").get("creators").isArray()) {
                for (JsonNode creatorNode : root.get("creationInfo").get("creators")) {
                    String creatorStr = creatorNode.asText();
                    if (creatorStr.startsWith("Organization:") || creatorStr.startsWith("Person:")) {
                        supplier = creatorStr.substring(creatorStr.indexOf(":") + 1).trim();
                        break;
                    }
                }
            }

            List<ParsedComponent> components = new ArrayList<>();
            if (root.has("packages") && root.get("packages").isArray()) {
                for (JsonNode pkgNode : root.get("packages")) {
                    ParsedComponent component = parsePackage(pkgNode);
                    if (component != null) {
                        components.add(component);
                    }
                }
            }

            List<ParsedDependency> dependencies = new ArrayList<>();
            if (root.has("relationships") && root.get("relationships").isArray()) {
                for (JsonNode relNode : root.get("relationships")) {
                    if (relNode.has("spdxElementId") && relNode.has("relatedSpdxElement") && relNode.has("relationshipType")) {
                        String relType = relNode.get("relationshipType").asText();
                        String elem1 = relNode.get("spdxElementId").asText();
                        String elem2 = relNode.get("relatedSpdxElement").asText();

                        if ("DEPENDS_ON".equalsIgnoreCase(relType) || "DEPENDENCY_OF".equalsIgnoreCase(relType) || "CONTAINS".equalsIgnoreCase(relType)) {
                            dependencies.add(ParsedDependency.builder()
                                    .parentRef("DEPENDENCY_OF".equalsIgnoreCase(relType) ? elem2 : elem1)
                                    .childRef("DEPENDENCY_OF".equalsIgnoreCase(relType) ? elem1 : elem2)
                                    .build());
                        }
                    }
                }
            }

            return ParsedSbom.builder()
                    .format(SbomFormat.SPDX)
                    .name(name)
                    .version("1.0")
                    .specVersion(specVersion)
                    .serialNumber(documentNamespace)
                    .supplier(supplier)
                    .components(components)
                    .dependencies(dependencies)
                    .build();

        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to parse SPDX JSON document", e);
            throw new IllegalArgumentException("Malformed SPDX JSON document: " + e.getMessage(), e);
        }
    }

    private ParsedComponent parsePackage(JsonNode pkgNode) {
        if (!pkgNode.has("name")) {
            return null;
        }

        String name = pkgNode.get("name").asText();
        String refId = pkgNode.has("SPDXID") ? pkgNode.get("SPDXID").asText() : name;
        String version = pkgNode.has("versionInfo") ? pkgNode.get("versionInfo").asText() : null;
        String description = pkgNode.has("description") ? pkgNode.get("description").asText() : (pkgNode.has("summary") ? pkgNode.get("summary").asText() : null);

        String supplier = null;
        if (pkgNode.has("supplier")) {
            supplier = pkgNode.get("supplier").asText();
        } else if (pkgNode.has("originator")) {
            supplier = pkgNode.get("originator").asText();
        }

        String licenseConcluded = pkgNode.has("licenseConcluded") ? pkgNode.get("licenseConcluded").asText() : null;
        String licenseDeclared = pkgNode.has("licenseDeclared") ? pkgNode.get("licenseDeclared").asText() : null;
        String license = (licenseConcluded != null && !"NOASSERTION".equalsIgnoreCase(licenseConcluded)) ? licenseConcluded : licenseDeclared;
        if ("NOASSERTION".equalsIgnoreCase(license)) {
            license = null;
        }

        String purl = null;
        String cpe = null;

        if (pkgNode.has("externalRefs") && pkgNode.get("externalRefs").isArray()) {
            for (JsonNode refNode : pkgNode.get("externalRefs")) {
                if (refNode.has("referenceType") && refNode.has("referenceLocator")) {
                    String refType = refNode.get("referenceType").asText();
                    String locator = refNode.get("referenceLocator").asText();
                    if ("purl".equalsIgnoreCase(refType)) {
                        purl = locator;
                    } else if (refType.toLowerCase().contains("cpe")) {
                        cpe = locator;
                    }
                }
            }
        }

        String hashSha256 = null;
        String hashSha1 = null;
        String hashMd5 = null;

        if (pkgNode.has("checksums") && pkgNode.get("checksums").isArray()) {
            for (JsonNode csNode : pkgNode.get("checksums")) {
                if (csNode.has("algorithm") && csNode.has("checksumValue")) {
                    String alg = csNode.get("algorithm").asText();
                    String val = csNode.get("checksumValue").asText();
                    if ("SHA256".equalsIgnoreCase(alg)) {
                        hashSha256 = val;
                    } else if ("SHA1".equalsIgnoreCase(alg)) {
                        hashSha1 = val;
                    } else if ("MD5".equalsIgnoreCase(alg)) {
                        hashMd5 = val;
                    }
                }
            }
        }

        return ParsedComponent.builder()
                .refId(refId)
                .name(name)
                .version(version)
                .purl(purl)
                .cpe(cpe)
                .componentType("library")
                .supplier(supplier)
                .licenseExpression(license)
                .hashSha256(hashSha256)
                .hashSha1(hashSha1)
                .hashMd5(hashMd5)
                .description(description)
                .build();
    }
}
