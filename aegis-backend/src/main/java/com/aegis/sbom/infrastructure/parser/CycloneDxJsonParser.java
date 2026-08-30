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
public class CycloneDxJsonParser implements SbomParser {

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
            return root.has("bomFormat") && "CycloneDX".equalsIgnoreCase(root.get("bomFormat").asText());
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public ParsedSbom parse(byte[] contentBytes) {
        try {
            JsonNode root = objectMapper.readTree(contentBytes);
            if (!root.has("bomFormat") || !"CycloneDX".equalsIgnoreCase(root.get("bomFormat").asText())) {
                throw new IllegalArgumentException("Invalid CycloneDX document: missing or invalid 'bomFormat'");
            }

            String specVersion = root.has("specVersion") ? root.get("specVersion").asText() : null;
            String serialNumber = root.has("serialNumber") ? root.get("serialNumber").asText() : null;

            String name = "CycloneDX-SBOM";
            String version = "1.0";
            String supplier = null;

            if (root.has("metadata")) {
                JsonNode metadata = root.get("metadata");
                if (metadata.has("component")) {
                    JsonNode mainComp = metadata.get("component");
                    if (mainComp.has("name")) {
                        name = mainComp.get("name").asText();
                    }
                    if (mainComp.has("version")) {
                        version = mainComp.get("version").asText();
                    }
                }
                if (metadata.has("supplier") && metadata.get("supplier").has("name")) {
                    supplier = metadata.get("supplier").get("name").asText();
                }
            }

            List<ParsedComponent> components = new ArrayList<>();
            if (root.has("components") && root.get("components").isArray()) {
                for (JsonNode compNode : root.get("components")) {
                    ParsedComponent component = parseComponent(compNode);
                    if (component != null) {
                        components.add(component);
                    }
                }
            }

            List<ParsedDependency> dependencies = new ArrayList<>();
            if (root.has("dependencies") && root.get("dependencies").isArray()) {
                for (JsonNode depNode : root.get("dependencies")) {
                    if (depNode.has("ref") && depNode.has("dependsOn") && depNode.get("dependsOn").isArray()) {
                        String parentRef = depNode.get("ref").asText();
                        for (JsonNode childRefNode : depNode.get("dependsOn")) {
                            String childRef = childRefNode.asText();
                            dependencies.add(ParsedDependency.builder()
                                    .parentRef(parentRef)
                                    .childRef(childRef)
                                    .build());
                        }
                    }
                }
            }

            return ParsedSbom.builder()
                    .format(SbomFormat.CYCLONEDX)
                    .name(name)
                    .version(version)
                    .specVersion(specVersion)
                    .serialNumber(serialNumber)
                    .supplier(supplier)
                    .components(components)
                    .dependencies(dependencies)
                    .build();

        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to parse CycloneDX JSON document", e);
            throw new IllegalArgumentException("Malformed CycloneDX JSON document: " + e.getMessage(), e);
        }
    }

    private ParsedComponent parseComponent(JsonNode compNode) {
        if (!compNode.has("name")) {
            return null;
        }

        String name = compNode.get("name").asText();
        String version = compNode.has("version") ? compNode.get("version").asText() : null;
        String group = compNode.has("group") ? compNode.get("group").asText() : null;
        String purl = compNode.has("purl") ? compNode.get("purl").asText() : null;
        String cpe = compNode.has("cpe") ? compNode.get("cpe").asText() : null;
        String type = compNode.has("type") ? compNode.get("type").asText() : "library";
        String refId = compNode.has("bom-ref") ? compNode.get("bom-ref").asText() : (group != null ? group + ":" + name : name);
        String description = compNode.has("description") ? compNode.get("description").asText() : null;

        String supplier = null;
        if (compNode.has("supplier") && compNode.get("supplier").has("name")) {
            supplier = compNode.get("supplier").get("name").asText();
        }

        String licenseExpression = parseLicenses(compNode);
        String hashSha256 = null;
        String hashSha1 = null;
        String hashMd5 = null;

        if (compNode.has("hashes") && compNode.get("hashes").isArray()) {
            for (JsonNode hashNode : compNode.get("hashes")) {
                if (hashNode.has("alg") && hashNode.has("content")) {
                    String alg = hashNode.get("alg").asText();
                    String content = hashNode.get("content").asText();
                    if ("SHA-256".equalsIgnoreCase(alg)) {
                        hashSha256 = content;
                    } else if ("SHA-1".equalsIgnoreCase(alg)) {
                        hashSha1 = content;
                    } else if ("MD5".equalsIgnoreCase(alg)) {
                        hashMd5 = content;
                    }
                }
            }
        }

        return ParsedComponent.builder()
                .refId(refId)
                .name(name)
                .version(version)
                .groupName(group)
                .purl(purl)
                .cpe(cpe)
                .componentType(type)
                .supplier(supplier)
                .licenseExpression(licenseExpression)
                .hashSha256(hashSha256)
                .hashSha1(hashSha1)
                .hashMd5(hashMd5)
                .description(description)
                .build();
    }

    private String parseLicenses(JsonNode compNode) {
        if (!compNode.has("licenses") || !compNode.get("licenses").isArray()) {
            return null;
        }

        List<String> licenses = new ArrayList<>();
        for (JsonNode licNode : compNode.get("licenses")) {
            if (licNode.has("expression")) {
                licenses.add(licNode.get("expression").asText());
            } else if (licNode.has("license")) {
                JsonNode l = licNode.get("license");
                if (l.has("id")) {
                    licenses.add(l.get("id").asText());
                } else if (l.has("name")) {
                    licenses.add(l.get("name").asText());
                }
            }
        }
        return licenses.isEmpty() ? null : String.join(" AND ", licenses);
    }
}
