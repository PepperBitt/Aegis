package com.aegis.sbom.infrastructure.parser;

import com.aegis.sbom.domain.SbomFormat;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.*;

class CycloneDxJsonParserTest {

    private CycloneDxJsonParser parser;

    @BeforeEach
    void setUp() {
        parser = new CycloneDxJsonParser(new ObjectMapper());
    }

    @Test
    void supports_ShouldReturnTrue_ForValidCycloneDxJson() throws Exception {
        try (InputStream is = getClass().getResourceAsStream("/sample-cyclonedx.json")) {
            byte[] bytes = is.readAllBytes();
            assertTrue(parser.supports(bytes));
        }
    }

    @Test
    void supports_ShouldReturnFalse_ForNonCycloneDxContent() {
        assertFalse(parser.supports("{\"foo\": \"bar\"}".getBytes()));
        assertFalse(parser.supports("not json".getBytes()));
    }

    @Test
    void parse_ShouldExtractMetadataComponentsAndDependencies() throws Exception {
        try (InputStream is = getClass().getResourceAsStream("/sample-cyclonedx.json")) {
            byte[] bytes = is.readAllBytes();
            ParsedSbom sbom = parser.parse(bytes);

            assertNotNull(sbom);
            assertEquals(SbomFormat.CYCLONEDX, sbom.getFormat());
            assertEquals("aegis-backend", sbom.getName());
            assertEquals("1.0.0", sbom.getVersion());
            assertEquals("1.4", sbom.getSpecVersion());
            assertEquals("AEGIS Security", sbom.getSupplier());

            assertEquals(2, sbom.getComponents().size());
            ParsedComponent c1 = sbom.getComponents().get(0);
            assertEquals("spring-boot-starter-web", c1.getName());
            assertEquals("3.3.5", c1.getVersion());
            assertEquals("org.springframework.boot", c1.getGroupName());
            assertEquals("Apache-2.0", c1.getLicenseExpression());
            assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", c1.getHashSha256());

            assertEquals(1, sbom.getDependencies().size());
            assertEquals("pkg:maven/org.springframework.boot/spring-boot-starter-web@3.3.5?type=jar", sbom.getDependencies().get(0).getParentRef());
            assertEquals("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.0?type=jar", sbom.getDependencies().get(0).getChildRef());
        }
    }

    @Test
    void parse_ShouldThrowIllegalArgumentException_ForMalformedJson() {
        assertThrows(IllegalArgumentException.class, () -> parser.parse("{malformed: json}".getBytes()));
    }
}
