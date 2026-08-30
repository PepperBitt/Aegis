package com.aegis.sbom.infrastructure.parser;

import com.aegis.sbom.domain.SbomFormat;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.*;

class SpdxJsonParserTest {

    private SpdxJsonParser parser;

    @BeforeEach
    void setUp() {
        parser = new SpdxJsonParser(new ObjectMapper());
    }

    @Test
    void supports_ShouldReturnTrue_ForValidSpdxJson() throws Exception {
        try (InputStream is = getClass().getResourceAsStream("/sample-spdx.json")) {
            byte[] bytes = is.readAllBytes();
            assertTrue(parser.supports(bytes));
        }
    }

    @Test
    void parse_ShouldExtractMetadataPackagesAndDependencies() throws Exception {
        try (InputStream is = getClass().getResourceAsStream("/sample-spdx.json")) {
            byte[] bytes = is.readAllBytes();
            ParsedSbom sbom = parser.parse(bytes);

            assertNotNull(sbom);
            assertEquals(SbomFormat.SPDX, sbom.getFormat());
            assertEquals("AEGIS SPDX Sample", sbom.getName());
            assertEquals("SPDX-2.3", sbom.getSpecVersion());
            assertEquals("AEGIS Team", sbom.getSupplier());

            assertEquals(2, sbom.getComponents().size());
            ParsedComponent pkg1 = sbom.getComponents().get(0);
            assertEquals("commons-lang3", pkg1.getName());
            assertEquals("3.14.0", pkg1.getVersion());
            assertEquals("Apache-2.0", pkg1.getLicenseExpression());
            assertEquals("pkg:maven/org.apache.commons/commons-lang3@3.14.0", pkg1.getPurl());

            assertEquals(1, sbom.getDependencies().size());
            assertEquals("SPDXRef-Package-commons-lang3", sbom.getDependencies().get(0).getParentRef());
            assertEquals("SPDXRef-Package-commons-io", sbom.getDependencies().get(0).getChildRef());
        }
    }

    @Test
    void parse_ShouldThrowIllegalArgumentException_ForMalformedJson() {
        assertThrows(IllegalArgumentException.class, () -> parser.parse("invalid json".getBytes()));
    }
}
