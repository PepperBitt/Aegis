package com.aegis.sbom.infrastructure.parser;

public interface SbomParser {
    boolean supports(byte[] contentBytes);
    ParsedSbom parse(byte[] contentBytes);
}
