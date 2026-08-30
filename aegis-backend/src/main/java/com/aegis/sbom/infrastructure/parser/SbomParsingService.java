package com.aegis.sbom.infrastructure.parser;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class SbomParsingService {

    private final List<SbomParser> parsers;

    public ParsedSbom parse(byte[] contentBytes) {
        if (contentBytes == null || contentBytes.length == 0) {
            throw new IllegalArgumentException("Uploaded file is empty");
        }

        for (SbomParser parser : parsers) {
            if (parser.supports(contentBytes)) {
                return parser.parse(contentBytes);
            }
        }

        throw new IllegalArgumentException("Unsupported or malformed SBOM format. Only CycloneDX JSON and SPDX JSON formats are currently supported.");
    }
}
