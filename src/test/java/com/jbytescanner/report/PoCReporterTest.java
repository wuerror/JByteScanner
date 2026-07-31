package com.jbytescanner.report;

import com.jbytescanner.model.ApiRoute;
import com.jbytescanner.model.Vulnerability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PoCReporterTest {

    @TempDir
    Path tempDir;

    @Test
    void matchesRouteAndGeneratesWithoutWorld() throws Exception {
        ApiRoute route = new ApiRoute(
                "POST",
                "/v1/script-fake-tx-callback",
                "org.srm.boot.marmotscript.faketx.controller.FakeTxUniversalController",
                "org.springframework.http.ResponseEntity callback(org.srm.boot.marmotscript.iface.vo.FakeTxCallBackRequestVO)");
        route.setContentType("application/json");
        route.setParameters(List.of(
                "arg0:org.srm.boot.marmotscript.iface.vo.FakeTxCallBackRequestVO"));
        route.setParamAnnotations(Map.of("arg0", "RequestBody"));

        String source =
                "<org.srm.boot.marmotscript.faketx.controller.FakeTxUniversalController: "
                        + "org.springframework.http.ResponseEntity callback("
                        + "org.srm.boot.marmotscript.iface.vo.FakeTxCallBackRequestVO)>";
        assertNotNull(PoCReporter.findRoute(List.of(route), source));

        Vulnerability vuln = new Vulnerability(
                "Deserialization",
                source,
                "<com.fasterxml.jackson.databind.ObjectMapper: java.lang.Object readValue(java.lang.String,java.lang.Class)>",
                List.of(source),
                true,
                null);

        new PoCReporter(tempDir.toFile()).generate(List.of(vuln), List.of(route));
        String text = Files.readString(tempDir.resolve("generated_pocs.txt"));
        assertTrue(text.contains("POST /v1/script-fake-tx-callback"));
        assertTrue(text.contains("_typeHint"));
        assertTrue(text.contains("@type") || text.contains("payload"));
    }
}
