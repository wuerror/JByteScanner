package com.jbytescanner.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.jbytescanner.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.List;

public class SarifReporter {
    private static final Logger logger = LoggerFactory.getLogger(SarifReporter.class);
    private final File workspaceDir;

    public SarifReporter(File workspaceDir) {
        this.workspaceDir = workspaceDir;
    }

    public void generate(List<Vulnerability> vulnerabilities) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);

        ObjectNode root = mapper.createObjectNode();
        root.put("version", "2.1.0");
        root.put("$schema", "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json");

        ArrayNode runs = root.putArray("runs");
        ObjectNode run = runs.addObject();

        // Tool Info
        ObjectNode tool = run.putObject("tool");
        ObjectNode driver = tool.putObject("driver");
        driver.put("name", "JByteScanner");
        driver.put("version", "1.0");

        // Results
        ArrayNode results = run.putArray("results");

        for (Vulnerability v : vulnerabilities) {
            ObjectNode result = results.addObject();
            result.put("ruleId", v.getType());
            result.put("level", "error");
            
            ObjectNode message = result.putObject("message");
            message.put("text", String.format("Detected %s flow from %s to %s", 
                    v.getType(), v.getSourceMethod(), v.getSinkMethod()));

            // Locations (Simplified - pointing to Sink)
            ArrayNode locations = result.putArray("locations");
            ObjectNode location = locations.addObject();
            ObjectNode physicalLocation = location.putObject("physicalLocation");
            ObjectNode artifactLocation = physicalLocation.putObject("artifactLocation");
            artifactLocation.put("uri", v.getSinkMethod()); // Ideally file path, but we have method sig

            // Code Flow (Trace)
            ArrayNode codeFlows = result.putArray("codeFlows");
            ObjectNode codeFlow = codeFlows.addObject();
            ArrayNode threadFlows = codeFlow.putArray("threadFlows");
            ObjectNode threadFlow = threadFlows.addObject();
            ArrayNode locationsFlow = threadFlow.putArray("locations");

            for (String step : v.getTrace()) {
                ObjectNode loc = locationsFlow.addObject();
                ObjectNode stepLoc = loc.putObject("location");
                ObjectNode stepMsg = stepLoc.putObject("message");
                stepMsg.put("text", step);
            }
        }

        File outFile = new File(workspaceDir, "result.sarif");
        try {
            mapper.writeValue(outFile, root);
            logger.info("SARIF Report generated: {}", outFile.getAbsolutePath());
        } catch (IOException e) {
            logger.error("Failed to write SARIF report", e);
        }
    }
}
