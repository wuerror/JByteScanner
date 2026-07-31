package com.jbytescanner.finding;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jbytescanner.config.Config;
import com.jbytescanner.config.ConfigManager;
import com.jbytescanner.config.ScanConfig;
import com.jbytescanner.engine.RuleManager;
import com.jbytescanner.model.ApiRoute;
import com.jbytescanner.model.Vulnerability;
import com.jbytescanner.report.SarifReporter;
import com.jbytescanner.worker.CapturedTaintFlow;
import com.jbytescanner.worker.TaieWorkerResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Offline P0.6 replay: read worker-result.json + workspace rules/api.txt,
 * run FindingPipeline without PTA.
 */
public final class OfflinePipelineReplay {

    private static final Logger logger = LoggerFactory.getLogger(OfflinePipelineReplay.class);

    private OfflinePipelineReplay() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: OfflinePipelineReplay <worker-result.json> <workspaceDir>");
            System.exit(2);
        }
        Path workerResult = Path.of(args[0]);
        File workspace = new File(args[1]);

        ObjectMapper mapper = new ObjectMapper();
        TaieWorkerResult wr = mapper.readValue(workerResult.toFile(), TaieWorkerResult.class);
        List<CapturedTaintFlow> flows = wr.taintFlows != null ? wr.taintFlows : List.of();

        ConfigManager cm = new ConfigManager();
        cm.init(workspace);
        Config config = cm.getConfig();
        RuleManager ruleManager = new RuleManager(config);
        ScanConfig scanConfig = config.getScanConfig() != null
                ? config.getScanConfig() : new ScanConfig();

        List<ApiRoute> routes = loadApiRoutes(new File(workspace, "api.txt"));
        logger.info("Loaded {} route(s) from api.txt for offline scoring", routes.size());

        FindingPipeline pipeline = new FindingPipeline(ruleManager, scanConfig, routes);
        PipelineResult result = pipeline.process(flows);
        FindingSidecarWriter.write(workspace, result, scanConfig.getNoiseFilter(), flows);

        int maxInst = scanConfig.getNoiseFilter().getMaxInstancesInSarif();
        List<Vulnerability> main = FindingPipeline.toVulnerabilities(result.mainFindings, maxInst);
        new SarifReporter(workspace).generate(main);

        System.out.printf("raw=%d main=%d low=%d suppressed=%d routes=%d%n",
                result.flowsRaw, result.mainFindings.size(),
                result.lowConfidenceFindings.size(), result.suppressedFindings.size(),
                routes.size());
        System.out.println(result.toBenchmarkMap());
    }

    static List<ApiRoute> loadApiRoutes(File apiFile) {
        List<ApiRoute> routes = new ArrayList<>();
        if (apiFile == null || !apiFile.isFile()) {
            return routes;
        }
        try {
            for (String line : Files.readAllLines(apiFile.toPath(), StandardCharsets.UTF_8)) {
                if (line.startsWith("#") || line.trim().isEmpty()) {
                    continue;
                }
                String baseLine = line;
                if (line.contains(" | {")) {
                    baseLine = line.substring(0, line.indexOf(" | {"));
                }
                String[] parts = baseLine.split(" ", 4);
                if (parts.length >= 4) {
                    routes.add(new ApiRoute(parts[0], parts[1], parts[2], parts[3]));
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to load api.txt: {}", e.toString());
        }
        return routes;
    }
}
