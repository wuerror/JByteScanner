package com.jbytescanner.cli;

import com.jbytescanner.config.ConfigManager;
import com.jbytescanner.config.ResourceBudget;
import com.jbytescanner.config.ScanConfig;
import com.jbytescanner.core.ClasspathPlanner;
import com.jbytescanner.core.JarLoader;
import com.jbytescanner.diagnose.DiagnosisOptions;
import com.jbytescanner.diagnose.DiagnosisOutcome;
import com.jbytescanner.diagnose.DiagnosisService;
import com.jbytescanner.diagnose.DiagnosisWorker;
import com.jbytescanner.diagnose.PreparedDiagnosisContext;
import com.jbytescanner.diagnose.TaiEMethodSignature;
import com.jbytescanner.engine.TaintEngine;
import com.jbytescanner.model.ApiRoute;
import com.jbytescanner.worker.TaieWorkerLauncher;
import com.jbytescanner.worker.TaieWorkerMain;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "diagnose", mixinStandardHelpOptions = true, version = "1.5.0",
        description = {
                "Run a targeted, bounded diagnosis for one exact Tai-e sink signature.",
                "JSON is written to stdout; logs and errors go to stderr.",
                "Exit codes: 0 diagnosis completed, 2 usage/signature error, "
                        + "3 input/artifact error, 4 worker failure."
        },
        footer = {
                "Example:",
                "  jbytescanner diagnose app.jar --sink "
                        + "'<java.io.File: void <init>(java.lang.String)>' --json",
                "The sink signature must include owner, return type, method name, and "
                        + "parameter types. Overloads are matched exactly. When --source is "
                        + "set, raw flows and finding placements are restricted to that source "
                        + "rule/container/index."
        })
public class DiagnoseCommand implements Callable<Integer> {

    @Parameters(index = "0", paramLabel = "<deployment-package>",
            description = "Target directory, JAR, or WAR to diagnose")
    private String targetPath;

    @Option(names = "--sink", required = true, paramLabel = "<Tai-e signature>",
            description = "Exact Tai-e sink signature: <owner: returnType name(paramTypes)>")
    private String sink;

    @Option(names = "--sink-index", paramLabel = "<N|base|result>",
            description = "Sensitive index to require; defaults to every configured index")
    private String sinkIndex;

    @Option(names = "--source", paramLabel = "<Tai-e signature>",
            description = "Optional exact source-rule signature; restricts flows and finding "
                    + "placements to this source")
    private String source;

    @Option(names = "--source-index", paramLabel = "<N|base|result>",
            description = "Optional source index; the finding instance must match the same "
                    + "source rule/container and index")
    private String sourceIndex;

    @Option(names = "--max-callers", defaultValue = "200",
            description = "Maximum caller sites included in invocation evidence (default: 200)")
    private int maxCallers;

    @Option(names = "--max-target-invokes", defaultValue = "200",
            description = "Maximum target invoke facts collected by the worker (default: 200)")
    private int maxTargetInvokes;

    @Option(names = "--worker", negatable = true, defaultValue = "true",
            description = "Run Tai-e in an isolated worker JVM (default: true)")
    private boolean worker = true;

    @Option(names = "--max-heap-mb", description = "Worker JVM -Xmx in megabytes")
    private Integer maxHeapMb;

    @Option(names = "--timeout-minutes", description = "Worker wall-clock timeout in minutes")
    private Integer timeoutMinutes;

    @Option(names = "--json", description = "Emit JSON on stdout (JSON is already the default)")
    private boolean json;

    @Override
    public Integer call() {
        // Tai-e's logging binding writes to System.out by default. Machine-readable
        // command output must be the only thing on stdout, so route logs to stderr
        // while the analysis runs and restore stdout for the final JSON document.
        CliSupport.redirectLogsToStderr();
        java.io.PrintStream realOut = System.out;
        Object payload;
        int exitCode;
        try {
            System.setOut(System.err);
            TaiEMethodSignature.parse(sink);
            if (source != null) {
                TaiEMethodSignature.parse(source);
            }
            File target = new File(targetPath);
            if (!target.exists()) {
                throw new java.io.IOException("target does not exist: " + targetPath);
            }
            File projectRoot = target.isDirectory() ? target : target.getParentFile();
            if (projectRoot == null) {
                projectRoot = new File(".");
            }
            File workspaceDir = new File(projectRoot, ".jbytescanner");
            if (!workspaceDir.exists() && !workspaceDir.mkdirs()) {
                throw new java.io.IOException("cannot create workspace: " + workspaceDir);
            }

            ConfigManager configManager = new ConfigManager();
            configManager.init(workspaceDir);
            ResourceBudget budget = applyBudget(configManager);

            JarLoader jarLoader = new JarLoader();
            List<String> scanPackages = configManager.getConfig().getScanConfig().getScanPackages();
            JarLoader.LoadedJars loadedJars = jarLoader.loadJars(targetPath, scanPackages);
            if (scanPackages == null || scanPackages.isEmpty()) {
                List<String> initial = new ArrayList<>(loadedJars.targetAppJars);
                initial.addAll(loadedJars.depAppJars);
                String inferred = jarLoader.inferBasePackage(initial);
                if (inferred != null) {
                    configManager.updateScanPackage(inferred);
                    scanPackages = configManager.getConfig().getScanConfig().getScanPackages();
                    loadedJars = jarLoader.loadJars(targetPath, scanPackages);
                }
            }
            ClasspathPlanner.PlanResult plan =
                    new ClasspathPlanner().plan(loadedJars, scanPackages, workspaceDir, false);
            loadedJars = plan.jars;

            File apiFile = new File(workspaceDir, "api.txt");
            List<ApiRoute> routes = apiFile.isFile()
                    ? TaintEngine.loadEntryPoints(apiFile) : List.of();

            PreparedDiagnosisContext context = new PreparedDiagnosisContext(
                    targetPath,
                    workspaceDir.toPath(),
                    loadedJars.targetAppJars,
                    loadedJars.depAppJars,
                    loadedJars.libJars,
                    configManager,
                    routes,
                    apiFile.toPath(),
                    budget
            );
            DiagnosisWorker workerRunner = (request, workerDir) -> {
                if (budget.isWorkerEnabled()) {
                    return new TaieWorkerLauncher(budget).run(request, workerDir);
                }
                return TaieWorkerMain.runForHost(request);
            };
            DiagnosisOutcome outcome = new DiagnosisService(context, workerRunner)
                    .diagnose(new DiagnosisOptions(sink, sinkIndex, source, sourceIndex,
                            maxCallers, maxTargetInvokes, true));
            payload = outcome.result();
            exitCode = outcome.exitCode();
        } catch (IllegalArgumentException e) {
            payload = CliSupport.errorPayload(CliSupport.EXIT_USAGE, "diagnose",
                    e.getMessage());
            exitCode = CliSupport.EXIT_USAGE;
        } catch (Exception e) {
            payload = CliSupport.errorPayload(CliSupport.EXIT_INPUT, "diagnose",
                    e.getClass().getSimpleName() + ": " + e.getMessage());
            exitCode = CliSupport.EXIT_INPUT;
        } finally {
            System.setOut(realOut);
        }
        CliSupport.printJson(payload);
        return exitCode;
    }

    private ResourceBudget applyBudget(ConfigManager configManager) {
        ScanConfig scanConfig = configManager.getConfig().getScanConfig();
        ResourceBudget budget = scanConfig.getResourceBudget();
        budget.setWorkerEnabled(worker);
        if (maxHeapMb != null && maxHeapMb > 0) {
            budget.setMaxHeapMb(maxHeapMb);
        }
        if (timeoutMinutes != null && timeoutMinutes >= 0) {
            budget.setTimeoutMinutes(timeoutMinutes);
        }
        return budget;
    }
}
