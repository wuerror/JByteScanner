package com.jbytescanner.cli;

import com.jbytescanner.diagnose.QueryOptions;
import com.jbytescanner.diagnose.QueryOutcome;
import com.jbytescanner.diagnose.QueryService;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(name = "query", mixinStandardHelpOptions = true, version = "1.5.0",
        description = {
                "Read existing scan artifacts without launching Tai-e.",
                "Kinds: findings (default), finding, scan-status.",
                "JSON is written to stdout; logs and errors go to stderr.",
                "scan-status reports the actual worker-result status; finding queries "
                        + "do not gate on artifact freshness.",
                "Exit codes: 0 evidence returned, 2 usage/signature error, "
                        + "4 worker failed, 6 evidence unavailable (run targeted diagnose)."
        },
        footer = {
                "Examples:",
                "  jbytescanner query app/.jbytescanner findings --sink "
                        + "'<java.io.File: void <init>(java.lang.String)>' --json",
                "  jbytescanner query app/.jbytescanner scan-status --json"
        })
public class QueryCommand implements Callable<Integer> {

    @Parameters(index = "0", paramLabel = "<workspace>",
            description = "Project directory or .jbytescanner workspace")
    private Path workspace;

    @Parameters(index = "1", arity = "0..1", defaultValue = "findings",
            paramLabel = "<findings|finding|scan-status>",
            description = "Query kind (default: findings)")
    private String what;

    @Option(names = "--sink", paramLabel = "<Tai-e signature>",
            description = "Exact sink signature filter (required for 'finding')")
    private String sink;

    @Option(names = "--sink-index", paramLabel = "<N|base|result>",
            description = "Exact sink index filter")
    private String sinkIndex;

    @Option(names = "--source", paramLabel = "<Tai-e signature>",
            description = "Exact source-rule signature filter; matches finding instances, "
                    + "not just the sink")
    private String source;

    @Option(names = "--source-index", paramLabel = "<N|base|result>",
            description = "Exact source index filter applied to finding instances")
    private String sourceIndex;

    @Option(names = "--limit", defaultValue = "500",
            description = "Maximum findings returned (default: 500)")
    private int limit;

    @Option(names = "--json", description = "Emit JSON on stdout (JSON is already the default)")
    private boolean json;

    @Override
    public Integer call() {
        CliSupport.redirectLogsToStderr();
        java.io.PrintStream realOut = System.out;
        Object payload;
        int exitCode;
        try {
            System.setOut(System.err);
            if (workspace == null) {
                payload = CliSupport.errorPayload(CliSupport.EXIT_INPUT, "query",
                        "workspace is required");
                exitCode = CliSupport.EXIT_INPUT;
            } else {
                QueryOutcome outcome = new QueryService(workspace)
                        .query(new QueryOptions(what, sink, sinkIndex, source, sourceIndex,
                                limit));
                payload = outcome.result();
                exitCode = outcome.exitCode();
            }
        } catch (IllegalArgumentException e) {
            payload = CliSupport.errorPayload(CliSupport.EXIT_USAGE, "query", e.getMessage());
            exitCode = CliSupport.EXIT_USAGE;
        } catch (Exception e) {
            payload = CliSupport.errorPayload(CliSupport.EXIT_INPUT, "query",
                    e.getClass().getSimpleName() + ": " + e.getMessage());
            exitCode = CliSupport.EXIT_INPUT;
        } finally {
            System.setOut(realOut);
        }
        CliSupport.printJson(payload);
        return exitCode;
    }
}
