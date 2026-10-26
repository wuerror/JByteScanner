package com.jbytescanner.cli;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.ConsoleAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.layout.PatternLayout;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

public final class CliSupport {

    public static final int EXIT_USAGE = 2;
    public static final int EXIT_INPUT = 3;

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    private CliSupport() {
    }

    /**
     * Targeted CLI commands must not pollute JSON stdout. Tai-e's logging binding
     * defaults to a stdout console appender; move existing console appenders to
     * stderr for this process only. Ordinary scan commands never call this.
     */
    public static void redirectLogsToStderr() {
        try {
            LoggerContext context = (LoggerContext) LogManager.getContext(false);
            Configuration configuration = context.getConfiguration();
            for (LoggerConfig logger : new ArrayList<>(configuration.getLoggers().values())) {
                for (String name : new ArrayList<>(logger.getAppenders().keySet())) {
                    logger.removeAppender(name);
                }
            }
            for (String name : new ArrayList<>(logger(configuration).getAppenders().keySet())) {
                logger(configuration).removeAppender(name);
            }
            ConsoleAppender stderr = ConsoleAppender.newBuilder()
                    .setName("JBS_STDERR")
                    .setTarget(ConsoleAppender.Target.SYSTEM_ERR)
                    .setLayout(PatternLayout.newBuilder()
                            .withPattern("%d{HH:mm:ss.SSS} [%t] %-5level %logger - %msg%n")
                            .build())
                    .build();
            stderr.start();
            configuration.addAppender(stderr);
            configuration.getRootLogger().addAppender(stderr, Level.INFO, null);
            context.updateLoggers();
        } catch (Throwable e) {
            // If the logging backend is unavailable, fall back to the caller's
            // System.setOut(System.err) guard.
            System.err.println("[WARN] could not redirect logging to stderr: " + e);
        }
    }

    private static LoggerConfig logger(Configuration configuration) {
        return configuration.getRootLogger();
    }

    public static void printJson(Object value) {
        try {
            System.out.println(MAPPER.writeValueAsString(value));
        } catch (Exception e) {
            System.err.println("[ERROR] failed to serialize JSON: " + e);
        }
    }

    public static void printError(int exitCode, String command, String error) {
        printJson(errorPayload(exitCode, command, error));
    }

    public static Map<String, Object> errorPayload(int exitCode, String command, String error) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("schemaVersion", "jbs-cli-error/v1");
        payload.put("command", command);
        payload.put("exitCode", exitCode);
        payload.put("error", error == null ? "unknown error" : error);
        return payload;
    }

    public static void log(String message) {
        if (message != null && !message.isBlank()) {
            System.err.println(message);
        }
    }

    @SuppressWarnings("unused")
    private static void usage(PrintWriter writer) {
        // Kept for symmetry with Picocli help writers.
    }
}
