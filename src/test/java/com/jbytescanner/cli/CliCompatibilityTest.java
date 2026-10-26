package com.jbytescanner.cli;

import com.jbytescanner.JByteScanner;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CliCompatibilityTest {

    @Test
    void legacyTargetModeInvocationsStillParse() throws Exception {
        CommandLine root = new CommandLine(new JByteScanner());
        root.parseArgs("/tmp/app.jar", "-m", "api");
        assertEquals("api", field(root.getCommand(), "mode"));

        CommandLine root2 = new CommandLine(new JByteScanner());
        root2.parseArgs("-m", "scan", "/tmp/app.jar");
        assertEquals("scan", field(root2.getCommand(), "mode"));
    }

    @Test
    void diagnoseAndQuerySubcommandsAreRegistered() {
        CommandLine root = new CommandLine(new JByteScanner());
        assertNotNull(root.getSubcommands().get("diagnose"));
        assertNotNull(root.getSubcommands().get("query"));
    }

    @Test
    void diagnoseHelpDocumentsExactSignatureAndExitCodes() {
        String usage = new CommandLine(new DiagnoseCommand()).getUsageMessage();
        assertTrue(usage.contains("--sink"));
        assertTrue(usage.contains("--source"));
        assertTrue(usage.contains("Exit codes"));
        assertTrue(usage.contains("4 worker failure"));
        assertFalse(usage.contains("5 stale"));
    }

    @Test
    void queryHelpDocumentsOfflineKinds() {
        String usage = new CommandLine(new QueryCommand()).getUsageMessage();
        assertTrue(usage.contains("scan-status"));
        assertTrue(usage.contains("findings"));
        assertTrue(usage.contains("Exit codes"));
        assertTrue(usage.contains("worker-result status"));
        assertFalse(usage.contains("5 stale/unverified"));
    }

    private String field(Object target, String name) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return (String) field.get(target);
    }
}
