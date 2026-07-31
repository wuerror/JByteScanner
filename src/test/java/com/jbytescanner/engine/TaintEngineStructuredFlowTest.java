package com.jbytescanner.engine;

import com.jbytescanner.config.Config;
import com.jbytescanner.config.SinkRule;
import com.jbytescanner.model.Vulnerability;
import com.jbytescanner.worker.CapturedTaintFlow;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TaintEngineStructuredFlowTest {

    @Test
    void mapsInvokeInterfaceFlowsByExactConfiguredSinkSignature() {
        SinkRule logRule = sink(
                "Log_Injection", "log-injection", 2.0,
                "<org.slf4j.Logger: void info(java.lang.String)>");
        SinkRule sqlRule = sink(
                "SQL_Injection", "sqli", null,
                "<java.sql.Statement: int executeUpdate(java.lang.String)>");
        RuleManager manager = ruleManager(logRule, sqlRule);

        CapturedTaintFlow logFlow = flow(
                "<example.Controller: void log(java.lang.String)>",
                logRule.getSignature(),
                "invokeinterface %v2.info(msg)");
        CapturedTaintFlow sqlFlow = flow(
                "<example.Controller: void query(java.lang.String)>",
                sqlRule.getSignature(),
                "invokeinterface ps.executeUpdate(nowSql)");

        List<Vulnerability> vulnerabilities = TaintEngine.convertCapturedFlows(
                List.of(logFlow, sqlFlow), manager);

        assertEquals(2, vulnerabilities.size());
        assertEquals("Log_Injection", vulnerabilities.get(0).getType());
        assertEquals(logRule.getSignature(), vulnerabilities.get(0).getSinkMethod());
        assertEquals(2.0, vulnerabilities.get(0).getSinkRule().getBaseScore());

        assertEquals("SQL_Injection", vulnerabilities.get(1).getType());
        assertEquals(sqlRule.getSignature(), vulnerabilities.get(1).getSinkMethod());
        assertEquals(8.0, vulnerabilities.get(1).getSinkRule().getBaseScore());
    }

    @Test
    void distinguishesSameNamedParseSinksWithoutMethodNameInference() {
        SinkRule groovy = sink(
                "Script_Engine_Injection", "code-exec", null,
                "<groovy.lang.GroovyShell: groovy.lang.Script parse(java.lang.String)>");
        SinkRule xml = sink(
                "XXE", "xxe", null,
                "<javax.xml.parsers.DocumentBuilder: org.w3c.dom.Document parse(java.io.InputStream)>");
        RuleManager manager = ruleManager(groovy, xml);

        CapturedTaintFlow flow = flow(
                "<example.Controller: void run(java.lang.String)>",
                groovy.getSignature(),
                "$r2 = invokevirtual $r1.parse(scriptText)");

        Vulnerability vulnerability = TaintEngine.convertCapturedFlows(
                List.of(flow), manager).get(0);

        assertEquals("Script_Engine_Injection", vulnerability.getType());
        assertEquals(groovy.getSignature(), vulnerability.getSinkMethod());
    }

    @Test
    void refusesUnmappedStructuredSinkInsteadOfEmittingUnknown() {
        RuleManager manager = ruleManager();
        CapturedTaintFlow flow = flow(
                "<example.Controller: void run(java.lang.String)>",
                "<example.MissingSink: void consume(java.lang.String)>",
                "invokeinterface sink.consume(value)");

        IllegalStateException error = assertThrows(
                IllegalStateException.class,
                () -> TaintEngine.convertCapturedFlows(List.of(flow), manager));

        assertNotNull(error.getMessage());
        assertTrue(error.getMessage().contains("MissingSink"));
    }

    private static RuleManager ruleManager(SinkRule... rules) {
        Config config = new Config();
        config.setSinks(List.of(rules));
        return new RuleManager(config);
    }

    private static SinkRule sink(String vulnType, String category,
                                 Double severity, String signature) {
        SinkRule rule = new SinkRule();
        rule.setType("method");
        rule.setVulnType(vulnType);
        rule.setCategory(category);
        rule.setSeverity(severity);
        rule.setSignature(signature);
        rule.setIndex(0);
        return rule;
    }

    private static CapturedTaintFlow flow(String source, String sinkRuleSignature,
                                          String invokeText) {
        CapturedTaintFlow flow = new CapturedTaintFlow();
        flow.sourceContainerSignature = source;
        flow.sourceRuleSignature = source;
        flow.sourceKind = "ParamSourcePoint";
        flow.sourceIndex = "0";
        flow.sinkRuleSignature = sinkRuleSignature;
        flow.sinkIndex = "0";
        flow.sinkContainerSignature = source;
        flow.sinkStmtIndex = 1;
        flow.sinkLineNumber = 10;
        flow.invokeText = invokeText;
        return flow;
    }
}
