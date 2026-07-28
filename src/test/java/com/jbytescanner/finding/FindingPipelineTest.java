package com.jbytescanner.finding;

import com.jbytescanner.config.Config;
import com.jbytescanner.config.NoiseFilterConfig;
import com.jbytescanner.config.ScanConfig;
import com.jbytescanner.config.SinkRule;
import com.jbytescanner.engine.RuleManager;
import com.jbytescanner.model.ApiRoute;
import com.jbytescanner.model.Vulnerability;
import com.jbytescanner.worker.CapturedTaintFlow;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FindingPipelineTest {

    @Test
    void sameMethodTwoSinkStmtsRemainDistinctFindings() {
        SinkRule sql = sink("SQL_Injection", "sqli",
                "<java.sql.Statement: java.sql.ResultSet executeQuery(java.lang.String)>");
        RuleManager rm = manager(sql);
        ScanConfig sc = scanConfig(List.of("com.example"), true);

        CapturedTaintFlow a = flow(
                "<com.example.C: void h(java.lang.String)>",
                sql.getSignature(),
                "<com.example.Svc: void run(java.lang.String)>",
                10, null);
        CapturedTaintFlow b = flow(
                "<com.example.C: void h(java.lang.String)>",
                sql.getSignature(),
                "<com.example.Svc: void run(java.lang.String)>",
                25, null);

        PipelineResult r = new FindingPipeline(rm, sc, List.of()).process(List.of(a, b));
        int total = r.mainFindings.size() + r.lowConfidenceFindings.size();
        assertEquals(2, total, "sinkStmtIndex must split findings");
        assertTrue(r.mainFindings.stream().anyMatch(f -> f.sinkStmtIndex == 10)
                || r.lowConfidenceFindings.stream().anyMatch(f -> f.sinkStmtIndex == 10));
        assertTrue(r.mainFindings.stream().anyMatch(f -> f.sinkStmtIndex == 25)
                || r.lowConfidenceFindings.stream().anyMatch(f -> f.sinkStmtIndex == 25));
    }

    @Test
    void inAppConstructorWithoutSideEffectIsDemotedNotSuppressed() {
        SinkRule url = sink("SSRF", "ssrf",
                "<java.net.URL: void <init>(java.lang.String)>");
        RuleManager rm = manager(url);
        ScanConfig sc = scanConfig(List.of("com.example"), true);

        CapturedTaintFlow f = flow(
                "<com.example.C: void h(java.lang.String)>",
                url.getSignature(),
                "<com.example.Svc: void openLater(java.lang.String)>",
                3, null);

        PipelineResult r = new FindingPipeline(rm, sc, List.of()).process(List.of(f));
        assertEquals(0, r.suppressedFindings.size(), "in-app constructor must not hard-suppress");
        assertEquals(1, r.lowConfidenceFindings.size());
        assertTrue(r.lowConfidenceFindings.get(0).reasonCodes.stream()
                .anyMatch(x -> x.contains("IN_APP")));
    }

    @Test
    void methodNameOnlyDoesNotPrefixMatch() {
        assertEquals("get", FindingPipeline.methodNameOnly("java.lang.String get()"));
        assertEquals("getUser", FindingPipeline.methodNameOnly("getUser(java.lang.String)"));
        assertEquals("get", FindingPipeline.methodNameOnly("get"));
    }

    @Test
    void outsidePackageWeakConstructorIsSuppressed() {
        SinkRule url = sink("SSRF", "ssrf",
                "<java.net.URL: void <init>(java.lang.String)>");
        RuleManager rm = manager(url);
        ScanConfig sc = scanConfig(List.of("com.example"), true);

        CapturedTaintFlow f = flow(
                "<com.example.C: void h(java.lang.String)>",
                url.getSignature(),
                "<oracle.xml.parser.v2.XMLReader: void push(java.lang.String)>",
                3, null);

        PipelineResult r = new FindingPipeline(rm, sc, List.of()).process(List.of(f));
        assertEquals(0, r.mainFindings.size());
        assertEquals(1, r.suppressedFindings.size());
        assertTrue(r.suppressedFindings.get(0).reasonCodes.stream()
                .anyMatch(x -> x.contains("WEAK_SINK") || x.contains("LIBRARY")));
    }

    @Test
    void outsidePackageTerminalSqlIsNotHardDropped() {
        SinkRule sql = sink("SQL_Injection", "sqli",
                "<java.sql.Statement: java.sql.ResultSet executeQuery(java.lang.String)>");
        RuleManager rm = manager(sql);
        ScanConfig sc = scanConfig(List.of("com.example"), true);

        CapturedTaintFlow f = flow(
                "<com.example.C: void h(java.lang.String)>",
                sql.getSignature(),
                "<com.thirdparty.Lib: void query(java.lang.String)>",
                7, null);

        PipelineResult r = new FindingPipeline(rm, sc, List.of()).process(List.of(f));
        assertEquals(0, r.suppressedFindings.size(), "terminal must not be hard-dropped");
        assertEquals(1, r.mainFindings.size() + r.lowConfidenceFindings.size());
        assertTrue(r.mainFindings.size() + r.lowConfidenceFindings.size() >= 1);
    }

    @Test
    void velocityHighFanInNotCritical() {
        SinkRule vel = sink("Velocity_Injection", "code-exec",
                "<org.apache.velocity.app.Velocity: boolean evaluate("
                        + "org.apache.velocity.context.Context,java.io.Writer,"
                        + "java.lang.String,java.lang.String)>");
        vel.setIndex(3);
        RuleManager rm = manager(vel);
        ScanConfig sc = scanConfig(List.of("com.example"), true);

        List<CapturedTaintFlow> flows = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            CapturedTaintFlow f = flow(
                    "<com.example.C" + i + ": void h(java.lang.String)>",
                    vel.getSignature(),
                    "<com.example.util.VelocityUtils: void parse(java.lang.String)>",
                    1, null);
            f.sinkIndex = "3";
            flows.add(f);
        }

        PipelineResult r = new FindingPipeline(rm, sc, List.of()).process(flows);
        List<CanonicalFinding> all = new ArrayList<>();
        all.addAll(r.mainFindings);
        all.addAll(r.lowConfidenceFindings);
        assertFalse(all.isEmpty());
        for (CanonicalFinding c : all) {
            assertFalse("CRITICAL".equals(c.riskLevel),
                    "Velocity without path evidence must not be CRITICAL");
        }
        assertTrue(r.lowConfidenceFindings.size() >= 1
                || r.mainFindings.stream().noneMatch(f -> "CRITICAL".equals(f.riskLevel)));
    }

    @Test
    void urlWithLocalSideEffectStaysMain() {
        SinkRule url = sink("SSRF", "ssrf",
                "<java.net.URL: void <init>(java.lang.String)>");
        RuleManager rm = manager(url);
        ScanConfig sc = scanConfig(List.of("org.srm"), true);

        CapturedTaintFlow f = flow(
                "<org.srm.mobile.config.api.controller.v1.mall.MallCodeController: "
                        + "org.springframework.http.ResponseEntity getPictureBase64(java.lang.String)>",
                url.getSignature(),
                "<org.srm.mobile.config.app.service.mall.impl.MallCodeServiceImpl: "
                        + "java.lang.String getPictureBase64(java.lang.String)>",
                2, List.of("openStream"));

        PipelineResult r = new FindingPipeline(rm, sc, List.of(
                new ApiRoute("GET", "/v1/get-picture/base64",
                        "org.srm.mobile.config.api.controller.v1.mall.MallCodeController",
                        "org.springframework.http.ResponseEntity getPictureBase64(java.lang.String)")
        )).process(List.of(f));

        assertEquals(1, r.mainFindings.size());
        assertEquals(SinkStrength.TERMINAL_SIDE_EFFECT, r.mainFindings.get(0).sinkStrength);
        assertEquals(EvidenceLevel.LOCAL_SIDE_EFFECT, r.mainFindings.get(0).evidenceLevel);
    }

    @Test
    void fanInAggregatesSqlSourcesButKeepsAllInstances() {
        SinkRule sql = sink("SQL_Injection", "sqli",
                "<java.sql.Statement: java.sql.ResultSet executeQuery(java.lang.String)>");
        RuleManager rm = manager(sql);
        ScanConfig sc = scanConfig(List.of("com.example"), true);

        List<CapturedTaintFlow> flows = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            flows.add(flow(
                    "<com.example.C" + i + ": void h(java.lang.String)>",
                    sql.getSignature(),
                    "<com.example.JdbcQueryer: void run(java.lang.String)>",
                    5, null));
        }

        PipelineResult r = new FindingPipeline(rm, sc, List.of()).process(flows);
        List<CanonicalFinding> kept = new ArrayList<>();
        kept.addAll(r.mainFindings);
        kept.addAll(r.lowConfidenceFindings);
        assertEquals(1, kept.size());
        assertEquals(4, kept.get(0).sourceCount);
        assertEquals(4, kept.get(0).instances.size());
    }

    @Test
    void noiseFilterDisabledRestoresMainCount() {
        SinkRule url = sink("SSRF", "ssrf",
                "<java.net.URL: void <init>(java.lang.String)>");
        RuleManager rm = manager(url);
        ScanConfig sc = scanConfig(List.of("com.example"), false);

        CapturedTaintFlow f = flow(
                "<com.example.C: void h(java.lang.String)>",
                url.getSignature(),
                "<oracle.xml.parser.Foo: void x(java.lang.String)>",
                1, null);

        PipelineResult r = new FindingPipeline(rm, sc, List.of()).process(List.of(f));
        assertEquals(1, r.mainFindings.size());
        assertEquals(0, r.suppressedFindings.size());
    }

    @Test
    void groovyShellEvaluateIsTerminalAndMain() {
        SinkRule groovy = sink("Groovy_Injection", "code-exec",
                "<groovy.lang.GroovyShell: java.lang.Object evaluate(java.lang.String)>");
        RuleManager rm = manager(groovy);
        ScanConfig sc = scanConfig(List.of("com.example"), true);

        CapturedTaintFlow f = flow(
                "<com.example.C: void h(java.lang.String)>",
                groovy.getSignature(),
                "<com.example.Svc: void run(java.lang.String)>",
                3, null);

        PipelineResult r = new FindingPipeline(rm, sc, List.of(
                new ApiRoute("POST", "/run", "com.example.C",
                        "void h(java.lang.String)")
        )).process(List.of(f));

        assertEquals(1, r.mainFindings.size(), "script evaluate must stay in main SARIF");
        assertEquals(SinkStrength.TERMINAL_SIDE_EFFECT, r.mainFindings.get(0).sinkStrength);
        assertTrue(r.mainFindings.get(0).severityScore >= 7.0
                || "CRITICAL".equals(r.mainFindings.get(0).riskLevel)
                || "HIGH".equals(r.mainFindings.get(0).riskLevel));
    }

    @Test
    void templateEvaluateIsNotScriptTerminal() {
        assertTrue(SinkStrengthClassifier.isTemplateEvaluate(
                "<org.apache.velocity.app.velocity: boolean evaluate("
                        + "org.apache.velocity.context.context,java.io.writer,"
                        + "java.lang.string,java.lang.string)>"));
        assertFalse(SinkStrengthClassifier.isTemplateEvaluate(
                "<groovy.lang.groovyshell: java.lang.object evaluate(java.lang.string)>"));
        assertTrue(SinkStrengthClassifier.isScriptEval(
                "<groovy.lang.groovyshell: java.lang.object evaluate(java.lang.string)>"));
    }

    @Test
    void toVulnerabilityPreservesStmtIndex() {
        SinkRule sql = sink("SQL_Injection", "sqli",
                "<java.sql.Statement: java.sql.ResultSet executeQuery(java.lang.String)>");
        RuleManager rm = manager(sql);
        ScanConfig sc = scanConfig(List.of("com.example"), true);
        CapturedTaintFlow f = flow(
                "<com.example.C: void h(java.lang.String)>",
                sql.getSignature(),
                "<com.example.Svc: void q(java.lang.String)>",
                42, null);
        PipelineResult r = new FindingPipeline(rm, sc, List.of()).process(List.of(f));
        List<Vulnerability> vulns = FindingPipeline.toVulnerabilities(
                r.mainFindings.isEmpty() ? r.lowConfidenceFindings : r.mainFindings);
        assertEquals(1, vulns.size());
        assertEquals(42, vulns.get(0).getSinkStmtIndex());
    }

    private static ScanConfig scanConfig(List<String> packages, boolean noiseOn) {
        ScanConfig sc = new ScanConfig();
        sc.setScanPackages(new ArrayList<>(packages));
        sc.setFindingPackages(new ArrayList<>(packages));
        NoiseFilterConfig nf = new NoiseFilterConfig();
        nf.setEnabled(noiseOn);
        sc.setNoiseFilter(nf);
        return sc;
    }

    private static RuleManager manager(SinkRule... rules) {
        Config config = new Config();
        config.setSinks(List.of(rules));
        config.setScanConfig(new ScanConfig());
        return new RuleManager(config);
    }

    private static SinkRule sink(String vulnType, String category, String signature) {
        SinkRule rule = new SinkRule();
        rule.setType("method");
        rule.setVulnType(vulnType);
        rule.setCategory(category);
        rule.setSignature(signature);
        rule.setIndex(0);
        return rule;
    }

    private static CapturedTaintFlow flow(String source, String sinkRule,
                                          String container, int stmtIdx,
                                          List<String> sideEffects) {
        CapturedTaintFlow flow = new CapturedTaintFlow();
        flow.sourceContainerSignature = source;
        flow.sourceRuleSignature = source;
        flow.sourceKind = "ParamSourcePoint";
        flow.sourceIndex = "0";
        flow.sinkRuleSignature = sinkRule;
        flow.sinkIndex = "0";
        flow.sinkContainerSignature = container;
        flow.sinkStmtIndex = stmtIdx;
        flow.sinkLineNumber = 100 + stmtIdx;
        flow.invokeText = "invoke " + sinkRule;
        flow.localFollowingSideEffects = sideEffects;
        return flow;
    }
}
