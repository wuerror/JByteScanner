package com.jbytescanner.finding;

import com.jbytescanner.config.SinkRule;

import java.util.Locale;
import java.util.Set;

/**
 * Maps configured sinks / signatures to P0.6 strength classes.
 */
public final class SinkStrengthClassifier {

    private static final Set<String> TERMINAL_CATEGORIES = Set.of(
            "code-exec", "cmd-exec", "jndi", "jdbc", "sqli",
            "file-write", "file-read", "xxe", "deserialization"
    );

    private static final Set<String> TERMINAL_VULN = Set.of(
            "rce", "sql_injection", "sqli", "command_injection",
            "script_engine_injection", "groovy_injection", "ognl_injection",
            "spel_injection", "mvel_injection", "reflection_rce",
            "xxe", "jndi_injection"
    );

    private SinkStrengthClassifier() {
    }

    public static SinkStrength classify(SinkRule rule, String sinkRuleSignature,
                                        boolean hasLocalSideEffect) {
        String sig = sinkRuleSignature != null ? sinkRuleSignature : "";
        String lower = sig.toLowerCase(Locale.ROOT);

        // 1) Constructors / path factories (optionally upgraded by local side effect)
        if (isConstructor(lower) || isPathGet(lower)) {
            if (hasLocalSideEffect) {
                return SinkStrength.TERMINAL_SIDE_EFFECT;
            }
            return SinkStrength.CONSTRUCTOR;
        }

        // 2) Terminal side effects BEFORE template heuristics (script engines use evaluate())
        if (isNetworkSideEffect(lower) || isSqlExecute(lower) || isCmdExec(lower)
                || isScriptEval(lower) || isFileSideEffect(lower)) {
            return SinkStrength.TERMINAL_SIDE_EFFECT;
        }

        // 3) Rule category / vuln_type terminal (script RCE, etc.)
        if (rule != null) {
            String cat = rule.getCategory() != null
                    ? rule.getCategory().toLowerCase(Locale.ROOT).trim() : "";
            String vuln = rule.getVulnType() != null
                    ? rule.getVulnType().toLowerCase(Locale.ROOT).trim() : "";
            if (TERMINAL_CATEGORIES.contains(cat) && !"ssrf".equals(cat)
                    && !isTemplateVuln(vuln)) {
                return SinkStrength.TERMINAL_SIDE_EFFECT;
            }
            if (TERMINAL_VULN.contains(vuln) || isScriptVuln(vuln)) {
                return SinkStrength.TERMINAL_SIDE_EFFECT;
            }
        }

        // 4) Weak JSON parsers
        if (isPlainJsonParse(lower) || isJacksonReadValue(lower)) {
            return SinkStrength.PARSER;
        }

        // 5) Template engines only by package / explicit template vuln type
        if (isTemplateEvaluate(lower)
                || (rule != null && isTemplateVuln(
                rule.getVulnType() != null
                        ? rule.getVulnType().toLowerCase(Locale.ROOT) : ""))) {
            return SinkStrength.INTERMEDIATE;
        }

        if (rule != null) {
            String cat = rule.getCategory() != null
                    ? rule.getCategory().toLowerCase(Locale.ROOT).trim() : "";
            String vuln = rule.getVulnType() != null
                    ? rule.getVulnType().toLowerCase(Locale.ROOT).trim() : "";
            if ("ssrf".equals(cat) || vuln.contains("ssrf") || vuln.contains("path")) {
                if (isConstructor(lower) || isPathGet(lower)) {
                    return hasLocalSideEffect
                            ? SinkStrength.TERMINAL_SIDE_EFFECT
                            : SinkStrength.CONSTRUCTOR;
                }
            }
            if (vuln.contains("fastjson") || vuln.contains("jackson")
                    || vuln.contains("deserialization")) {
                if (isPlainJsonParse(lower) || isJacksonReadValue(lower)) {
                    return SinkStrength.PARSER;
                }
            }
        }

        return SinkStrength.UNCLASSIFIED;
    }

    public static boolean isConstructor(String lowerSig) {
        return lowerSig.contains(": void <init>(")
                && (lowerSig.contains("java.net.url")
                || lowerSig.contains("java.net.uri")
                || lowerSig.contains("java.io.file"));
    }

    public static boolean isPathGet(String lowerSig) {
        return lowerSig.contains("java.nio.file.paths")
                && lowerSig.contains(" get(");
    }

    public static boolean isPlainJsonParse(String lowerSig) {
        return (lowerSig.contains("com.alibaba.fastjson")
                || lowerSig.contains("com.aliyun.openservices.shade.com.alibaba.fastjson"))
                && (lowerSig.contains(" parse(")
                || lowerSig.contains(" parseobject(")
                || lowerSig.contains(" parsearray("));
    }

    public static boolean isJacksonReadValue(String lowerSig) {
        return lowerSig.contains("com.fasterxml.jackson.databind.objectmapper")
                && lowerSig.contains(" readvalue(");
    }

    /**
     * Template SSTI sinks only — package-scoped. Must NOT match GroovyShell.evaluate,
     * Activiti/Flowable ScriptingEngines.evaluate, JEXL, Janino, etc.
     */
    public static boolean isTemplateEvaluate(String lowerSig) {
        boolean templatePkg = lowerSig.contains("org.apache.velocity")
                || lowerSig.contains("freemarker.template")
                || lowerSig.contains("freemarker.cache")
                || lowerSig.contains("org.thymeleaf")
                || lowerSig.contains("com.mitchellbosecke.pebble")
                || lowerSig.contains("org.beetl")
                || lowerSig.contains("com.hubspot.jinjava")
                || lowerSig.contains("com.github.mustachejava")
                || lowerSig.contains("com.samskivert.mustache");
        if (!templatePkg) {
            return false;
        }
        return lowerSig.contains(" evaluate(")
                || lowerSig.contains(" process(")
                || lowerSig.contains(" merge(")
                || lowerSig.contains(" puttemplate(")
                || lowerSig.contains(" render(");
    }

    public static boolean isNetworkSideEffect(String lowerSig) {
        return lowerSig.contains("openstream")
                || lowerSig.contains("openconnection")
                || lowerSig.contains("httpclient")
                || lowerSig.contains(" resttemplate")
                || lowerSig.contains("webclient")
                || lowerSig.contains("okhttp")
                || (lowerSig.contains("java.net.urlconnection") && lowerSig.contains("connect"));
    }

    public static boolean isSqlExecute(String lowerSig) {
        return lowerSig.contains("executequery(")
                || lowerSig.contains("executeupdate(")
                || (lowerSig.contains("java.sql.statement") && lowerSig.contains(" execute("))
                || lowerSig.contains("jdbctemplate");
    }

    public static boolean isCmdExec(String lowerSig) {
        return (lowerSig.contains("java.lang.runtime") && lowerSig.contains(" exec("))
                || lowerSig.contains("processbuilder")
                || lowerSig.contains("processimpl");
    }

    public static boolean isScriptEval(String lowerSig) {
        return (lowerSig.contains("scriptengine") && (lowerSig.contains(" eval(")
                || lowerSig.contains(" evaluate(")))
                || lowerSig.contains("groovyshell")
                || lowerSig.contains("groovyclassloader")
                || lowerSig.contains("groovy.lang.groovy")
                || lowerSig.contains("org.codehaus.groovy")
                || lowerSig.contains("org.activiti.engine.impl.scripting")
                || lowerSig.contains("org.flowable.common.engine.impl.scripting")
                || lowerSig.contains("org.camunda.bpm.engine.impl.scripting")
                || lowerSig.contains("org.apache.commons.jexl")
                || lowerSig.contains("org.codehaus.janino")
                || lowerSig.contains("javax.script")
                || lowerSig.contains("ognl.ognl")
                || lowerSig.contains("springframework.expression")
                || lowerSig.contains("mvel2");
    }

    public static boolean isFileSideEffect(String lowerSig) {
        return lowerSig.contains("fileinputstream")
                || lowerSig.contains("fileoutputstream")
                || lowerSig.contains("files.read")
                || lowerSig.contains("files.write")
                || lowerSig.contains("files.delete")
                || lowerSig.contains("filewriter")
                || lowerSig.contains("filereader")
                || lowerSig.contains("randomaccessfile");
    }

    private static boolean isTemplateVuln(String vuln) {
        if (vuln == null || vuln.isBlank()) {
            return false;
        }
        return vuln.contains("velocity") || vuln.contains("freemarker")
                || vuln.contains("thymeleaf") || vuln.contains("pebble")
                || vuln.contains("beetl") || vuln.contains("jinjava")
                || vuln.contains("mustache") || vuln.contains("template_injection")
                || vuln.contains("ssti");
    }

    private static boolean isScriptVuln(String vuln) {
        if (vuln == null || vuln.isBlank()) {
            return false;
        }
        return vuln.contains("script") || vuln.contains("groovy")
                || vuln.contains("ognl") || vuln.contains("spel")
                || vuln.contains("mvel") || vuln.contains("jexl")
                || vuln.contains("aviator") || vuln.contains("janino")
                || vuln.contains("activiti") || vuln.contains("flowable")
                || vuln.contains("camunda") || vuln.contains("reflection");
    }
}
