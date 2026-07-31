package com.jbytescanner.engine;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class TaintEngineLogParserTest {

    @Test
    void parsesCallResultSource() {
        String line = "INFO TaintFlow{"
                + "<com.qzing.ieep.groovy.model.GroovyScriptInfo: "
                + "com.qzing.ieep.groovy.model.GroovyScriptInfo newInstance(com.qzing.ieep.groovy.entity.GroovyScript)>"
                + "[3@L36] groovyScript.getContent()/result -> "
                + "<com.qzing.ieep.groovy.util.GroovyUtils: groovy.lang.Script initScript(java.lang.String)>"
                + "[4@L50] $r2 = invokevirtual $r1.parse(scriptText)/0}";

        TaintEngine.ParsedTaintFlow flow = TaintEngine.parseTaintFlowLine(line);

        assertNotNull(flow);
        assertEquals("com.qzing.ieep.groovy.model.GroovyScriptInfo: "
                        + "com.qzing.ieep.groovy.model.GroovyScriptInfo newInstance(com.qzing.ieep.groovy.entity.GroovyScript)",
                flow.sourceMethod());
        assertEquals("com.qzing.ieep.groovy.util.GroovyUtils: groovy.lang.Script initScript(java.lang.String)",
                flow.containerMethod());
        assertEquals(4, flow.sinkStmtIndex());
        assertEquals("$r2 = invokevirtual $r1.parse(scriptText)", flow.invokeText());
    }

    @Test
    void parsesConstructorSinkContainingInitAngleBrackets() {
        String line = "TaintFlow{"
                + "<com.qzing.ieep.controller.IndexController: java.lang.Object exportFile(java.lang.String,java.util.Map)>/0 -> "
                + "<com.qzing.ieep.controller.IndexController: java.lang.Object exportFile(java.lang.String,java.util.Map)>"
                + "[6@L82] invokespecial $r3.<init>(filePath)/0}";

        TaintEngine.ParsedTaintFlow flow = TaintEngine.parseTaintFlowLine(line);

        assertNotNull(flow);
        assertEquals("com.qzing.ieep.controller.IndexController: "
                        + "java.lang.Object exportFile(java.lang.String,java.util.Map)",
                flow.sourceMethod());
        assertEquals(6, flow.sinkStmtIndex());
        assertEquals("invokespecial $r3.<init>(filePath)", flow.invokeText());
    }

    @Test
    void parsesConstructorSourceSignature() {
        String line = "TaintFlow{<example.Input: void <init>(java.lang.String)>/0 -> "
                + "<example.Input: void consume(java.lang.String)>"
                + "[1@L12] invokestatic example.Sink.run(value)/0}";

        TaintEngine.ParsedTaintFlow flow = TaintEngine.parseTaintFlowLine(line);

        assertNotNull(flow);
        assertEquals("example.Input: void <init>(java.lang.String)", flow.sourceMethod());
    }
}
