package com.jbytescanner.engine;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pascal.taie.analysis.graph.callgraph.Edge;
import pascal.taie.analysis.pta.core.cs.context.Context;
import pascal.taie.analysis.pta.core.cs.element.CSCallSite;
import pascal.taie.analysis.pta.core.cs.element.CSMethod;
import pascal.taie.analysis.pta.core.heap.Descriptor;
import pascal.taie.analysis.pta.core.heap.HeapModel;
import pascal.taie.analysis.pta.core.heap.Obj;
import pascal.taie.analysis.pta.core.solver.Solver;
import pascal.taie.analysis.pta.plugin.Plugin;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.language.classes.JMethod;
import pascal.taie.language.type.Type;

import java.util.Set;

/**
 * Tai-e PTA plugin that injects synthetic return objects for known library
 * factory methods, restoring taint analysis correctness when only-app:true
 * is used.
 *
 * <h2>Why this is needed</h2>
 * <p>With {@code only-app:true}, DefaultSolver skips the return-value PFG
 * edge for every library callee (see {@code processCallEdge}):
 * <pre>
 *   if (!isIgnored(csCallee.getMethod())) {
 *       // pass args and return — SKIPPED for library methods
 *   }
 *   plugin.onNewCallEdge(edge);  // still fired
 * </pre>
 * This means the LHS variable of any library call (e.g.
 * {@code rt = Runtime.getRuntime()}) has an empty points-to set.
 * A subsequent virtual call on that variable (e.g. {@code rt.exec(cmd)})
 * therefore never creates a call edge, and SinkHandler never fires.
 *
 * <h2>What this plugin does</h2>
 * <p>For a curated set of library "factory methods" whose return objects
 * are commonly used as receivers for security-sensitive (sink) calls,
 * this plugin intercepts the call edge in {@link #onNewCallEdge} and
 * immediately adds a synthetic {@link Obj} of the correct type to the
 * return variable's points-to set via
 * {@code solver.addVarPointsTo(context, result, bridgeObj)}.
 * This unblocks virtual-call resolution for the next step in the chain.
 *
 * <h2>Remaining limitation</h2>
 * <p>Spring {@code @Autowired} beans (e.g. {@code JdbcTemplate}) still
 * cannot be modelled this way because the receiver field itself has an
 * empty points-to set (no Spring injection model), so no call edge to the
 * factory method is ever created in the first place.
 */
public class LibraryBridgePlugin implements Plugin {

    private static final Logger logger = LoggerFactory.getLogger(LibraryBridgePlugin.class);

    /** Descriptor that labels all synthetic objects emitted by this plugin. */
    private static final Descriptor BRIDGE_DESC = () -> "LibraryBridgeObj";

    // -----------------------------------------------------------------------
    // Factory methods whose return values are used as receivers for sinks.
    // We only list methods whose call edges ARE reachable (i.e. either static
    // or the receiver is app-allocated). Spring-injected beans are excluded
    // because the field itself has no pts without Spring modelling.
    // -----------------------------------------------------------------------
    private static final Set<String> BRIDGE_METHODS = Set.of(

        // ── RCE: Runtime.exec ──────────────────────────────────────────────
        "<java.lang.Runtime: java.lang.Runtime getRuntime()>",

        // ── RCE: ScriptEngine.eval ─────────────────────────────────────────
        // ScriptEngineManager is created with `new` in app code (pts non-empty),
        // so only getEngineByName/Extension/MimeType need bridging.
        "<javax.script.ScriptEngineManager: javax.script.ScriptEngine getEngineByName(java.lang.String)>",
        "<javax.script.ScriptEngineManager: javax.script.ScriptEngine getEngineByExtension(java.lang.String)>",
        "<javax.script.ScriptEngineManager: javax.script.ScriptEngine getEngineByMimeType(java.lang.String)>",

        // ── SQL injection: JDBC chain ──────────────────────────────────────
        // DriverManager.getConnection is a static factory; the returned
        // Connection then needs createStatement to get the sink.
        "<java.sql.DriverManager: java.sql.Connection getConnection(java.lang.String)>",
        "<java.sql.DriverManager: java.sql.Connection getConnection(java.lang.String,java.lang.String,java.lang.String)>",
        "<java.sql.DriverManager: java.sql.Connection getConnection(java.lang.String,java.util.Properties)>",
        "<javax.sql.DataSource: java.sql.Connection getConnection()>",
        "<javax.sql.DataSource: java.sql.Connection getConnection(java.lang.String,java.lang.String)>",
        "<java.sql.Connection: java.sql.Statement createStatement()>",
        "<java.sql.Connection: java.sql.Statement createStatement(int,int)>",
        "<java.sql.Connection: java.sql.Statement createStatement(int,int,int)>",
        "<java.sql.Connection: java.sql.PreparedStatement prepareStatement(java.lang.String)>",
        "<java.sql.Connection: java.sql.PreparedStatement prepareStatement(java.lang.String,int)>",
        "<java.sql.Connection: java.sql.PreparedStatement prepareStatement(java.lang.String,int[])>",
        "<java.sql.Connection: java.sql.PreparedStatement prepareStatement(java.lang.String,java.lang.String[])>",
        "<java.sql.Connection: java.sql.PreparedStatement prepareStatement(java.lang.String,int,int)>",
        "<java.sql.Connection: java.sql.PreparedStatement prepareStatement(java.lang.String,int,int,int)>",

        // ── XXE: DocumentBuilder chain ─────────────────────────────────────
        "<javax.xml.parsers.DocumentBuilderFactory: javax.xml.parsers.DocumentBuilderFactory newInstance()>",
        "<javax.xml.parsers.DocumentBuilderFactory: javax.xml.parsers.DocumentBuilder newDocumentBuilder()>",

        // ── XXE: SAXParser chain ───────────────────────────────────────────
        "<javax.xml.parsers.SAXParserFactory: javax.xml.parsers.SAXParserFactory newInstance()>",
        "<javax.xml.parsers.SAXParserFactory: javax.xml.parsers.SAXParser newSAXParser()>",
        "<javax.xml.parsers.SAXParser: org.xml.sax.XMLReader getXMLReader()>",

        // ── XXE: XMLReader direct factory ──────────────────────────────────
        "<org.xml.sax.helpers.XMLReaderFactory: org.xml.sax.XMLReader createXMLReader()>",
        "<org.xml.sax.helpers.XMLReaderFactory: org.xml.sax.XMLReader createXMLReader(java.lang.String)>",

        // ── XXE: XMLInputFactory ───────────────────────────────────────────
        "<javax.xml.stream.XMLInputFactory: javax.xml.stream.XMLInputFactory newInstance()>",
        "<javax.xml.stream.XMLInputFactory: javax.xml.stream.XMLInputFactory newFactory()>",

        // ── XXE / XSLT: TransformerFactory ────────────────────────────────
        "<javax.xml.transform.TransformerFactory: javax.xml.transform.TransformerFactory newInstance()>",

        // ── XPath injection ────────────────────────────────────────────────
        "<javax.xml.xpath.XPathFactory: javax.xml.xpath.XPathFactory newInstance()>",
        "<javax.xml.xpath.XPathFactory: javax.xml.xpath.XPath newXPath()>",

        // ── SSRF: Apache HttpClient ────────────────────────────────────────
        "<org.apache.http.impl.client.HttpClients: org.apache.http.impl.client.CloseableHttpClient createDefault()>",
        "<org.apache.http.impl.client.HttpClientBuilder: org.apache.http.impl.client.CloseableHttpClient build()>"
    );

    private Solver solver;
    private HeapModel heapModel;

    // -----------------------------------------------------------------------

    @Override
    public void setSolver(Solver solver) {
        this.solver = solver;
        this.heapModel = solver.getHeapModel();
    }

    @Override
    public void onNewCallEdge(Edge<CSCallSite, CSMethod> edge) {
        JMethod callee = edge.getCallee().getMethod();
        if (!BRIDGE_METHODS.contains(callee.getSignature())) {
            return;
        }

        CSCallSite csCallSite = edge.getCallSite();
        Invoke invoke = csCallSite.getCallSite();
        Var result = invoke.getResult();
        if (result == null) {
            return; // result discarded by caller
        }

        Type returnType = result.getType();
        Context context = csCallSite.getContext();

        // Create one synthetic object per (call site, return type) pair.
        // Using `invoke` as the allocation key gives a distinct object per
        // call site, avoiding unintended aliasing.
        Obj bridgeObj = heapModel.getMockObj(
                BRIDGE_DESC, invoke, returnType, invoke.getContainer());

        solver.addVarPointsTo(context, result, bridgeObj);

        logger.debug("[LibraryBridgePlugin] Bridged {} → {}",
                callee.getSignature(), returnType);
    }
}
