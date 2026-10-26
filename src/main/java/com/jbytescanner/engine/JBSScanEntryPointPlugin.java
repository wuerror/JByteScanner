package com.jbytescanner.engine;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.jbytescanner.diagnose.TaiEMethodSignature;
import com.jbytescanner.worker.EntryCheckEvidence;
import com.jbytescanner.worker.TargetDiagnosticEvidence;
import com.jbytescanner.worker.TargetDiagnosticRequest;
import com.jbytescanner.worker.TargetInvokeEvidence;
import pascal.taie.World;
import pascal.taie.analysis.graph.callgraph.CallGraph;
import pascal.taie.analysis.pta.core.cs.element.CSCallSite;
import pascal.taie.analysis.pta.core.cs.element.CSMethod;
import pascal.taie.analysis.pta.core.solver.DeclaredParamProvider;
import pascal.taie.analysis.pta.core.solver.EntryPoint;
import pascal.taie.analysis.pta.core.solver.Solver;
import pascal.taie.analysis.pta.plugin.Plugin;
import pascal.taie.ir.IR;
import pascal.taie.ir.proginfo.MethodRef;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.ir.stmt.Stmt;
import pascal.taie.language.classes.ClassHierarchy;
import pascal.taie.language.classes.JClass;
import pascal.taie.language.classes.JMethod;
import pascal.taie.language.type.Type;

import pascal.taie.analysis.pta.plugin.taint.TaintAnalysis;
import pascal.taie.analysis.pta.plugin.taint.TaintFlow;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Tai-e PTA plugin that injects JByteScanner's discovered API entry methods
 * into the pointer analysis call graph.
 *
 * Web application controller methods are NOT JVM-implicit entry points.
 * Without this plugin they would never appear in the PTA call graph,
 * causing TaintAnalysis to find zero flows even for genuinely vulnerable code.
 *
 * Usage: set {@link #entrySignatures} before building the Tai-e World, then
 * add "plugins:[com.jbytescanner.engine.JBSScanEntryPointPlugin]" to the PTA
 * config string.
 */
public class JBSScanEntryPointPlugin implements Plugin {
    private static final Logger logger = LoggerFactory.getLogger(JBSScanEntryPointPlugin.class);

    /**
     * API entry method signatures discovered by DiscoveryEngine.
     * Must be set by TaintEngine BEFORE AnalysisManager.execute() is called.
     * Format: {@code <com.example.Class: returnType methodName(paramTypes)>}
     */
    public static volatile List<String> entrySignatures = List.of();

    /**
     * Conservative fallback for incomplete Spring deployments: make concrete public
     * methods of application @Service classes reachable without enabling Tai-e's full
     * Spring DI/WEC plugin. Their parameters are deliberately not registered as sources.
     */
    public static volatile boolean springServiceEntryFallback = false;

    /** Internal methods that contain inferred persistent-data reads. */
    public static volatile List<String> supplementalEntrySignatures = List.of();

    /**
     * Taint flows captured in onFinish(), after TaintAnalysis has stored its results.
     * Plugin execution order: TaintAnalysis → ResultProcessor → JBSScanEntryPointPlugin.
     * This field is populated BEFORE AnalysisManager clears the PTA result from World,
     * which is why we capture here instead of reading World.get().getResult("pta") post-analysis.
     */
    public static volatile Set<TaintFlow> capturedTaintFlows = null;

    /** Last onStart/onFinish inject and capture counts for expansion metrics. */
    public static volatile ExpansionMetrics lastInjectMetrics = new ExpansionMetrics();

    /** Set only by targeted diagnose; ordinary scans leave this null. */
    public static volatile TargetDiagnosticRequest diagnosticTarget;

    /** Bounded target evidence captured before the worker's World is released. */
    public static volatile TargetDiagnosticEvidence lastDiagnosticEvidence;

    private Solver solver;

    @Override
    public void setSolver(Solver solver) {
        this.solver = solver;
    }

    @Override
    public void onStart() {
        lastInjectMetrics = new ExpansionMetrics();
        if (entrySignatures.isEmpty()) {
            logger.warn("[JBSScanEntryPointPlugin] entrySignatures is empty — no API entry points will be injected.");
            return;
        }
        ClassHierarchy ch = World.get().getClassHierarchy();
        int raw = 0;
        int added = 0;
        int duplicate = 0;
        int unresolved = 0;
        int skippedNoBody = 0;
        Set<JMethod> addedMethods = new HashSet<>();
        for (String sig : entrySignatures) {
            raw++;
            JMethod method = resolveMethod(ch, sig);
            if (method == null) {
                unresolved++;
            } else if (method.isAbstract()
                    || method.isNative()
                    || method.getDeclaringClass().isPhantom()) {
                // PTA plugins such as ExceptionAnalysis call JMethod.getIR() for
                // every newly reachable method. Abstract, native, and phantom
                // methods have no IR and therefore cannot be direct entry points.
                skippedNoBody++;
                logger.debug("[JBSScanEntryPointPlugin] Skipping API method without a body: {}", sig);
            } else if (addedMethods.add(method)) {
                // Record before inject so repeated signatures never double-inject.
                solver.addEntryPoint(new EntryPoint(method,
                        new DeclaredParamProvider(method, solver.getHeapModel())));
                added++;
            } else {
                duplicate++;
            }
        }
        // raw/duplicate here are post route-level EntryPointKey dedup (TaintEngine).
        // duplicateSkipped counts JMethod-identity collisions (same method, different sig strings
        // should be rare) and is mainly useful vs supplemental/service fallback paths.
        logger.info("[JBSScanEntryPointPlugin] Entry inject (postEntryKeyDedup): candidates={}, "
                        + "uniqueInjected={}, methodIdentityDupSkipped={}, unresolved={}, "
                        + "noBodySkipped={}.",
                raw, added, duplicate, unresolved, skippedNoBody);
        ExpansionMetrics injectMetrics = new ExpansionMetrics();
        injectMetrics.entryCandidates = raw;
        injectMetrics.entryInjected = added;
        injectMetrics.entryMethodIdentityDupSkipped = duplicate;
        injectMetrics.entryUnresolved = unresolved;
        injectMetrics.entryNoBodySkipped = skippedNoBody;

        int supplementalAdded = 0;
        int supplementalSkipped = 0;
        for (String sig : supplementalEntrySignatures) {
            JMethod method = resolveMethod(ch, sig);
            if (method == null || method.isAbstract() || method.isNative()
                    || method.getDeclaringClass().isPhantom()) {
                supplementalSkipped++;
                continue;
            }
            if (!addedMethods.add(method)) {
                supplementalSkipped++;
                continue;
            }
            solver.addEntryPoint(new EntryPoint(method,
                    new DeclaredParamProvider(method, solver.getHeapModel())));
            supplementalAdded++;
        }
        if (!supplementalEntrySignatures.isEmpty()) {
            logger.info("[JBSScanEntryPointPlugin] Injected {} inferred persistent-read "
                            + "entry method(s) ({} skipped).",
                    supplementalAdded, supplementalSkipped);
        }
        injectMetrics.supplementalEntriesInjected = supplementalAdded;
        injectMetrics.supplementalEntriesSkipped = supplementalSkipped;

        if (springServiceEntryFallback) {
            int serviceClasses = 0;
            int serviceMethods = 0;
            for (JClass clazz : ch.applicationClasses().toList()) {
                if (clazz.isPhantom() || clazz.isInterface() || clazz.isAbstract()
                        || !clazz.hasAnnotation("org.springframework.stereotype.Service")) {
                    continue;
                }
                serviceClasses++;
                for (JMethod method : clazz.getDeclaredMethods()) {
                    if (!method.isPublic() || method.isStatic() || method.isConstructor()
                            || method.isStaticInitializer() || method.isAbstract()
                            || method.isNative()) {
                        continue;
                    }
                    if (!addedMethods.add(method)) {
                        continue;
                    }
                    solver.addEntryPoint(new EntryPoint(method,
                            new DeclaredParamProvider(method, solver.getHeapModel())));
                    serviceMethods++;
                }
            }
            logger.info("[JBSScanEntryPointPlugin] Spring service fallback injected {} public "
                            + "method(s) from {} concrete @Service class(es).",
                    serviceMethods, serviceClasses);
            injectMetrics.serviceFallbackClasses = serviceClasses;
            injectMetrics.serviceFallbackMethodsInjected = serviceMethods;
        }
        lastInjectMetrics = injectMetrics;
        collectEntryChecks(ch, addedMethods);
    }

    @Override
    public void onFinish() {
        // Plugin order: TaintAnalysis → ResultProcessor → us (JBSScanEntryPointPlugin).
        // By the time our onFinish() is called, TaintAnalysis has already called:
        //   solver.getResult().storeResult(TaintAnalysis.class.getName(), taintFlows)
        // We capture them here before AnalysisManager clears the PTA result from World.
        Set<TaintFlow> flows = solver.getResult().getResult(TaintAnalysis.class.getName());
        capturedTaintFlows = flows;
        int flowCount = flows != null ? flows.size() : 0;
        logger.info("[JBSScanEntryPointPlugin] Captured {} taint flow(s) from TaintAnalysis.",
                flowCount);
        if (lastInjectMetrics != null) {
            lastInjectMetrics.capturedTaintFlows = flowCount;
        }

        collectTargetEvidence();

        // Optional focused call-graph diagnostics for false-negative investigations.
        // Example: -Djbs.reachability.filter=com.example.feature
        String reachabilityFilter = System.getProperty("jbs.reachability.filter");
        if (reachabilityFilter != null && !reachabilityFilter.isBlank()) {
            solver.getCallGraph().reachableMethods()
                    .map(csMethod -> csMethod.getMethod().getSignature())
                    .filter(signature -> signature.contains(reachabilityFilter))
                    .distinct()
                    .sorted()
                    .forEach(signature -> logger.info("[JBS-Reachable] {}", signature));
        }
    }

    private void collectEntryChecks(ClassHierarchy ch, Set<JMethod> addedMethods) {
        TargetDiagnosticRequest request = diagnosticTarget;
        if (request == null || request.entrySignaturesToCheck == null
                || request.entrySignaturesToCheck.isEmpty()) {
            return;
        }
        TargetDiagnosticEvidence evidence = ensureDiagnosticEvidence();
        Set<String> listedEntries = new HashSet<>();
        for (String entry : entrySignatures) {
            listedEntries.add(TaiEMethodSignature.canonicalize(entry));
        }
        for (String signature : request.entrySignaturesToCheck) {
            if (signature == null || signature.isBlank()) {
                continue;
            }
            EntryCheckEvidence check = new EntryCheckEvidence();
            check.signature = signature;
            JMethod method = resolveMethod(ch, signature);
            if (method == null) {
                check.status = "UNRESOLVED";
                check.detail = "signature did not resolve in the Tai-e World";
                evidence.entryChecks.add(check);
                continue;
            }
            check.inApplicationScope = method.isApplication();
            check.declaringClassPhantom = method.getDeclaringClass().isPhantom();
            if (!listedEntries.contains(TaiEMethodSignature.canonicalize(signature))) {
                check.status = "NOT_IN_ENTRY_LIST";
                check.detail = "resolved but was not injected as an entry signature";
            } else if (method.getDeclaringClass().isPhantom()) {
                check.status = "PHANTOM_CLASS";
                check.detail = "declaring class is phantom";
            } else if (method.isAbstract()) {
                check.status = "ABSTRACT";
                check.detail = "entry method is abstract";
            } else if (method.isNative()) {
                check.status = "NATIVE";
                check.detail = "entry method is native";
            } else if (addedMethods.contains(method)) {
                check.status = "INJECTED";
                check.detail = "entry method injected with declared-parameter provider";
            } else {
                check.status = "DUPLICATE_NOT_INJECTED";
                check.detail = "method was already injected under another entry identity";
            }
            evidence.entryChecks.add(check);
        }
    }

    private void collectTargetEvidence() {
        TargetDiagnosticRequest request = diagnosticTarget;
        if (request == null) {
            return;
        }
        TargetDiagnosticEvidence evidence = ensureDiagnosticEvidence();
        evidence.limits.put("maxTargetInvokes", request.maxTargetInvokes);
        evidence.limits.put("maxReachableMethods", request.maxReachableMethods);
        evidence.limits.put("maxApplicationMethods", request.maxApplicationMethods);
        evidence.limits.put("maxCalleesPerInvoke", request.maxCalleesPerInvoke);
        TaiEMethodSignature target = TaiEMethodSignature.parseNullable(request.sinkSignature);
        if (target == null) {
            evidence.notes.add("target sink signature could not be parsed in the worker");
            lastDiagnosticEvidence = evidence;
            return;
        }
        int maxInvokes = request.maxTargetInvokes > 0 ? request.maxTargetInvokes : 200;
        int maxCallees = request.maxCalleesPerInvoke > 0 ? request.maxCalleesPerInvoke : 64;
        List<Sighting> sightings = new ArrayList<>();
        boolean invokeTruncated = false;
        long maxApplicationMethods = request.maxApplicationMethods > 0
                ? request.maxApplicationMethods : 2_000_000L;
        long applicationMethodsScanned = 0;
        outer:
        for (JClass clazz : World.get().getClassHierarchy().applicationClasses().toList()) {
            for (JMethod method : clazz.getDeclaredMethods()) {
                if (method.isAbstract() || method.isNative()
                        || method.getDeclaringClass().isPhantom()) {
                    continue;
                }
                applicationMethodsScanned++;
                if (applicationMethodsScanned > maxApplicationMethods) {
                    evidence.irScanTruncated = true;
                    evidence.notes.add("application IR scan reached maxApplicationMethods");
                    break outer;
                }
                IR ir;
                try {
                    ir = method.getIR();
                } catch (Throwable ignored) {
                    continue;
                }
                if (ir == null) {
                    continue;
                }
                for (Stmt stmt : ir) {
                    if (!(stmt instanceof Invoke invoke)) {
                        continue;
                    }
                    // InvokeDynamic has no MethodRef in Tai-e and throws
                    // UnsupportedOperationException. It can never be the exact
                    // named sink signature, so skip it.
                    if (invoke.isDynamic()) {
                        continue;
                    }
                    MethodRef ref = invoke.getMethodRef();
                    String declaredSignature = methodRefSignature(ref);
                    if (!target.canonical().equals(declaredSignature)) {
                        continue;
                    }
                    if (sightings.size() >= maxInvokes) {
                        invokeTruncated = true;
                        break outer;
                    }
                    TargetInvokeEvidence item = new TargetInvokeEvidence();
                    item.containerSignature = method.getSignature();
                    item.stmtIndex = invoke.getIndex();
                    item.lineNumber = invoke.getLineNumber();
                    item.invokeText = invoke.toString();
                    item.declaredSignature = declaredSignature;
                    JMethod resolved = ref.resolveNullable();
                    item.resolvedSignature = resolved != null ? resolved.getSignature() : null;
                    sightings.add(new Sighting(item, invoke));
                }
            }
        }
        evidence.applicationMethodsScanned = applicationMethodsScanned;
        if (invokeTruncated) {
            evidence.limits.put("targetInvokesTruncated", true);
            evidence.notes.add("target invoke collection reached maxTargetInvokes");
        }

        CallGraph<CSCallSite, CSMethod> callGraph = solver != null
                ? solver.getCallGraph() : null;
        evidence.callGraphAvailable = callGraph != null;
        if (callGraph == null) {
            evidence.notes.add("call graph unavailable in the worker");
            evidence.targetInvokes = sightings.stream().map(Sighting::evidence).toList();
            lastDiagnosticEvidence = evidence;
            return;
        }

        Set<String> containerSignatures = new LinkedHashSet<>();
        for (Sighting sighting : sightings) {
            containerSignatures.add(sighting.evidence().containerSignature);
        }
        Map<String, CSMethod> reachableContainers = new HashMap<>();
        long reachableCount = 0;
        long maxReachable = request.maxReachableMethods > 0
                ? request.maxReachableMethods : 2_000_000L;
        try (var reachable = callGraph.reachableMethods()) {
            var iterator = reachable.iterator();
            while (iterator.hasNext()) {
                CSMethod csMethod = iterator.next();
                reachableCount++;
                if (reachableCount > maxReachable) {
                    evidence.reachableScanTruncated = true;
                    evidence.notes.add("reachable method scan reached maxReachableMethods");
                    break;
                }
                String signature = csMethod.getMethod().getSignature();
                if (containerSignatures.contains(signature)
                        && !reachableContainers.containsKey(signature)) {
                    reachableContainers.put(signature, csMethod);
                }
            }
        } catch (Throwable t) {
            evidence.notes.add("reachable method scan failed: " + t);
        }
        evidence.reachableMethodCount = reachableCount;

        for (Sighting sighting : sightings) {
            TargetInvokeEvidence item = sighting.evidence();
            CSMethod container = reachableContainers.get(item.containerSignature);
            item.callerReachable = container != null;
            if (container == null) {
                continue;
            }
            try {
                for (CSCallSite callSite : callGraph.getCallSitesIn(container)) {
                    if (!callSite.getCallSite().equals(sighting.invoke())) {
                        continue;
                    }
                    Set<CSMethod> callees = callGraph.getCalleesOf(callSite);
                    if (callees != null) {
                        int added = 0;
                        for (CSMethod callee : callees) {
                            if (added >= maxCallees) {
                                evidence.limits.put("calleesTruncated", true);
                                break;
                            }
                            String calleeSignature = callee.getMethod().getSignature();
                            if (!item.resolvedCallees.contains(calleeSignature)) {
                                item.resolvedCallees.add(calleeSignature);
                                added++;
                            }
                            if (target.canonical().equals(calleeSignature)) {
                                item.calleeReachable = true;
                            }
                        }
                    }
                    item.callEdgeObserved = !item.resolvedCallees.isEmpty();
                    break;
                }
            } catch (Throwable t) {
                evidence.notes.add("call edge lookup failed for "
                        + item.containerSignature + ": " + t);
            }
        }
        evidence.targetInvokes = sightings.stream().map(Sighting::evidence).toList();
        lastDiagnosticEvidence = evidence;
    }

    private TargetDiagnosticEvidence ensureDiagnosticEvidence() {
        if (lastDiagnosticEvidence == null) {
            lastDiagnosticEvidence = new TargetDiagnosticEvidence();
        }
        return lastDiagnosticEvidence;
    }

    private static String methodRefSignature(MethodRef ref) {
        List<Type> parameters = ref.getParameterTypes();
        List<String> names = new ArrayList<>(parameters.size());
        for (Type parameter : parameters) {
            names.add(parameter.getName());
        }
        return "<" + ref.getDeclaringClass().getName() + ": "
                + ref.getReturnType().getName() + " " + ref.getName()
                + "(" + String.join(",", names) + ")>";
    }

    private record Sighting(TargetInvokeEvidence evidence, Invoke invoke) {
    }

    /**
     * Resolves a Tai-e method signature string to a JMethod.
     *
     * @param ch  class hierarchy
     * @param sig format {@code <com.example.Class: returnType methodName(paramTypes)>}
     * @return the resolved JMethod, or {@code null} if not found
     */
    static JMethod resolveMethod(ClassHierarchy ch, String sig) {
        try {
            if (sig == null || !sig.startsWith("<") || !sig.endsWith(">")) return null;
            String inner = sig.substring(1, sig.length() - 1); // strip < >
            int colonIdx = inner.indexOf(": ");
            if (colonIdx < 0) return null;
            String className = inner.substring(0, colonIdx);
            JClass clazz = ch.getClass(className);
            if (clazz == null) return null;
            for (JMethod m : clazz.getDeclaredMethods()) {
                if (sig.equals(m.getSignature())) {
                    return m;
                }
            }
        } catch (Exception e) {
            logger.debug("Failed to resolve entry method signature: {}", sig, e);
        }
        return null;
    }
}
