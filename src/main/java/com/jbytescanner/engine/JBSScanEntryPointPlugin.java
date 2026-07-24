package com.jbytescanner.engine;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pascal.taie.World;
import pascal.taie.analysis.pta.core.solver.DeclaredParamProvider;
import pascal.taie.analysis.pta.core.solver.EntryPoint;
import pascal.taie.analysis.pta.core.solver.Solver;
import pascal.taie.analysis.pta.plugin.Plugin;
import pascal.taie.language.classes.ClassHierarchy;
import pascal.taie.language.classes.JClass;
import pascal.taie.language.classes.JMethod;

import pascal.taie.analysis.pta.plugin.taint.TaintAnalysis;
import pascal.taie.analysis.pta.plugin.taint.TaintFlow;

import java.util.HashSet;
import java.util.List;
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

    private Solver solver;

    @Override
    public void setSolver(Solver solver) {
        this.solver = solver;
    }

    @Override
    public void onStart() {
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
        }
    }

    @Override
    public void onFinish() {
        // Plugin order: TaintAnalysis → ResultProcessor → us (JBSScanEntryPointPlugin).
        // By the time our onFinish() is called, TaintAnalysis has already called:
        //   solver.getResult().storeResult(TaintAnalysis.class.getName(), taintFlows)
        // We capture them here before AnalysisManager clears the PTA result from World.
        Set<TaintFlow> flows = solver.getResult().getResult(TaintAnalysis.class.getName());
        capturedTaintFlows = flows;
        logger.info("[JBSScanEntryPointPlugin] Captured {} taint flow(s) from TaintAnalysis.",
                flows != null ? flows.size() : 0);

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
