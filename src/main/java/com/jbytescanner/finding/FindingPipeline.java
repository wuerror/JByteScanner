package com.jbytescanner.finding;

import com.jbytescanner.config.NoiseFilterConfig;
import com.jbytescanner.config.ScanConfig;
import com.jbytescanner.config.SinkRule;
import com.jbytescanner.engine.RuleManager;
import com.jbytescanner.model.ApiRoute;
import com.jbytescanner.model.Vulnerability;
import com.jbytescanner.worker.CapturedTaintFlow;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * P0.6 finding pipeline: normalize → classify → suppress/demote → aggregate → score.
 * Reporters must only serialize pipeline outputs.
 */
public class FindingPipeline {

    private static final Logger logger = LoggerFactory.getLogger(FindingPipeline.class);
    private static final Pattern SOURCE_SIG = Pattern.compile(
            "^<([^:]+):\\s*([\\w.$\\[\\]]+)\\s+([\\w$<>]+\\([^)]*\\))>$");

    private final RuleManager ruleManager;
    private final ScanConfig scanConfig;
    private final NoiseFilterConfig noiseFilter;
    private final List<String> findingPackages;
    private final List<ApiRoute> routes;

    public FindingPipeline(RuleManager ruleManager, ScanConfig scanConfig, List<ApiRoute> routes) {
        this.ruleManager = ruleManager;
        this.scanConfig = scanConfig != null ? scanConfig : new ScanConfig();
        NoiseFilterConfig nf = this.scanConfig.getNoiseFilter();
        this.noiseFilter = nf != null ? nf : new NoiseFilterConfig();
        this.findingPackages = resolveFindingPackages(this.scanConfig);
        this.routes = routes != null ? routes : List.of();
    }

    public PipelineResult process(List<CapturedTaintFlow> flows) {
        PipelineResult result = new PipelineResult();
        result.authSource = "asm_route";
        if (flows == null) {
            flows = List.of();
        }
        result.flowsRaw = flows.size();

        if (!noiseFilter.isEnabled()) {
            return processDisabled(flows, result);
        }

        boolean exactDedupe = !"off".equalsIgnoreCase(
                noiseFilter.getDedupe() != null ? noiseFilter.getDedupe() : "exact");

        Map<String, CanonicalFinding> exact = new LinkedHashMap<>();
        List<CanonicalFinding> noDedupe = new ArrayList<>();
        for (CapturedTaintFlow flow : flows) {
            CanonicalFinding built = buildFromFlow(flow);
            if (built == null) {
                continue;
            }
            applyDisposition(built);
            FindingInstance inst = built.instances.isEmpty() ? null : built.instances.get(0);
            if (!exactDedupe) {
                noDedupe.add(built);
                continue;
            }
            String key = built.exactInstanceKey(inst);
            CanonicalFinding existing = exact.get(key);
            if (existing == null) {
                exact.put(key, built);
            } else {
                existing.mergeInstance(inst);
                if (rankDisposition(built.disposition) < rankDisposition(existing.disposition)) {
                    existing.disposition = built.disposition;
                    for (String r : built.reasonCodes) {
                        existing.addReason(r);
                    }
                }
            }
        }
        List<CanonicalFinding> afterExact = exactDedupe
                ? new ArrayList<>(exact.values()) : noDedupe;
        result.findingsAfterExactDedupe = afterExact.size();

        List<CanonicalFinding> afterFanIn = fanInAggregate(afterExact);
        result.findingsAfterFanIn = afterFanIn.size();
        result.authSource = routes.isEmpty() ? "unavailable" : "asm_route";

        for (CanonicalFinding f : afterFanIn) {
            sortInstances(f);
            score(f);
            place(result, f);
        }

        logger.info("FindingPipeline: raw={} exact={} fanIn={} main={} low={} suppressed={}",
                result.flowsRaw, result.findingsAfterExactDedupe, result.findingsAfterFanIn,
                result.mainFindings.size(), result.lowConfidenceFindings.size(),
                result.suppressedFindings.size());
        return result;
    }

    private PipelineResult processDisabled(List<CapturedTaintFlow> flows, PipelineResult result) {
        // Honor dedupe: off → one finding per raw flow (identity preserved for A/B replay).
        boolean exactDedupe = !"off".equalsIgnoreCase(
                noiseFilter.getDedupe() != null ? noiseFilter.getDedupe() : "exact");
        Map<String, CanonicalFinding> exact = new LinkedHashMap<>();
        List<CanonicalFinding> rawList = new ArrayList<>();
        int idx = 0;
        for (CapturedTaintFlow flow : flows) {
            CanonicalFinding built = buildFromFlow(flow);
            if (built == null) {
                continue;
            }
            built.disposition = FindingDisposition.MAIN;
            built.addReason("NOISE_FILTER_DISABLED");
            FindingInstance inst = built.instances.isEmpty() ? null : built.instances.get(0);
            if (!exactDedupe) {
                // Unique key per raw flow so identical identities stay distinct when dedupe=off
                built.addReason("RAW_FLOW_" + (idx++));
                rawList.add(built);
                continue;
            }
            String key = built.exactInstanceKey(inst);
            CanonicalFinding existing = exact.get(key);
            if (existing == null) {
                exact.put(key, built);
            } else {
                existing.mergeInstance(inst);
            }
        }
        List<CanonicalFinding> list = exactDedupe ? new ArrayList<>(exact.values()) : rawList;
        result.findingsAfterExactDedupe = list.size();
        result.findingsAfterFanIn = list.size();
        for (CanonicalFinding f : list) {
            sortInstances(f);
            score(f);
            f.disposition = FindingDisposition.MAIN;
            result.mainFindings.add(f);
        }
        return result;
    }

    private CanonicalFinding buildFromFlow(CapturedTaintFlow flow) {
        SinkRule sinkRule = findSinkRule(flow);
        if (sinkRule == null) {
            throw new IllegalStateException(String.format(
                    "No SinkRule for captured flow: configured=%s, declared=%s, "
                            + "resolved=%s, container=%s, stmt=%d, invoke=%s",
                    flow.sinkRuleSignature, flow.declaredSinkSignature,
                    flow.resolvedSinkSignature, flow.sinkContainerSignature,
                    flow.sinkStmtIndex, flow.invokeText));
        }

        boolean hasSideEffect = flow.localFollowingSideEffects != null
                && !flow.localFollowingSideEffects.isEmpty();
        SinkStrength strength = SinkStrengthClassifier.classify(
                sinkRule, flow.sinkRuleSignature, hasSideEffect);

        CanonicalFinding f = new CanonicalFinding();
        f.ruleId = sinkRule.getVulnType() != null ? sinkRule.getVulnType() : "Unknown";
        f.sinkRuleSignature = firstNonBlank(flow.sinkRuleSignature, sinkRule.getSignature());
        f.sinkIndex = flow.sinkIndex;
        f.sinkContainerSignature = flow.sinkContainerSignature;
        f.sinkStmtIndex = flow.sinkStmtIndex;
        f.sinkLineNumber = flow.sinkLineNumber;
        f.declaredSinkSignature = flow.declaredSinkSignature;
        f.resolvedSinkSignature = flow.resolvedSinkSignature;
        f.invokeText = flow.invokeText;
        f.sinkStrength = strength;
        f.sinkRule = sinkRule;
        f.evidenceLevel = hasSideEffect
                ? EvidenceLevel.LOCAL_SIDE_EFFECT
                : EvidenceLevel.ENDPOINT_ONLY;
        if (flow.localFollowingSideEffects != null) {
            f.localFollowingSideEffects = new ArrayList<>(flow.localFollowingSideEffects);
        }

        FindingInstance inst = new FindingInstance();
        inst.sourceContainerSignature = flow.sourceContainerSignature;
        inst.sourceRuleSignature = flow.sourceRuleSignature;
        inst.sourceKind = flow.sourceKind;
        inst.sourceIndex = flow.sourceIndex;
        inst.rawFlow = flow.rawFlow;
        bindRoute(inst);
        f.instances.add(inst);
        f.sourceCount = 1;
        return f;
    }

    private void applyDisposition(CanonicalFinding f) {
        String containerClass = LibraryInternalPackages.classNameFromSignature(
                f.sinkContainerSignature);
        boolean inFindingPkg = findingPackages.isEmpty()
                || matchesPackage(containerClass, findingPackages);
        boolean outside = !findingPackages.isEmpty() && !inFindingPkg;
        boolean libraryInternal = LibraryInternalPackages.matches(
                containerClass, noiseFilter.getLibraryPackageDeny());
        boolean weak = LibraryInternalPackages.isWeakFamily(f.sinkStrength);

        f.packageProvenance = inFindingPkg
                ? "IN_FINDING_PACKAGES"
                : (findingPackages.isEmpty() ? "PACKAGES_UNSPECIFIED" : "OUTSIDE_FINDING_PACKAGES");

        // Library-internal weak sinks
        if (libraryInternal && weak
                && "suppress".equalsIgnoreCase(noiseFilter.getLibraryInternalWeak())) {
            f.disposition = FindingDisposition.SUPPRESSED;
            f.addReason("WEAK_SINK_LIBRARY_INTERNAL");
            return;
        }

        // Outside package + weak
        if (outside && weak) {
            String mode = noiseFilter.getWeakSinkOutsidePackage();
            if ("suppress".equalsIgnoreCase(mode)) {
                f.disposition = FindingDisposition.SUPPRESSED;
                f.addReason("WEAK_SINK_OUTSIDE_APP");
                return;
            }
            f.disposition = FindingDisposition.LOW_CONFIDENCE;
            f.addReason("WEAK_SINK_OUTSIDE_APP_DEMOTE");
            return;
        }

        // Constructor without same-method side effect.
        // Outside/library: hard suppress (or demote if configured).
        // In finding packages: demote only — openStream may be in another method (FN if suppress).
        if (f.sinkStrength == SinkStrength.CONSTRUCTOR
                && f.evidenceLevel == EvidenceLevel.ENDPOINT_ONLY) {
            String mode = noiseFilter.getConstructorWithoutSideEffect();
            boolean hardDropSite = outside || libraryInternal;
            if (hardDropSite) {
                if ("demote".equalsIgnoreCase(mode) || "keep".equalsIgnoreCase(mode)) {
                    f.disposition = FindingDisposition.LOW_CONFIDENCE;
                    f.addReason("CONSTRUCTOR_WITHOUT_SIDE_EFFECT_OUTSIDE");
                } else {
                    f.disposition = FindingDisposition.SUPPRESSED;
                    f.addReason("CONSTRUCTOR_WITHOUT_SIDE_EFFECT");
                }
                return;
            }
            // In-app: always demote (never suppress) so cross-method SSRF remains visible
            f.disposition = FindingDisposition.LOW_CONFIDENCE;
            f.addReason("CONSTRUCTOR_WITHOUT_SIDE_EFFECT_IN_APP");
            return;
        }

        // Plain JSON parse demote
        if (noiseFilter.isDemotePlainJsonParse()
                && f.sinkStrength == SinkStrength.PARSER) {
            f.disposition = FindingDisposition.LOW_CONFIDENCE;
            f.addReason("PLAIN_JSON_PARSE");
            return;
        }

        // Template high fan-in / no path evidence — applied after aggregation too
        if (noiseFilter.isDemoteTemplateWithoutPathEvidence()
                && isTemplateRule(f.ruleId)
                && f.evidenceLevel == EvidenceLevel.ENDPOINT_ONLY) {
            f.disposition = FindingDisposition.LOW_CONFIDENCE;
            f.addReason("TEMPLATE_NO_PATH_EVIDENCE");
            return;
        }

        // Terminal outside package: never hard-drop; optional confidence demote via config
        if (outside && f.sinkStrength == SinkStrength.TERMINAL_SIDE_EFFECT) {
            String mode = noiseFilter.getTerminalOutsidePackage();
            f.addReason("TERMINAL_OUTSIDE_APP_PACKAGE");
            if ("keep_demote_confidence".equalsIgnoreCase(mode)
                    || "demote".equalsIgnoreCase(mode)) {
                // Stay MAIN (triage-visible); score() applies confidence penalty via provenance
                f.disposition = FindingDisposition.MAIN;
            } else {
                f.disposition = FindingDisposition.MAIN;
            }
            return;
        }

        // Constructor upgraded via local side effect inside app → main
        if (f.sinkStrength == SinkStrength.TERMINAL_SIDE_EFFECT
                && f.evidenceLevel == EvidenceLevel.LOCAL_SIDE_EFFECT) {
            f.disposition = FindingDisposition.MAIN;
            f.addReason("LOCAL_SIDE_EFFECT");
            return;
        }

        if (f.sinkStrength == SinkStrength.TERMINAL_SIDE_EFFECT) {
            f.disposition = FindingDisposition.MAIN;
            return;
        }

        if (f.sinkStrength == SinkStrength.UNCLASSIFIED) {
            f.disposition = FindingDisposition.LOW_CONFIDENCE;
            f.addReason("UNCLASSIFIED_SINK");
            return;
        }

        f.disposition = FindingDisposition.MAIN;
    }

    private List<CanonicalFinding> fanInAggregate(List<CanonicalFinding> input) {
        List<String> fanRules = noiseFilter.getFanInRules();
        if (fanRules == null || fanRules.isEmpty()) {
            return input;
        }
        Map<String, CanonicalFinding> byLocation = new LinkedHashMap<>();
        List<CanonicalFinding> passthrough = new ArrayList<>();

        for (CanonicalFinding f : input) {
            if (f.disposition == FindingDisposition.SUPPRESSED) {
                passthrough.add(f);
                continue;
            }
            boolean fan = fanRules.stream().anyMatch(r ->
                    r != null && r.equalsIgnoreCase(f.ruleId));
            if (!fan) {
                passthrough.add(f);
                continue;
            }
            String loc = f.sinkLocationKey();
            CanonicalFinding agg = byLocation.get(loc);
            if (agg == null) {
                byLocation.put(loc, f);
            } else {
                for (FindingInstance inst : f.instances) {
                    agg.mergeInstance(inst);
                }
                if (rankDisposition(f.disposition) < rankDisposition(agg.disposition)) {
                    agg.disposition = f.disposition;
                }
                for (String r : f.reasonCodes) {
                    agg.addReason(r);
                }
            }
        }

        // Re-apply template demote after fan-in when sourceCount is high
        List<CanonicalFinding> out = new ArrayList<>(passthrough);
        for (CanonicalFinding f : byLocation.values()) {
            if (noiseFilter.isDemoteTemplateWithoutPathEvidence()
                    && isTemplateRule(f.ruleId)
                    && f.evidenceLevel == EvidenceLevel.ENDPOINT_ONLY
                    && f.sourceCount >= 3) {
                f.disposition = FindingDisposition.LOW_CONFIDENCE;
                f.addReason("TEMPLATE_HIGH_FAN_IN");
            }
            if (isSqlRule(f.ruleId) && f.sourceCount >= 5
                    && f.evidenceLevel == EvidenceLevel.ENDPOINT_ONLY) {
                f.addReason("SQL_HIGH_FAN_IN");
                // keep MAIN but confidence will drop
            }
            out.add(f);
        }
        return out;
    }

    private void sortInstances(CanonicalFinding f) {
        if (f.instances == null || f.instances.size() <= 1) {
            f.sourceCount = f.instances == null ? 0 : f.instances.size();
            return;
        }
        f.instances.sort(Comparator
                .comparing((FindingInstance i) -> !i.hasRoute)
                .thenComparingDouble(i -> -i.authBarrier)
                .thenComparing(i -> i.sourceContainerSignature == null
                        ? "" : i.sourceContainerSignature));
        f.sourceCount = f.instances.size();
    }

    private void score(CanonicalFinding f) {
        double base = f.sinkRule != null ? f.sinkRule.getBaseScore() : 5.0;
        FindingInstance rep = f.representative();
        double reach = (rep != null && rep.hasRoute) ? 1.0 : 0.1;
        double auth = rep != null ? rep.authBarrier : 1.0;

        // Severity = impact/exploitability only (no confidence fold-in)
        f.severityScore = base * reach * auth;

        double conf = 0.85;
        if ("OUTSIDE_FINDING_PACKAGES".equals(f.packageProvenance)) {
            conf *= 0.55;
        }
        if (f.sinkStrength == SinkStrength.CONSTRUCTOR
                || f.sinkStrength == SinkStrength.PARSER
                || f.sinkStrength == SinkStrength.INTERMEDIATE) {
            conf *= 0.35;
        }
        if (f.evidenceLevel == EvidenceLevel.LOCAL_SIDE_EFFECT) {
            conf = Math.min(1.0, conf + 0.25);
        }
        if (f.sourceCount >= 10) {
            conf *= 0.55;
        } else if (f.sourceCount >= 5) {
            conf *= 0.7;
        } else if (f.sourceCount >= 3) {
            conf *= 0.85;
        }
        if (f.reasonCodes.contains("PLAIN_JSON_PARSE")
                || f.reasonCodes.contains("TEMPLATE_NO_PATH_EVIDENCE")
                || f.reasonCodes.contains("TEMPLATE_HIGH_FAN_IN")) {
            conf = Math.min(conf, 0.35);
        }
        if (f.disposition == FindingDisposition.SUPPRESSED) {
            conf = Math.min(conf, 0.15);
        }
        f.confidenceScore = clamp01(conf);
        f.rankScore = f.severityScore * f.confidenceScore;

        // riskLevel reflects severity impact; low confidence is a separate property
        // and disposition (low-confidence.jsonl), not a rewritten "LOW impact" label.
        if (f.severityScore >= 9.0) {
            f.riskLevel = "CRITICAL";
        } else if (f.severityScore >= 7.0) {
            f.riskLevel = "HIGH";
        } else if (f.severityScore >= 4.0) {
            f.riskLevel = "MEDIUM";
        } else if (f.severityScore >= 1.0) {
            f.riskLevel = "LOW";
        } else {
            f.riskLevel = "INFO";
        }
        // Templates without evidence: keep severity but demote display tag for triage
        // only when still in LOW_CONFIDENCE disposition (not MAIN).
        if (isTemplateRule(f.ruleId)
                && f.evidenceLevel == EvidenceLevel.ENDPOINT_ONLY
                && f.disposition == FindingDisposition.LOW_CONFIDENCE
                && ("CRITICAL".equals(f.riskLevel) || "HIGH".equals(f.riskLevel))) {
            f.riskLevel = "LOW";
        }
    }

    private void place(PipelineResult result, CanonicalFinding f) {
        if (f.disposition == FindingDisposition.SUPPRESSED) {
            result.suppressedFindings.add(f);
            result.bumpReason(result.suppressedByReason, f.reasonCodes);
            return;
        }
        if (f.disposition == FindingDisposition.LOW_CONFIDENCE) {
            result.lowConfidenceFindings.add(f);
            result.bumpReason(result.lowConfidenceByReason, f.reasonCodes);
            return;
        }

        boolean terminal = f.sinkStrength == SinkStrength.TERMINAL_SIDE_EFFECT;
        boolean passConfidence = f.confidenceScore >= noiseFilter.getMainSarifMinConfidence();
        boolean passTerminal = terminal
                && noiseFilter.isMainSarifAlwaysIncludeTerminal()
                && !isTemplateRule(f.ruleId)
                && f.sinkStrength != SinkStrength.PARSER;

        if (passConfidence || passTerminal) {
            result.mainFindings.add(f);
            return;
        }

        f.disposition = FindingDisposition.LOW_CONFIDENCE;
        f.addReason("BELOW_MAIN_CONFIDENCE");
        result.lowConfidenceFindings.add(f);
        result.bumpReason(result.lowConfidenceByReason, f.reasonCodes);
    }

    private void bindRoute(FindingInstance inst) {
        if (inst.sourceContainerSignature == null) {
            return;
        }
        ApiRoute route = findRoute(inst.sourceContainerSignature);
        if (route == null) {
            inst.hasRoute = false;
            inst.authBarrier = 1.0;
            return;
        }
        inst.hasRoute = true;
        inst.routeHttpMethod = route.getHttpMethod();
        inst.routePath = route.getPath();
        // Auth without World: keyword heuristic on path/class + Permission-like param annotations
        inst.authBarrier = estimateAuthBarrier(route);
    }

    static double estimateAuthBarrier(ApiRoute route) {
        if (route == null) {
            return 1.0;
        }
        String blob = ((route.getClassName() != null ? route.getClassName() : "")
                + " " + (route.getPath() != null ? route.getPath() : "")
                + " " + (route.getMethodSig() != null ? route.getMethodSig() : ""))
                .toLowerCase(Locale.ROOT);
        if (blob.contains("public") || blob.contains("anon") || blob.contains("open")
                || blob.contains("permitall")) {
            return 1.0;
        }
        if (blob.contains("admin") || blob.contains("auth") || blob.contains("secure")
                || blob.contains("permission") || blob.contains("role")) {
            return 0.5;
        }
        if (route.getParamAnnotations() != null) {
            for (String ann : route.getParamAnnotations().values()) {
                if (ann == null) {
                    continue;
                }
                String a = ann.toLowerCase(Locale.ROOT);
                if (a.contains("permission") || a.contains("preauthorize")
                        || a.contains("secured") || a.contains("rolesallowed")) {
                    return 0.5;
                }
            }
        }
        return 1.0;
    }

    private ApiRoute findRoute(String sourceSignature) {
        Matcher m = SOURCE_SIG.matcher(sourceSignature.trim());
        if (!m.matches()) {
            return null;
        }
        String className = m.group(1);
        String methodWithParams = m.group(3);
        String methodName = methodNameOnly(methodWithParams);
        // 1) Exact class + method name token (avoids get matching getUser)
        for (ApiRoute r : routes) {
            if (r.getClassName() == null || r.getMethodSig() == null) {
                continue;
            }
            if (!r.getClassName().equals(className)) {
                continue;
            }
            if (methodName.equals(methodNameOnly(r.getMethodSig()))) {
                return r;
            }
        }
        // 2) Exact class + full "name(params)" if route stores full subsignature
        for (ApiRoute r : routes) {
            if (r.getClassName() != null && r.getClassName().equals(className)
                    && r.getMethodSig() != null
                    && (r.getMethodSig().equals(methodWithParams)
                    || r.getMethodSig().endsWith(" " + methodWithParams)
                    || r.getMethodSig().contains(methodWithParams))) {
                // only if method name token still exact
                if (methodName.equals(methodNameOnly(r.getMethodSig()))) {
                    return r;
                }
            }
        }
        return null;
    }

    static String methodNameOnly(String methodSigOrSubsig) {
        if (methodSigOrSubsig == null) {
            return "";
        }
        String s = methodSigOrSubsig.trim();
        // strip return type if present: "java.lang.String getUser(...)" or "getUser(...)"
        int paren = s.indexOf('(');
        String head = paren >= 0 ? s.substring(0, paren).trim() : s;
        int sp = head.lastIndexOf(' ');
        return sp >= 0 ? head.substring(sp + 1).trim() : head;
    }

    private SinkRule findSinkRule(CapturedTaintFlow flow) {
        if (flow == null) {
            return null;
        }
        String[] candidates = {
                flow.sinkRuleSignature,
                flow.declaredSinkSignature,
                flow.resolvedSinkSignature
        };
        for (String candidate : candidates) {
            if (candidate == null || candidate.isBlank()) {
                continue;
            }
            SinkRule rule = ruleManager.getRuleForSink(candidate);
            if (rule != null) {
                return rule;
            }
        }
        return null;
    }

    public static List<Vulnerability> toVulnerabilities(List<CanonicalFinding> findings) {
        List<Vulnerability> out = new ArrayList<>();
        if (findings == null) {
            return out;
        }
        for (CanonicalFinding f : findings) {
            out.add(toVulnerability(f));
        }
        return out;
    }

    public static List<Vulnerability> toVulnerabilities(List<CanonicalFinding> findings,
                                                        int maxInstancesInSarif) {
        List<Vulnerability> out = new ArrayList<>();
        if (findings == null) {
            return out;
        }
        int max = maxInstancesInSarif > 0 ? maxInstancesInSarif : Integer.MAX_VALUE;
        for (CanonicalFinding f : findings) {
            out.add(toVulnerability(f, max));
        }
        return out;
    }

    public static Vulnerability toVulnerability(CanonicalFinding f) {
        return toVulnerability(f, Integer.MAX_VALUE);
    }

    public static Vulnerability toVulnerability(CanonicalFinding f, int maxInstancesInTrace) {
        FindingInstance rep = f.representative();
        String source = rep != null && rep.sourceContainerSignature != null
                ? rep.sourceContainerSignature
                : "<unknown-source>";
        String sink = f.sinkRuleSignature != null ? f.sinkRuleSignature : "<unknown-sink>";

        List<String> trace = new ArrayList<>();
        int shown = 0;
        if (f.instances != null) {
            for (FindingInstance inst : f.instances) {
                if (shown >= maxInstancesInTrace) {
                    break;
                }
                String s = inst.sourceContainerSignature != null
                        ? inst.sourceContainerSignature : "<unknown-source>";
                if (inst.sourceIndex != null) {
                    s += " idx=" + inst.sourceIndex;
                }
                if (inst.routePath != null) {
                    s += " route=" + (inst.routeHttpMethod != null ? inst.routeHttpMethod + " " : "")
                            + inst.routePath;
                }
                trace.add(s + (shown == 0 ? " (Source/representative)" : " (Source/instance)"));
                shown++;
            }
        }
        if (trace.isEmpty()) {
            trace.add(source + " (Source)");
        }
        if (f.sourceCount > shown) {
            trace.add("sourceCount=" + f.sourceCount
                    + " shown=" + shown
                    + " (full instances in findings-main.jsonl)");
        }
        if (f.sinkContainerSignature != null
                && !f.sinkContainerSignature.isBlank()
                && !f.sinkContainerSignature.equals(source)) {
            String location = f.sinkContainerSignature;
            if (f.sinkLineNumber >= 0) {
                location += " @L" + f.sinkLineNumber;
            }
            location += " stmt#" + f.sinkStmtIndex;
            trace.add(location + " (Container)");
        }
        if (f.localFollowingSideEffects != null && !f.localFollowingSideEffects.isEmpty()) {
            trace.add("localSideEffects=" + f.localFollowingSideEffects);
        }
        trace.add(sink + " (Sink)");

        Vulnerability v = new Vulnerability(
                f.ruleId,
                source,
                sink,
                trace,
                f.evidenceLevel != EvidenceLevel.ENDPOINT_ONLY,
                f.sinkRule);
        // Prefer severity for human score; rank remains in properties
        v.setScore(f.severityScore);
        v.setConfidenceScore(f.confidenceScore);
        v.setRiskLevel(f.riskLevel);
        v.setSeverityScore(f.severityScore);
        v.setRankScore(f.rankScore);
        v.setSinkStrength(f.sinkStrength != null ? f.sinkStrength.name() : null);
        v.setEvidenceLevel(f.evidenceLevel != null ? f.evidenceLevel.name() : null);
        v.setSinkContainerSignature(f.sinkContainerSignature);
        v.setSinkStmtIndex(f.sinkStmtIndex);
        v.setSinkIndex(f.sinkIndex);
        v.setSourceIndex(rep != null ? rep.sourceIndex : null);
        v.setSourceCount(f.sourceCount);
        v.setReasonCodes(f.reasonCodes != null ? new ArrayList<>(f.reasonCodes) : null);
        v.setPackageProvenance(f.packageProvenance);
        return v;
    }

    private static List<String> resolveFindingPackages(ScanConfig sc) {
        if (sc.getFindingPackages() != null && !sc.getFindingPackages().isEmpty()) {
            return new ArrayList<>(sc.getFindingPackages());
        }
        return new ArrayList<>(sc.getScanPackages());
    }

    private static boolean matchesPackage(String className, List<String> packages) {
        if (className == null || className.isBlank() || packages == null) {
            return false;
        }
        for (String p : packages) {
            if (p == null || p.isBlank()) {
                continue;
            }
            String prefix = p.trim();
            if (className.equals(prefix) || className.startsWith(prefix + ".")) {
                return true;
            }
        }
        return false;
    }

    private static boolean isTemplateRule(String ruleId) {
        if (ruleId == null) {
            return false;
        }
        String r = ruleId.toLowerCase(Locale.ROOT);
        return r.contains("velocity") || r.contains("freemarker")
                || r.contains("thymeleaf") || r.contains("pebble")
                || r.contains("beetl") || r.contains("jinjava")
                || r.contains("mustache");
    }

    private static boolean isSqlRule(String ruleId) {
        if (ruleId == null) {
            return false;
        }
        String r = ruleId.toLowerCase(Locale.ROOT);
        return r.contains("sql");
    }

    private static int rankDisposition(FindingDisposition d) {
        if (d == FindingDisposition.MAIN) {
            return 0;
        }
        if (d == FindingDisposition.LOW_CONFIDENCE) {
            return 1;
        }
        return 2;
    }

    private static double clamp01(double v) {
        if (v < 0) {
            return 0;
        }
        if (v > 1) {
            return 1;
        }
        return v;
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }
}
