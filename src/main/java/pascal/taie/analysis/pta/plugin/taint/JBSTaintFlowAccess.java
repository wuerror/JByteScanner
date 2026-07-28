package pascal.taie.analysis.pta.plugin.taint;

import com.jbytescanner.worker.CapturedTaintFlow;
import pascal.taie.ir.exp.InvokeInstanceExp;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.ir.stmt.Stmt;
import pascal.taie.language.classes.JMethod;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Package bridge for extracting a stable, JSON-safe snapshot from Tai-e 0.5.4.
 *
 * <p>Tai-e intentionally keeps SourcePoint/SinkPoint package-private. Keeping
 * this tiny adapter in Tai-e's package avoids reflection while isolating the
 * version-specific access in one place.</p>
 */
public final class JBSTaintFlowAccess {

    /** Network side effects on URL / URLConnection receivers only. */
    private static final Set<String> URL_NETWORK_METHODS = Set.of(
            "openstream", "openconnection", "getinputstream", "getcontent"
    );

    private static final Set<String> URL_OWNERS = Set.of(
            "java.net.URL",
            "java.net.URLConnection",
            "java.net.HttpURLConnection",
            "javax.net.ssl.HttpsURLConnection"
    );

    private static final Set<String> FILE_SIDE_EFFECTS = Set.of(
            "read", "write", "delete", "createNewFile", "mkdir", "mkdirs",
            "renameTo", "list", "listFiles"
    );

    private JBSTaintFlowAccess() {
    }

    public static CapturedTaintFlow snapshot(TaintFlow flow) {
        SourcePoint sourcePoint = flow.sourcePoint();
        SinkPoint sinkPoint = flow.sinkPoint();
        Invoke sinkCall = sinkPoint.sinkCall();
        Sink configuredSink = sinkPoint.sink();

        CapturedTaintFlow result = new CapturedTaintFlow();
        result.sourceContainerSignature = signature(sourcePoint.getContainer());
        result.sourceRuleSignature = sourceRuleSignature(sourcePoint);
        result.sourceKind = sourcePoint.getClass().getSimpleName();
        result.sourceIndex = sourceIndex(sourcePoint);

        result.sinkRuleSignature = signature(configuredSink.method());
        result.sinkIndex = configuredSink.indexRef() != null
                ? configuredSink.indexRef().toString()
                : null;

        result.sinkContainerSignature = signature(sinkCall.getContainer());
        result.declaredSinkSignature = sinkCall.getMethodRef().toString();
        JMethod resolved = sinkCall.getMethodRef().resolveNullable();
        result.resolvedSinkSignature = signature(resolved);
        result.sinkStmtIndex = sinkCall.getIndex();
        result.sinkLineNumber = sinkCall.getLineNumber();
        result.invokeText = sinkCall.toString();
        result.rawFlow = flow.toString();
        result.localFollowingSideEffects = collectLocalSideEffects(sinkCall);
        return result;
    }

    /**
     * Same-method following invokes that look like network/file side effects
     * on the same constructed receiver when resolvable.
     */
    static List<String> collectLocalSideEffects(Invoke sinkCall) {
        List<String> effects = new ArrayList<>();
        if (sinkCall == null) {
            return effects;
        }
        JMethod container = sinkCall.getContainer();
        if (container == null || container.isAbstract() || container.isNative()) {
            return effects;
        }
        pascal.taie.ir.IR ir;
        try {
            ir = container.getIR();
        } catch (Throwable ignored) {
            return effects;
        }
        if (ir == null) {
            return effects;
        }
        String sinkName = sinkCall.getMethodRef().getName();
        boolean constructorSink = "<init>".equals(sinkName);
        if (!constructorSink) {
            return effects;
        }
        String sinkOwner = sinkCall.getMethodRef().getDeclaringClass().getName();
        boolean urlOrUri = "java.net.URL".equals(sinkOwner) || "java.net.URI".equals(sinkOwner);
        boolean fileLike = "java.io.File".equals(sinkOwner)
                || "java.nio.file.Paths".equals(sinkOwner)
                || "java.nio.file.Path".equals(sinkOwner);
        if (!urlOrUri && !fileLike) {
            return effects;
        }

        Var constructed = receiverOf(sinkCall);
        int sinkIdx = sinkCall.getIndex();
        Set<String> seen = new LinkedHashSet<>();
        for (Stmt stmt : ir) {
            if (!(stmt instanceof Invoke inv)) {
                continue;
            }
            if (inv.getIndex() <= sinkIdx) {
                continue;
            }
            String name = inv.getMethodRef().getName();
            String owner = inv.getMethodRef().getDeclaringClass().getName();
            String nameLower = name.toLowerCase(Locale.ROOT);
            String key = owner + "#" + name;

            if (urlOrUri) {
                boolean urlFamily = URL_OWNERS.contains(owner)
                        || owner.endsWith("URLConnection")
                        || "java.net.URL".equals(owner);
                if (!urlFamily || !URL_NETWORK_METHODS.contains(nameLower)) {
                    continue;
                }
                // Require same receiver when both sides are known. Do not whitelist
                // openStream/openConnection against a different local (false SSRF upgrade).
                if (constructed != null) {
                    Var invRecv = receiverOf(inv);
                    if (invRecv != null && !invRecv.equals(constructed)) {
                        continue;
                    }
                    // If invoke has no instance base, skip — cannot prove same object.
                    if (invRecv == null && inv.getInvokeExp() instanceof InvokeInstanceExp) {
                        continue;
                    }
                }
                if (seen.add(key)) {
                    effects.add(name);
                }
            } else if (fileLike) {
                if (!(FILE_SIDE_EFFECTS.contains(name)
                        || nameLower.startsWith("read")
                        || nameLower.startsWith("write")
                        || nameLower.startsWith("delete"))) {
                    continue;
                }
                if (constructed != null) {
                    Var invRecv = receiverOf(inv);
                    if (invRecv != null && !invRecv.equals(constructed)) {
                        continue;
                    }
                    if (invRecv == null && inv.getInvokeExp() instanceof InvokeInstanceExp) {
                        continue;
                    }
                }
                if (seen.add(key)) {
                    effects.add(name);
                }
            }
        }
        return effects;
    }

    private static Var receiverOf(Invoke invoke) {
        if (invoke == null || invoke.getInvokeExp() == null) {
            return null;
        }
        if (invoke.getInvokeExp() instanceof InvokeInstanceExp inst) {
            return inst.getBase();
        }
        return null;
    }

    private static String sourceRuleSignature(SourcePoint sourcePoint) {
        if (sourcePoint instanceof ParamSourcePoint param) {
            return signature(param.source().method());
        }
        if (sourcePoint instanceof CallSourcePoint call) {
            return signature(call.source().method());
        }
        if (sourcePoint instanceof FieldSourcePoint field) {
            return field.source().field().getSignature();
        }
        return null;
    }

    private static String sourceIndex(SourcePoint sourcePoint) {
        if (sourcePoint instanceof ParamSourcePoint param) {
            return param.indexRef().toString();
        }
        if (sourcePoint instanceof CallSourcePoint call) {
            return call.indexRef().toString();
        }
        return null;
    }

    private static String signature(JMethod method) {
        return method != null ? method.getSignature() : null;
    }
}
