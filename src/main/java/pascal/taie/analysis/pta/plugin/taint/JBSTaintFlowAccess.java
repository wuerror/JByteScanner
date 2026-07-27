package pascal.taie.analysis.pta.plugin.taint;

import com.jbytescanner.worker.CapturedTaintFlow;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.language.classes.JMethod;

/**
 * Package bridge for extracting a stable, JSON-safe snapshot from Tai-e 0.5.4.
 *
 * <p>Tai-e intentionally keeps SourcePoint/SinkPoint package-private. Keeping
 * this tiny adapter in Tai-e's package avoids reflection while isolating the
 * version-specific access in one place.</p>
 */
public final class JBSTaintFlowAccess {

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

        // This is the exact method from the sink configuration, even when the
        // call site is invokeinterface/invokevirtual or dispatches to an override.
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
        return result;
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
