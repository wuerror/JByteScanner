package com.jbytescanner.diagnose;

public record DiagnosisOptions(
        String sinkSignature,
        String sinkIndex,
        String sourceSignature,
        String sourceIndex,
        int maxCallers,
        int maxTargetInvokes,
        boolean runWorker
) {
    public DiagnosisOptions {
        if (maxCallers <= 0) {
            maxCallers = 200;
        }
        if (maxTargetInvokes <= 0) {
            maxTargetInvokes = 200;
        }
    }
}
