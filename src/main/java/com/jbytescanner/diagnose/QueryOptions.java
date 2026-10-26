package com.jbytescanner.diagnose;

public record QueryOptions(
        String what,
        String sinkSignature,
        String sinkIndex,
        String sourceSignature,
        String sourceIndex,
        int limit
) {
    public QueryOptions {
        if (limit <= 0) {
            limit = 500;
        }
    }
}
