package com.jbytescanner.analysis;

import soot.SootMethod;
import java.util.BitSet;
import java.util.Objects;

/**
 * Represents the state of analysis at a method entry point.
 * Used for memoization to prevent infinite recursion and redundant analysis.
 * Replaces the inefficient String-based key.
 */
public class AnalysisState {
    private final SootMethod method;
    // BitSet representing indices of tainted parameters.
    // Index 0 = 1st parameter, Index 1 = 2nd parameter, etc.
    private final BitSet taintedParams;

    public AnalysisState(SootMethod method, BitSet taintedParams) {
        this.method = method;
        // Store a clone to ensure immutability if the caller modifies the passed BitSet
        this.taintedParams = (BitSet) taintedParams.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AnalysisState that = (AnalysisState) o;
        return Objects.equals(method, that.method) &&
               Objects.equals(taintedParams, that.taintedParams);
    }

    @Override
    public int hashCode() {
        return Objects.hash(method, taintedParams);
    }

    @Override
    public String toString() {
        return method.getSignature() + " taintedArgs:" + taintedParams;
    }
}
