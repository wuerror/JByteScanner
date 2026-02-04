package com.jbytescanner.analysis;

import java.util.BitSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

/**
 * Capture the taint behavior of a method.
 * Used to speed up analysis by avoiding re-analyzing the same method body.
 */
public class MethodSummary {
    private final String methodSignature;
    
    // BitSet indicating which parameters flow to the return value.
    // Index i corresponds to the i-th parameter.
    private final BitSet paramsToReturn = new BitSet();
    
    // BitSet indicating which parameters pollute 'this' object.
    private final BitSet paramsToThis = new BitSet();
    
    // Tracks if 'this' flows to return value (e.g., chained setters return this)
    private boolean thisToReturn = false;

    // Map parameter index to a set of Sink Signatures it reaches.
    // This allows us to report vulnerabilities in the caller context.
    private final Map<Integer, Set<String>> paramsToSinks = new HashMap<>();

    public MethodSummary(String methodSignature) {
        this.methodSignature = methodSignature;
    }

    public void addParamToReturnFlow(int paramIndex) {
        paramsToReturn.set(paramIndex);
    }
    
    public boolean flowsToReturn(int paramIndex) {
        return paramsToReturn.get(paramIndex);
    }
    
    public void addParamToThisFlow(int paramIndex) {
        paramsToThis.set(paramIndex);
    }
    
    public boolean flowsToThis(int paramIndex) {
        return paramsToThis.get(paramIndex);
    }

    public void setThisToReturn(boolean flows) {
        this.thisToReturn = flows;
    }

    public boolean isThisToReturn() {
        return thisToReturn;
    }

    public void addSinkReachability(int paramIndex, String sinkSignature) {
        paramsToSinks.computeIfAbsent(paramIndex, k -> new HashSet<>()).add(sinkSignature);
    }

    public Set<String> getReachedSinks(int paramIndex) {
        return paramsToSinks.getOrDefault(paramIndex, new HashSet<>());
    }

    public String getMethodSignature() {
        return methodSignature;
    }
    
    @Override
    public String toString() {
        return "Summary{" + methodSignature + 
               " | P->Ret: " + paramsToReturn + 
               " | P->This: " + paramsToThis + 
               " | This->Ret: " + thisToReturn + 
               "}";
    }
}
