package com.jbytescanner.graph;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.MethodOrMethodContext;
import soot.SootMethod;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

import java.util.*;

public class ReachabilityAnalyzer {
    private static final Logger logger = LoggerFactory.getLogger(ReachabilityAnalyzer.class);
    private final CallGraph cg;

    public ReachabilityAnalyzer(CallGraph cg) {
        this.cg = cg;
    }

    public Set<SootMethod> computeBackwardReachability(Set<SootMethod> sinks) {
        logger.info("Starting Backward Reachability Analysis from {} sinks...", sinks.size());
        
        Set<SootMethod> reachableMethods = new HashSet<>(sinks);
        Queue<SootMethod> queue = new LinkedList<>(sinks);
        
        while (!queue.isEmpty()) {
            SootMethod current = queue.poll();
            
            Iterator<Edge> sources = cg.edgesInto(current);
            while (sources.hasNext()) {
                Edge edge = sources.next();
                SootMethod caller = edge.src();
                
                if (caller != null && !reachableMethods.contains(caller)) {
                    reachableMethods.add(caller);
                    queue.add(caller);
                }
            }
        }
        
        logger.info("Backward Reachability Analysis Complete. {} methods can reach sinks.", reachableMethods.size());
        return reachableMethods;
    }

}
