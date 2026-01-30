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

    public void findPathToSink(String sinkSignature) {
        logger.info("Searching for paths to sink: {}", sinkSignature);
        
        // Find sink method
        // In real impl, we match against list of sinks from rules.yaml
        // Here we just do a string contains check on signature for demo
        
        // BFS from EntryPoints
        Queue<List<Edge>> queue = new LinkedList<>();
        Set<SootMethod> visited = new HashSet<>();
        
        // Find dummy main
        Iterator<Edge> edges = cg.iterator();
        while (edges.hasNext()) {
            Edge e = edges.next();
            if (e.src().getName().equals("main") && 
                e.src().getDeclaringClass().getName().equals("com.jbytescanner.DummyMain")) {
                List<Edge> path = new ArrayList<>();
                path.add(e);
                queue.add(path);
                visited.add(e.src());
            }
        }

        int pathsFound = 0;
        int maxPaths = 5; // Limit output

        while (!queue.isEmpty() && pathsFound < maxPaths) {
            List<Edge> currentPath = queue.poll();
            Edge lastEdge = currentPath.get(currentPath.size() - 1);
            SootMethod currentMethod = lastEdge.tgt();

            // Check if sink
            if (currentMethod.getSignature().contains(sinkSignature)) {
                logger.warn("!!! FOUND PATH TO SINK !!!");
                printPath(currentPath);
                pathsFound++;
                continue;
            }

            if (currentPath.size() > 10) continue; // Depth limit
            if (visited.contains(currentMethod)) continue;
            visited.add(currentMethod);

            Iterator<Edge> outEdges = cg.edgesOutOf(currentMethod);
            while (outEdges.hasNext()) {
                Edge out = outEdges.next();
                List<Edge> newPath = new ArrayList<>(currentPath);
                newPath.add(out);
                queue.add(newPath);
            }
        }
        
        if (pathsFound == 0) {
            logger.info("No paths found to {}", sinkSignature);
        }
    }

    private void printPath(List<Edge> path) {
        StringBuilder sb = new StringBuilder();
        sb.append("\n[Trace]\n");
        for (Edge e : path) {
            sb.append("  -> ").append(e.tgt().getSignature()).append("\n");
        }
        logger.warn(sb.toString());
    }
}
