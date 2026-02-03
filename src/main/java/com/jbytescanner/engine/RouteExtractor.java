package com.jbytescanner.engine;

import com.jbytescanner.model.ApiRoute;
import soot.*;
import soot.tagkit.AnnotationTag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class RouteExtractor {
    private static final Logger logger = LoggerFactory.getLogger(RouteExtractor.class);

    // Spring Annotations
    private static final String ANN_REST_CONTROLLER = "org.springframework.web.bind.annotation.RestController";
    private static final String ANN_CONTROLLER = "org.springframework.stereotype.Controller";
    private static final String ANN_REQUEST_MAPPING = "org.springframework.web.bind.annotation.RequestMapping";
    private static final String ANN_GET_MAPPING = "org.springframework.web.bind.annotation.GetMapping";
    private static final String ANN_POST_MAPPING = "org.springframework.web.bind.annotation.PostMapping";
    private static final String ANN_PUT_MAPPING = "org.springframework.web.bind.annotation.PutMapping";
    private static final String ANN_DELETE_MAPPING = "org.springframework.web.bind.annotation.DeleteMapping";

    // Servlet
    private static final String CLASS_HTTP_SERVLET = "javax.servlet.http.HttpServlet";
    private static final String ANN_WEB_SERVLET = "javax.servlet.annotation.WebServlet";

    private final List<String> filterAnnotations;

    public RouteExtractor(List<String> filterAnnotations) {
        this.filterAnnotations = filterAnnotations;
    }

    public List<ApiRoute> extract() {
        List<ApiRoute> routes = new ArrayList<>();
        
        for (SootClass sc : Scene.v().getApplicationClasses()) {
            if (sc.isPhantom()) continue;
            
            // 1. Check Spring Controller
            if (AnnotationHelper.hasAnnotation(sc, ANN_REST_CONTROLLER) || 
                AnnotationHelper.hasAnnotation(sc, ANN_CONTROLLER)) {
                routes.addAll(extractSpringRoutes(sc));
            }
            
            // 2. Check Servlet
            if (isServlet(sc)) {
                routes.addAll(extractServletRoutes(sc));
            }
        }
        
        return routes;
    }

    private boolean isServlet(SootClass sc) {
        // Check annotation
        if (AnnotationHelper.hasAnnotation(sc, ANN_WEB_SERVLET)) return true;
        
        // Check hierarchy
        SootClass current = sc;
        while (current.hasSuperclass()) {
            current = current.getSuperclass();
            if (current.getName().equals(CLASS_HTTP_SERVLET)) return true;
            if (current.getName().equals("java.lang.Object")) break;
        }
        return false;
    }

    private List<ApiRoute> extractServletRoutes(SootClass sc) {
        List<ApiRoute> routes = new ArrayList<>();
        
        // Filter Check (Servlet is class-level mostly)
        if (filterAnnotations != null && !filterAnnotations.isEmpty()) {
            if (!AnnotationHelper.hasAnnotationContaining(sc, filterAnnotations)) {
                return routes; // Skip if class doesn't have the annotation
            }
        }

        AnnotationTag webServlet = AnnotationHelper.getAnnotation(sc, ANN_WEB_SERVLET);
        List<String> paths = new ArrayList<>();
        
        if (webServlet != null) {
            // Try "value" or "urlPatterns"
            paths.addAll(AnnotationHelper.getAnnotationValues(webServlet, "value"));
            paths.addAll(AnnotationHelper.getAnnotationValues(webServlet, "urlPatterns"));
        }
        
        if (paths.isEmpty()) {
            // Fallback: If defined in web.xml (not implemented in Phase 2 lightweight scan), or default mapping
            // We just return class name as path indicator for manual review
            paths.add("/servlet/" + sc.getShortName()); 
        }

        for (String path : paths) {
            routes.add(new ApiRoute("ALL", path, sc.getName(), "service"));
        }
        return routes;
    }

    private List<ApiRoute> extractSpringRoutes(SootClass sc) {
        List<ApiRoute> routes = new ArrayList<>();
        
        // Check Class Level Annotations for filter
        boolean classMatchesFilter = false;
        if (filterAnnotations != null && !filterAnnotations.isEmpty()) {
            classMatchesFilter = AnnotationHelper.hasAnnotationContaining(sc, filterAnnotations);
        }

        // Class-level path
        List<String> classPaths = new ArrayList<>();
        AnnotationTag classMapping = AnnotationHelper.getAnnotation(sc, ANN_REQUEST_MAPPING);
        if (classMapping != null) {
            classPaths.addAll(AnnotationHelper.getAnnotationValues(classMapping, "value"));
            classPaths.addAll(AnnotationHelper.getAnnotationValues(classMapping, "path"));
        }
        if (classPaths.isEmpty()) classPaths.add(""); // Default to root if no path at class level

        // Method-level paths
        for (SootMethod sm : sc.getMethods()) {
            
            // Filter Check: If filter is active, either Class OR Method must match
            if (filterAnnotations != null && !filterAnnotations.isEmpty()) {
                boolean methodMatchesFilter = AnnotationHelper.hasAnnotationContaining(sm, filterAnnotations);
                if (!classMatchesFilter && !methodMatchesFilter) {
                    continue; // Skip this method
                }
            }

            String httpMethod = null;
            List<String> methodPaths = new ArrayList<>();
            
            if (AnnotationHelper.hasAnnotation(sm, ANN_REQUEST_MAPPING)) {
                AnnotationTag tag = AnnotationHelper.getAnnotation(sm, ANN_REQUEST_MAPPING);
                methodPaths.addAll(AnnotationHelper.getAnnotationValues(tag, "value"));
                methodPaths.addAll(AnnotationHelper.getAnnotationValues(tag, "path"));
                // Attempt to extract method from RequestMethod enum is complex in bytecode, 
                // often defaults to ALL if not easily statically resolved
                httpMethod = "ALL"; 
            } else if (AnnotationHelper.hasAnnotation(sm, ANN_GET_MAPPING)) {
                AnnotationTag tag = AnnotationHelper.getAnnotation(sm, ANN_GET_MAPPING);
                methodPaths.addAll(AnnotationHelper.getAnnotationValues(tag, "value"));
                methodPaths.addAll(AnnotationHelper.getAnnotationValues(tag, "path"));
                httpMethod = "GET";
            } else if (AnnotationHelper.hasAnnotation(sm, ANN_POST_MAPPING)) {
                AnnotationTag tag = AnnotationHelper.getAnnotation(sm, ANN_POST_MAPPING);
                methodPaths.addAll(AnnotationHelper.getAnnotationValues(tag, "value"));
                methodPaths.addAll(AnnotationHelper.getAnnotationValues(tag, "path"));
                httpMethod = "POST";
            }
            // Add PUT, DELETE similarly...

            if (httpMethod != null) {
                if (methodPaths.isEmpty()) methodPaths.add("");
                
                for (String cp : classPaths) {
                    for (String mp : methodPaths) {
                        String fullPath = combinePaths(cp, mp);
                        routes.add(new ApiRoute(httpMethod, fullPath, sc.getName(), sm.getSubSignature()));
                    }
                }
            }
        }
        return routes;
    }

    private String combinePaths(String p1, String p2) {
        if (!p1.startsWith("/")) p1 = "/" + p1;
        if (!p2.startsWith("/") && !p2.isEmpty()) p2 = "/" + p2;
        if (p1.endsWith("/") && p2.startsWith("/")) return p1 + p2.substring(1);
        return p1 + p2;
    }
}
