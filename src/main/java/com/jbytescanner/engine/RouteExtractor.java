package com.jbytescanner.engine;

import com.jbytescanner.model.ApiRoute;
import soot.*;
import soot.tagkit.AnnotationTag;
import soot.tagkit.VisibilityAnnotationTag;
import soot.tagkit.VisibilityParameterAnnotationTag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

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
    
    // Param Annotations
    private static final String ANN_REQUEST_BODY = "org.springframework.web.bind.annotation.RequestBody";
    private static final String ANN_REQUEST_PARAM = "org.springframework.web.bind.annotation.RequestParam";
    private static final String ANN_PATH_VARIABLE = "org.springframework.web.bind.annotation.PathVariable";

    // Servlet
    private static final String CLASS_HTTP_SERVLET = "javax.servlet.http.HttpServlet";
    private static final String ANN_WEB_SERVLET = "javax.servlet.annotation.WebServlet";

    private final List<String> filterAnnotations;
    private final List<String> scanJars;

    public RouteExtractor(List<String> filterAnnotations, List<String> scanJars) {
        this.filterAnnotations = filterAnnotations;
        this.scanJars = scanJars;
    }

    public List<ApiRoute> extract() {
        List<ApiRoute> routes = new ArrayList<>();
        
        // 0. Extract Routes from web.xml (Legacy/Hybrid)
        routes.addAll(extractWebXmlRoutes());

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
                // often defaults to ALL if not easily statically resolved.
                // For PoC, we default to GET if unknown, or try to parse 'method' attribute.
                List<String> methods = AnnotationHelper.getAnnotationValues(tag, "method");
                if (!methods.isEmpty()) {
                     httpMethod = methods.get(0).replace("RequestMethod.", "");
                } else {
                     httpMethod = "ALL"; 
                }
                
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
            } else if (AnnotationHelper.hasAnnotation(sm, ANN_PUT_MAPPING)) {
                AnnotationTag tag = AnnotationHelper.getAnnotation(sm, ANN_PUT_MAPPING);
                methodPaths.addAll(AnnotationHelper.getAnnotationValues(tag, "value"));
                methodPaths.addAll(AnnotationHelper.getAnnotationValues(tag, "path"));
                httpMethod = "PUT";
            } else if (AnnotationHelper.hasAnnotation(sm, ANN_DELETE_MAPPING)) {
                AnnotationTag tag = AnnotationHelper.getAnnotation(sm, ANN_DELETE_MAPPING);
                methodPaths.addAll(AnnotationHelper.getAnnotationValues(tag, "value"));
                methodPaths.addAll(AnnotationHelper.getAnnotationValues(tag, "path"));
                httpMethod = "DELETE";
            }

            if (httpMethod != null) {
                if (methodPaths.isEmpty()) methodPaths.add("");
                
                // Extract Parameters Info
                RouteMetadata metadata = extractRouteMetadata(sm);
                
                for (String cp : classPaths) {
                    for (String mp : methodPaths) {
                        String fullPath = combinePaths(cp, mp);
                        
                        ApiRoute route = new ApiRoute(
                            httpMethod, fullPath, sc.getName(), sm.getSubSignature(),
                            metadata.parameters, metadata.paramAnnotations, metadata.contentType
                        );
                        routes.add(route);
                    }
                }
            }
        }
        return routes;
    }

    private List<ApiRoute> extractWebXmlRoutes() {
        List<ApiRoute> routes = new ArrayList<>();
        if (scanJars == null || scanJars.isEmpty()) return routes;
        
        WebXmlParser parser = new WebXmlParser();
        for (String jarPath : scanJars) {
            Map<String, List<String>> webXmlRoutes = parser.parse(new java.io.File(jarPath));
            
            for (Map.Entry<String, List<String>> entry : webXmlRoutes.entrySet()) {
                String className = entry.getKey();
                List<String> paths = entry.getValue();
                
                // Verify if class is in Soot (Optional, but good for validation)
                // If the class is a library class, it might not be in "ApplicationClasses" but in "Scene.v().getClasses()"
                // We add it regardless, because web.xml is an explicit definition.
                
                for (String path : paths) {
                    // Create a route for ALL methods since web.xml maps the servlet generally
                    routes.add(new ApiRoute(
                        "ALL", 
                        path, 
                        className, 
                        "service", // Method name placeholder
                        new ArrayList<>(), // No params known from web.xml
                        new HashMap<>(), 
                        "application/x-www-form-urlencoded"
                    ));
                }
            }
        }
        return routes;
    }

    private String combinePaths(String p1, String p2) {
        if (!p1.startsWith("/")) p1 = "/" + p1;
        if (!p2.startsWith("/") && !p2.isEmpty()) p2 = "/" + p2;
        if (p1.endsWith("/") && p2.startsWith("/")) return p1 + p2.substring(1);
        if (p1.equals("/") && p2.startsWith("/")) return p2; // Avoid //api
        return p1 + p2;
    }
    
    // --- Phase 8.3 Metadata Extraction ---
    
    private static class RouteMetadata {
        List<String> parameters = new ArrayList<>();
        Map<String, String> paramAnnotations = new HashMap<>();
        String contentType = "application/x-www-form-urlencoded"; // Default
    }

    private RouteMetadata extractRouteMetadata(SootMethod sm) {
        RouteMetadata meta = new RouteMetadata();
        
        // 1. Basic Parameter Info (Name:Type)
        // Try to get names from ActiveBody (LocalVariableTable) if available
        List<String> paramNames = new ArrayList<>();
        try {
            if (sm.hasActiveBody()) {
                // Not reliable for interfaces/abstract, but Controllers usually have bodies
                // However, without debug info (-g:vars), names are arg0, arg1...
                // Spring uses -parameters flag usually.
                // We rely on simple counting for now: arg0...
            }
        } catch (Exception e) {}
        
        // 2. Annotation Analysis (VisibilityParameterAnnotationTag)
        // Format: Tag -> Annotations[] -> Annotation
        VisibilityParameterAnnotationTag tag = (VisibilityParameterAnnotationTag) sm.getTag("VisibilityParameterAnnotationTag");
        
        int paramCount = sm.getParameterCount();
        for (int i = 0; i < paramCount; i++) {
            String name = "arg" + i; 
            Type type = sm.getParameterType(i);
            meta.parameters.add(name + ":" + type.toString());
            
            // Check for Multipart
            if (type.toString().contains("MultipartFile")) {
                meta.contentType = "multipart/form-data";
            }

            if (tag != null && tag.getVisibilityAnnotations() != null && i < tag.getVisibilityAnnotations().size()) {
                VisibilityAnnotationTag paramTags = tag.getVisibilityAnnotations().get(i);
                if (paramTags != null && paramTags.getAnnotations() != null) {
                    for (AnnotationTag at : paramTags.getAnnotations()) {
                        String typeName = at.getType().replace("/", ".").replace(";", "");
                        if (typeName.startsWith("L")) typeName = typeName.substring(1); // Remove L prefix

                        if (typeName.equals(ANN_REQUEST_BODY)) {
                            meta.paramAnnotations.put(name, "RequestBody");
                            meta.contentType = "application/json";
                        } else if (typeName.equals(ANN_REQUEST_PARAM)) {
                            meta.paramAnnotations.put(name, "RequestParam");
                            // If we have @RequestParam("alias"), we should extract it.
                            // But parsing annotation values here is complex (requires searching elems).
                            // For MVP, we stick to argX or rely on parameter name preservation.
                        } else if (typeName.equals(ANN_PATH_VARIABLE)) {
                            meta.paramAnnotations.put(name, "PathVariable");
                        }
                    }
                }
            }
        }
        
        return meta;
    }
}
