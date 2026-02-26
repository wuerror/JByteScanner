package com.jbytescanner.engine;

import com.jbytescanner.model.ApiRoute;
import pascal.taie.World;
import pascal.taie.language.classes.JClass;
import pascal.taie.language.classes.JMethod;
import pascal.taie.language.annotation.Annotation;
import pascal.taie.language.annotation.Element;
import pascal.taie.language.annotation.ArrayElement;
import pascal.taie.language.annotation.StringElement;
import pascal.taie.language.type.Type;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Collection;

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

    // JAX-RS Annotations
    private static final String ANN_PATH = "javax.ws.rs.Path";
    private static final String ANN_GET = "javax.ws.rs.GET";
    private static final String ANN_POST = "javax.ws.rs.POST";
    private static final String ANN_PUT = "javax.ws.rs.PUT";
    private static final String ANN_DELETE = "javax.ws.rs.DELETE";
    private static final String ANN_HEAD = "javax.ws.rs.HEAD";
    private static final String ANN_OPTIONS = "javax.ws.rs.OPTIONS";
    private static final String ANN_PATCH = "javax.ws.rs.PATCH";
    private static final String ANN_CONSUMES = "javax.ws.rs.Consumes";
    private static final String ANN_PRODUCES = "javax.ws.rs.Produces";
    
    // JAX-RS Param Annotations
    private static final String ANN_QUERY_PARAM = "javax.ws.rs.QueryParam";
    private static final String ANN_PATH_PARAM = "javax.ws.rs.PathParam";
    private static final String ANN_HEADER_PARAM = "javax.ws.rs.HeaderParam";
    private static final String ANN_FORM_PARAM = "javax.ws.rs.FormParam";
    private static final String ANN_COOKIE_PARAM = "javax.ws.rs.CookieParam";
    private static final String ANN_MATRIX_PARAM = "javax.ws.rs.MatrixParam";

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

        // PERFORMANCE OPTIMIZATION 1: World.get().getClassHierarchy().applicationClasses() 
        // Only returns classes from --app-class-path (targetAppJars) if configured correctly in TaieManager.
        for (JClass sc : World.get().getClassHierarchy().applicationClasses().collect(Collectors.toList())) {
            
            // 1. Check Spring Controller
            if (hasAnnotation(sc, ANN_REST_CONTROLLER) || hasAnnotation(sc, ANN_CONTROLLER)) {
                routes.addAll(extractSpringRoutes(sc));
            }
            
            // 2. Check Servlet
            if (isServlet(sc)) {
                routes.addAll(extractServletRoutes(sc));
            }
            
            // 3. Check JAX-RS Resources
            if (hasJaxRsAnnotations(sc)) {
                routes.addAll(extractJaxrsRoutes(sc));
            }
        }

        return routes;
    }
    
    // Helper to check if a class has a specific annotation
    private boolean hasAnnotation(JClass clazz, String annotationType) {
        return clazz.hasAnnotation(annotationType);
    }
    
    private boolean hasAnnotation(JMethod method, String annotationType) {
        return method.hasAnnotation(annotationType);
    }
    
    // Helper to get annotation values
    private List<String> getAnnotationValues(Annotation annotation, String key) {
        List<String> values = new ArrayList<>();
        if (annotation == null) return values;
        
        Element element = annotation.getElement(key);
        if (element != null) {
            if (element instanceof ArrayElement) {
                for (Element el : ((ArrayElement) element).getElements()) {
                    if (el instanceof StringElement) {
                        values.add(((StringElement) el).getValue());
                    }
                }
            } else if (element instanceof StringElement) {
                values.add(((StringElement) element).getValue());
            }
        }
        return values;
    }
    
    private boolean hasAnnotationContaining(JClass sc, List<String> filters) {
        if (filters == null || filters.isEmpty()) return true;
        Collection<Annotation> annotations = sc.getAnnotations();
        for (Annotation a : annotations) {
            String type = a.getType();
            for (String f : filters) {
                if (type.contains(f)) return true;
            }
        }
        return false;
    }

    private boolean hasAnnotationContaining(JMethod sm, List<String> filters) {
        if (filters == null || filters.isEmpty()) return true;
        Collection<Annotation> annotations = sm.getAnnotations();
        for (Annotation a : annotations) {
            String type = a.getType();
            for (String f : filters) {
                if (type.contains(f)) return true;
            }
        }
        return false;
    }

    private boolean hasJaxRsAnnotations(JClass sc) {
        if (hasAnnotation(sc, ANN_PATH)) {
            return true;
        }
        for (JMethod sm : sc.getDeclaredMethods()) {
            if (hasAnnotation(sm, ANN_GET) ||
                hasAnnotation(sm, ANN_POST) ||
                hasAnnotation(sm, ANN_PUT) ||
                hasAnnotation(sm, ANN_DELETE) ||
                hasAnnotation(sm, ANN_HEAD) ||
                hasAnnotation(sm, ANN_OPTIONS) ||
                hasAnnotation(sm, ANN_PATCH) ||
                hasAnnotation(sm, ANN_PATH)) {
                return true;
            }
        }
        return false;
    }

    private List<ApiRoute> extractJaxrsRoutes(JClass sc) {
        List<ApiRoute> routes = new ArrayList<>();

        Annotation classPathAnnotation = sc.getAnnotation(ANN_PATH);
        List<String> classPaths = new ArrayList<>();
        
        if (classPathAnnotation != null) {
            classPaths.addAll(getAnnotationValues(classPathAnnotation, "value"));
            if (classPaths.isEmpty()) {
                classPaths.add("");
            }
        } else {
            classPaths.add("");
        }

        boolean classMatchesFilter = false;
        if (filterAnnotations != null && !filterAnnotations.isEmpty()) {
            classMatchesFilter = hasAnnotationContaining(sc, filterAnnotations);
        }

        for (JMethod sm : sc.getDeclaredMethods()) {
            String httpMethod = null;
            List<String> methodPaths = new ArrayList<>();
            
            if (hasAnnotation(sm, ANN_GET)) httpMethod = "GET";
            else if (hasAnnotation(sm, ANN_POST)) httpMethod = "POST";
            else if (hasAnnotation(sm, ANN_PUT)) httpMethod = "PUT";
            else if (hasAnnotation(sm, ANN_DELETE)) httpMethod = "DELETE";
            else if (hasAnnotation(sm, ANN_HEAD)) httpMethod = "HEAD";
            else if (hasAnnotation(sm, ANN_OPTIONS)) httpMethod = "OPTIONS";
            else if (hasAnnotation(sm, ANN_PATCH)) httpMethod = "PATCH";

            Annotation methodPathAnnotation = sm.getAnnotation(ANN_PATH);
            if (methodPathAnnotation != null) {
                methodPaths.addAll(getAnnotationValues(methodPathAnnotation, "value"));
                if (methodPaths.isEmpty()) {
                    methodPaths.add(""); 
                }
                if (httpMethod == null) {
                    httpMethod = "GET";
                }
            } else if (httpMethod != null) {
                methodPaths.add("");
            }

            if (filterAnnotations != null && !filterAnnotations.isEmpty()) {
                boolean methodMatchesFilter = hasAnnotationContaining(sm, filterAnnotations);
                if (!classMatchesFilter && !methodMatchesFilter) {
                    continue; 
                }
            }

            if (httpMethod != null && !methodPaths.isEmpty()) {
                RouteMetadata metadata = extractJaxrsRouteMetadata(sm);

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

    private boolean isServlet(JClass sc) {
        if (hasAnnotation(sc, ANN_WEB_SERVLET)) return true;
        
        JClass current = sc;
        while (current != null && current.getSuperClass() != null) {
            current = current.getSuperClass();
            if (current.getName().equals(CLASS_HTTP_SERVLET)) return true;
            if (current.getName().equals("java.lang.Object")) break;
        }
        return false;
    }

    private List<ApiRoute> extractServletRoutes(JClass sc) {
        List<ApiRoute> routes = new ArrayList<>();
        
        if (filterAnnotations != null && !filterAnnotations.isEmpty()) {
            if (!hasAnnotationContaining(sc, filterAnnotations)) {
                return routes;
            }
        }

        Annotation webServlet = sc.getAnnotation(ANN_WEB_SERVLET);
        List<String> paths = new ArrayList<>();
        
        if (webServlet != null) {
            paths.addAll(getAnnotationValues(webServlet, "value"));
            paths.addAll(getAnnotationValues(webServlet, "urlPatterns"));
        }
        
        if (paths.isEmpty()) {
            paths.add("/servlet/" + sc.getSimpleName()); 
        }

        for (String path : paths) {
            routes.add(new ApiRoute("ALL", path, sc.getName(), "service"));
        }
        return routes;
    }

    private List<ApiRoute> extractSpringRoutes(JClass sc) {
        List<ApiRoute> routes = new ArrayList<>();
        
        boolean classMatchesFilter = false;
        if (filterAnnotations != null && !filterAnnotations.isEmpty()) {
            classMatchesFilter = hasAnnotationContaining(sc, filterAnnotations);
        }

        List<String> classPaths = new ArrayList<>();
        Annotation classMapping = sc.getAnnotation(ANN_REQUEST_MAPPING);
        if (classMapping != null) {
            classPaths.addAll(getAnnotationValues(classMapping, "value"));
            classPaths.addAll(getAnnotationValues(classMapping, "path"));
        }
        if (classPaths.isEmpty()) classPaths.add("");

        for (JMethod sm : sc.getDeclaredMethods()) {
            
            if (filterAnnotations != null && !filterAnnotations.isEmpty()) {
                boolean methodMatchesFilter = hasAnnotationContaining(sm, filterAnnotations);
                if (!classMatchesFilter && !methodMatchesFilter) {
                    continue;
                }
            }

            String httpMethod = null;
            List<String> methodPaths = new ArrayList<>();
            
            if (hasAnnotation(sm, ANN_REQUEST_MAPPING)) {
                Annotation tag = sm.getAnnotation(ANN_REQUEST_MAPPING);
                methodPaths.addAll(getAnnotationValues(tag, "value"));
                methodPaths.addAll(getAnnotationValues(tag, "path"));
                List<String> methods = getAnnotationValues(tag, "method");
                if (!methods.isEmpty()) {
                     httpMethod = methods.get(0).replace("RequestMethod.", "");
                } else {
                     httpMethod = "ALL"; 
                }
                
            } else if (hasAnnotation(sm, ANN_GET_MAPPING)) {
                Annotation tag = sm.getAnnotation(ANN_GET_MAPPING);
                methodPaths.addAll(getAnnotationValues(tag, "value"));
                methodPaths.addAll(getAnnotationValues(tag, "path"));
                httpMethod = "GET";
            } else if (hasAnnotation(sm, ANN_POST_MAPPING)) {
                Annotation tag = sm.getAnnotation(ANN_POST_MAPPING);
                methodPaths.addAll(getAnnotationValues(tag, "value"));
                methodPaths.addAll(getAnnotationValues(tag, "path"));
                httpMethod = "POST";
            } else if (hasAnnotation(sm, ANN_PUT_MAPPING)) {
                Annotation tag = sm.getAnnotation(ANN_PUT_MAPPING);
                methodPaths.addAll(getAnnotationValues(tag, "value"));
                methodPaths.addAll(getAnnotationValues(tag, "path"));
                httpMethod = "PUT";
            } else if (hasAnnotation(sm, ANN_DELETE_MAPPING)) {
                Annotation tag = sm.getAnnotation(ANN_DELETE_MAPPING);
                methodPaths.addAll(getAnnotationValues(tag, "value"));
                methodPaths.addAll(getAnnotationValues(tag, "path"));
                httpMethod = "DELETE";
            }

            if (httpMethod != null) {
                if (methodPaths.isEmpty()) methodPaths.add("");
                
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
                
                for (String path : paths) {
                    routes.add(new ApiRoute(
                        "ALL", 
                        path, 
                        className, 
                        "service", 
                        new ArrayList<>(), 
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
        if (p1.equals("/") && p2.startsWith("/")) return p2; 
        return p1 + p2;
    }
    
    private static class RouteMetadata {
        List<String> parameters = new ArrayList<>();
        Map<String, String> paramAnnotations = new HashMap<>();
        String contentType = "application/x-www-form-urlencoded"; 
    }

    private RouteMetadata extractRouteMetadata(JMethod sm) {
        RouteMetadata meta = new RouteMetadata();
        
        int paramCount = sm.getParamCount();
        for (int i = 0; i < paramCount; i++) {
            // PERFORMANCE OPTIMIZATION 3: Do not call sm.getParamName() here!
            // It triggers IR construction for the method, dramatically slowing down API extraction.
            String name = "arg" + i; 
            Type type = sm.getParamType(i);
            meta.parameters.add(name + ":" + type.getName());
            
            if (type.getName().contains("MultipartFile")) {
                meta.contentType = "multipart/form-data";
            }

            Collection<Annotation> paramAnnos = sm.getParamAnnotations(i);
            for (Annotation at : paramAnnos) {
                String typeName = at.getType();
                if (typeName.equals(ANN_REQUEST_BODY)) {
                    meta.paramAnnotations.put(name, "RequestBody");
                    meta.contentType = "application/json";
                } else if (typeName.equals(ANN_REQUEST_PARAM)) {
                    meta.paramAnnotations.put(name, "RequestParam");
                } else if (typeName.equals(ANN_PATH_VARIABLE)) {
                    meta.paramAnnotations.put(name, "PathVariable");
                }
            }
        }
        
        return meta;
    }

    private RouteMetadata extractJaxrsRouteMetadata(JMethod sm) {
        RouteMetadata meta = new RouteMetadata();

        int paramCount = sm.getParamCount();
        for (int i = 0; i < paramCount; i++) {
            // PERFORMANCE OPTIMIZATION 3: Do not call sm.getParamName() here!
            String name = "arg" + i;
            Type type = sm.getParamType(i);
            meta.parameters.add(name + ":" + type.getName());

            String typeStr = type.getName();
            if (!isPrimitiveOrBasicType(typeStr)) {
                Annotation consumesTag = sm.getAnnotation(ANN_CONSUMES);
                if (consumesTag != null) {
                    List<String> consumesValues = getAnnotationValues(consumesTag, "value");
                    for (String value : consumesValues) {
                        if (value.toLowerCase().contains("json")) {
                            meta.contentType = "application/json";
                            break;
                        }
                    }
                }
            }

            Collection<Annotation> paramAnnos = sm.getParamAnnotations(i);
            for (Annotation at : paramAnnos) {
                String typeName = at.getType();
                if (typeName.equals(ANN_QUERY_PARAM)) {
                    meta.paramAnnotations.put(name, "QueryParam");
                } else if (typeName.equals(ANN_PATH_PARAM)) {
                    meta.paramAnnotations.put(name, "PathParam");
                } else if (typeName.equals(ANN_HEADER_PARAM)) {
                    meta.paramAnnotations.put(name, "HeaderParam");
                } else if (typeName.equals(ANN_FORM_PARAM)) {
                    meta.paramAnnotations.put(name, "FormParam");
                } else if (typeName.equals(ANN_COOKIE_PARAM)) {
                    meta.paramAnnotations.put(name, "CookieParam");
                } else if (typeName.equals(ANN_MATRIX_PARAM)) {
                    meta.paramAnnotations.put(name, "MatrixParam");
                }
            }
        }

        Annotation consumesTag = sm.getAnnotation(ANN_CONSUMES);
        if (consumesTag != null) {
            List<String> consumesValues = getAnnotationValues(consumesTag, "value");
            for (String value : consumesValues) {
                if (value.toLowerCase().contains("json")) {
                    meta.contentType = "application/json";
                    break;
                } else if (value.toLowerCase().contains("xml")) {
                    meta.contentType = "application/xml";
                    break;
                } else if (value.toLowerCase().contains("form")) {
                    meta.contentType = "application/x-www-form-urlencoded";
                    break;
                } else if (value.toLowerCase().contains("multipart")) {
                    meta.contentType = "multipart/form-data";
                    break;
                }
            }
        }

        return meta;
    }
    
    private boolean isPrimitiveOrBasicType(String typeStr) {
        return typeStr.equals("boolean") || typeStr.equals("char") || 
               typeStr.equals("byte") || typeStr.equals("short") || 
               typeStr.equals("int") || typeStr.equals("long") || 
               typeStr.equals("float") || typeStr.equals("double") ||
               typeStr.contains("String") || typeStr.contains("Boolean") ||
               typeStr.contains("Character") || typeStr.contains("Byte") ||
               typeStr.contains("Short") || typeStr.contains("Integer") ||
               typeStr.contains("Long") || typeStr.contains("Float") ||
               typeStr.contains("Double") || typeStr.contains("Date") ||
               typeStr.contains("List") || typeStr.contains("Collection") ||
               typeStr.contains("Map") || typeStr.contains("Array");
    }
}
