package com.jbytescanner.engine;

import com.jbytescanner.model.ApiRoute;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * ASM-based route extractor for API discovery mode.
 *
 * <p>Reads class file metadata (annotations, method signatures, parameter annotations) directly
 * from bytecode without building a Tai-e World or loading IR. This makes discovery orders of
 * magnitude faster than the Tai-e-based RouteExtractor (&lt;1s vs 35s, &lt;100MB vs 2GB).
 *
 * <p>Supports Spring MVC, Servlet, and JAX-RS. Produces {@link ApiRoute} objects in the same
 * format as the Tai-e-based extractor so that downstream TaintEngine can consume them unchanged.
 */
public class AsmRouteExtractor {
    private static final Logger logger = LoggerFactory.getLogger(AsmRouteExtractor.class);

    // Spring MVC annotation descriptors
    private static final String DESC_REST_CONTROLLER = "Lorg/springframework/web/bind/annotation/RestController;";
    private static final String DESC_CONTROLLER      = "Lorg/springframework/stereotype/Controller;";
    private static final String DESC_REQUEST_MAPPING = "Lorg/springframework/web/bind/annotation/RequestMapping;";
    private static final String DESC_GET_MAPPING     = "Lorg/springframework/web/bind/annotation/GetMapping;";
    private static final String DESC_POST_MAPPING    = "Lorg/springframework/web/bind/annotation/PostMapping;";
    private static final String DESC_PUT_MAPPING     = "Lorg/springframework/web/bind/annotation/PutMapping;";
    private static final String DESC_DELETE_MAPPING  = "Lorg/springframework/web/bind/annotation/DeleteMapping;";
    private static final String DESC_PATCH_MAPPING   = "Lorg/springframework/web/bind/annotation/PatchMapping;";

    // Spring parameter annotations
    private static final String DESC_REQUEST_BODY  = "Lorg/springframework/web/bind/annotation/RequestBody;";
    private static final String DESC_REQUEST_PARAM = "Lorg/springframework/web/bind/annotation/RequestParam;";
    private static final String DESC_PATH_VARIABLE = "Lorg/springframework/web/bind/annotation/PathVariable;";

    // Servlet
    private static final String INTERNAL_HTTP_SERVLET = "javax/servlet/http/HttpServlet";
    private static final String DESC_WEB_SERVLET       = "Ljavax/servlet/annotation/WebServlet;";

    // JAX-RS annotation descriptors
    private static final String DESC_PATH    = "Ljavax/ws/rs/Path;";
    private static final String DESC_GET     = "Ljavax/ws/rs/GET;";
    private static final String DESC_POST    = "Ljavax/ws/rs/POST;";
    private static final String DESC_PUT     = "Ljavax/ws/rs/PUT;";
    private static final String DESC_DELETE  = "Ljavax/ws/rs/DELETE;";
    private static final String DESC_HEAD    = "Ljavax/ws/rs/HEAD;";
    private static final String DESC_OPTIONS = "Ljavax/ws/rs/OPTIONS;";
    private static final String DESC_PATCH   = "Ljavax/ws/rs/PATCH;";
    private static final String DESC_CONSUMES = "Ljavax/ws/rs/Consumes;";

    // JAX-RS parameter annotations
    private static final String DESC_QUERY_PARAM  = "Ljavax/ws/rs/QueryParam;";
    private static final String DESC_PATH_PARAM   = "Ljavax/ws/rs/PathParam;";
    private static final String DESC_HEADER_PARAM = "Ljavax/ws/rs/HeaderParam;";
    private static final String DESC_FORM_PARAM   = "Ljavax/ws/rs/FormParam;";
    private static final String DESC_COOKIE_PARAM = "Ljavax/ws/rs/CookieParam;";
    private static final String DESC_MATRIX_PARAM = "Ljavax/ws/rs/MatrixParam;";

    private final List<String> filterAnnotations;
    private final List<String> targetJars;

    public AsmRouteExtractor(List<String> filterAnnotations, List<String> targetJars) {
        this.filterAnnotations = filterAnnotations;
        this.targetJars = targetJars;
    }

    public List<ApiRoute> extract() {
        // Phase 1: scan all class files and collect metadata
        Map<String, ClassInfo> classInfoMap = new HashMap<>();
        for (String jarPath : targetJars) {
            File f = new File(jarPath);
            if (f.isDirectory()) {
                scanDirectory(f, classInfoMap);
            } else if (f.isFile() && jarPath.endsWith(".jar")) {
                scanJar(f, classInfoMap);
            }
        }
        logger.info("AsmRouteExtractor: scanned {} classes.", classInfoMap.size());

        // Phase 2: web.xml routes (WebXmlParser has no Tai-e dependency)
        List<ApiRoute> routes = new ArrayList<>();
        WebXmlParser parser = new WebXmlParser();
        for (String jarPath : targetJars) {
            Map<String, List<String>> webXmlRoutes = parser.parse(new File(jarPath));
            for (Map.Entry<String, List<String>> entry : webXmlRoutes.entrySet()) {
                for (String path : entry.getValue()) {
                    routes.add(new ApiRoute("ALL", path, entry.getKey(), "service",
                            new ArrayList<>(), new HashMap<>(), "application/x-www-form-urlencoded"));
                }
            }
        }

        // Phase 3: annotation-based routes
        for (ClassInfo ci : classInfoMap.values()) {
            if (ci.hasAnnotation(DESC_REST_CONTROLLER) || ci.hasAnnotation(DESC_CONTROLLER)) {
                routes.addAll(extractSpringRoutes(ci));
            }
            if (isServlet(ci, classInfoMap)) {
                routes.addAll(extractServletRoutes(ci));
            }
            if (isJaxRs(ci)) {
                routes.addAll(extractJaxRsRoutes(ci));
            }
        }
        return routes;
    }

    // ---- Internal Data Model ----

    private static class ClassInfo {
        final String className;         // dot-separated, e.g. "com.example.UserController"
        final String internalSuperName; // slash-separated, e.g. "javax/servlet/http/HttpServlet"
        final List<AnnInfo> annotations = new ArrayList<>();
        final List<MethodInfo> methods  = new ArrayList<>();

        ClassInfo(String className, String internalSuperName) {
            this.className = className;
            this.internalSuperName = internalSuperName;
        }

        boolean hasAnnotation(String descriptor) {
            for (AnnInfo a : annotations) {
                if (descriptor.equals(a.descriptor)) return true;
            }
            return false;
        }

        AnnInfo getAnnotation(String descriptor) {
            for (AnnInfo a : annotations) {
                if (descriptor.equals(a.descriptor)) return a;
            }
            return null;
        }

        boolean hasAnnotationContaining(List<String> filters) {
            if (filters == null || filters.isEmpty()) return true;
            for (AnnInfo a : annotations) {
                String typeName = descriptorToClassName(a.descriptor);
                for (String f : filters) {
                    if (typeName.contains(f)) return true;
                }
            }
            return false;
        }
    }

    private static class AnnInfo {
        final String descriptor; // e.g. "Lorg/springframework/web/bind/annotation/GetMapping;"
        final Map<String, List<String>> values = new LinkedHashMap<>();

        AnnInfo(String descriptor) {
            this.descriptor = descriptor;
        }

        List<String> getValues(String key) {
            return values.getOrDefault(key, Collections.emptyList());
        }
    }

    private static class MethodInfo {
        final String name;
        final String descriptor;
        final List<AnnInfo> annotations = new ArrayList<>();
        // index i → list of annotations on parameter i
        final List<List<AnnInfo>> paramAnnotations;

        MethodInfo(String name, String descriptor) {
            this.name = name;
            this.descriptor = descriptor;
            int count = parseParamTypes(descriptor).size();
            this.paramAnnotations = new ArrayList<>(count);
            for (int i = 0; i < count; i++) paramAnnotations.add(new ArrayList<>());
        }

        boolean hasAnnotation(String descriptor) {
            for (AnnInfo a : annotations) {
                if (descriptor.equals(a.descriptor)) return true;
            }
            return false;
        }

        AnnInfo getAnnotation(String descriptor) {
            for (AnnInfo a : annotations) {
                if (descriptor.equals(a.descriptor)) return a;
            }
            return null;
        }

        boolean hasAnnotationContaining(List<String> filters) {
            if (filters == null || filters.isEmpty()) return true;
            for (AnnInfo a : annotations) {
                String typeName = descriptorToClassName(a.descriptor);
                for (String f : filters) {
                    if (typeName.contains(f)) return true;
                }
            }
            return false;
        }

        List<AnnInfo> getParamAnnotations(int i) {
            if (i < paramAnnotations.size()) return paramAnnotations.get(i);
            return Collections.emptyList();
        }
    }

    // ---- ASM Scanning ----

    private void scanDirectory(File dir, Map<String, ClassInfo> classInfoMap) {
        try (Stream<Path> walk = Files.walk(dir.toPath())) {
            walk.filter(p -> p.toString().endsWith(".class")).forEach(p -> {
                try (InputStream is = Files.newInputStream(p)) {
                    readClass(is, classInfoMap);
                } catch (Exception ignored) { }
            });
        } catch (IOException e) {
            logger.error("Error walking directory for ASM: {}", dir, e);
        }
    }

    private void scanJar(File jarFile, Map<String, ClassInfo> classInfoMap) {
        try (ZipFile zip = new ZipFile(jarFile)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".class")) {
                    try (InputStream is = zip.getInputStream(entry)) {
                        readClass(is, classInfoMap);
                    } catch (Exception ignored) { }
                }
            }
        } catch (IOException e) {
            logger.error("Error reading jar for ASM: {}", jarFile, e);
        }
    }

    private void readClass(InputStream is, Map<String, ClassInfo> classInfoMap) throws IOException {
        ClassReader cr = new ClassReader(is);
        RouteClassVisitor visitor = new RouteClassVisitor();
        // SKIP_CODE: skip method bytecode (we only need metadata/annotations)
        // SKIP_DEBUG: skip line numbers and local variable names
        // SKIP_FRAMES: skip stack map frames
        cr.accept(visitor, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        if (visitor.classInfo != null) {
            classInfoMap.put(visitor.classInfo.className, visitor.classInfo);
        }
    }

    // ---- ASM Visitors ----

    private static class RouteClassVisitor extends ClassVisitor {
        ClassInfo classInfo;

        RouteClassVisitor() {
            super(Opcodes.ASM9);
        }

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            classInfo = new ClassInfo(name.replace('/', '.'), superName);
        }

        @Override
        public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
            AnnInfo ann = new AnnInfo(descriptor);
            classInfo.annotations.add(ann);
            return new AnnValueCollector(ann);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            // Skip constructors, static initializers, and compiler-generated methods
            if (name.startsWith("<")
                    || (access & Opcodes.ACC_SYNTHETIC) != 0
                    || (access & Opcodes.ACC_BRIDGE) != 0) {
                return null;
            }
            MethodInfo mi = new MethodInfo(name, descriptor);
            classInfo.methods.add(mi);
            return new RouteMethodVisitor(mi);
        }
    }

    private static class RouteMethodVisitor extends MethodVisitor {
        private final MethodInfo methodInfo;

        RouteMethodVisitor(MethodInfo methodInfo) {
            super(Opcodes.ASM9);
            this.methodInfo = methodInfo;
        }

        @Override
        public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
            AnnInfo ann = new AnnInfo(descriptor);
            methodInfo.annotations.add(ann);
            return new AnnValueCollector(ann);
        }

        @Override
        public AnnotationVisitor visitParameterAnnotation(int parameter, String descriptor, boolean visible) {
            // Expand the list if needed (e.g. implicit parameters in inner classes)
            while (methodInfo.paramAnnotations.size() <= parameter) {
                methodInfo.paramAnnotations.add(new ArrayList<>());
            }
            AnnInfo ann = new AnnInfo(descriptor);
            methodInfo.paramAnnotations.get(parameter).add(ann);
            return new AnnValueCollector(ann);
        }
    }

    /** Collects String-valued and enum-valued annotation attributes, including array forms. */
    private static class AnnValueCollector extends AnnotationVisitor {
        private final AnnInfo annInfo;

        AnnValueCollector(AnnInfo annInfo) {
            super(Opcodes.ASM9);
            this.annInfo = annInfo;
        }

        @Override
        public void visit(String name, Object value) {
            if (value instanceof String) {
                annInfo.values.computeIfAbsent(name, k -> new ArrayList<>()).add((String) value);
            }
        }

        @Override
        public void visitEnum(String name, String descriptor, String value) {
            // Handles e.g. @RequestMapping(method = RequestMethod.GET)
            annInfo.values.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
        }

        @Override
        public AnnotationVisitor visitArray(String name) {
            List<String> list = annInfo.values.computeIfAbsent(name, k -> new ArrayList<>());
            return new AnnotationVisitor(Opcodes.ASM9) {
                @Override
                public void visit(String n, Object value) {
                    if (value instanceof String) list.add((String) value);
                }

                @Override
                public void visitEnum(String n, String descriptor, String value) {
                    list.add(value);
                }
            };
        }
    }

    // ---- Framework Detection ----

    private boolean isServlet(ClassInfo ci, Map<String, ClassInfo> classInfoMap) {
        if (ci.hasAnnotation(DESC_WEB_SERVLET)) return true;
        // Traverse superclass chain to check for HttpServlet
        String superName = ci.internalSuperName;
        Set<String> visited = new HashSet<>();
        while (superName != null
                && !superName.equals("java/lang/Object")
                && visited.add(superName)) {
            if (INTERNAL_HTTP_SERVLET.equals(superName)) return true;
            ClassInfo superCi = classInfoMap.get(superName.replace('/', '.'));
            if (superCi != null) {
                superName = superCi.internalSuperName;
            } else {
                break; // superclass not in target JARs
            }
        }
        return false;
    }

    private boolean isJaxRs(ClassInfo ci) {
        if (ci.hasAnnotation(DESC_PATH)) return true;
        for (MethodInfo mi : ci.methods) {
            if (mi.hasAnnotation(DESC_GET) || mi.hasAnnotation(DESC_POST)
                    || mi.hasAnnotation(DESC_PUT) || mi.hasAnnotation(DESC_DELETE)
                    || mi.hasAnnotation(DESC_HEAD) || mi.hasAnnotation(DESC_OPTIONS)
                    || mi.hasAnnotation(DESC_PATCH) || mi.hasAnnotation(DESC_PATH)) {
                return true;
            }
        }
        return false;
    }

    // ---- Route Extraction ----

    private List<ApiRoute> extractSpringRoutes(ClassInfo ci) {
        List<ApiRoute> routes = new ArrayList<>();
        boolean classMatchesFilter = ci.hasAnnotationContaining(filterAnnotations);

        List<String> classPaths = new ArrayList<>();
        AnnInfo classMapping = ci.getAnnotation(DESC_REQUEST_MAPPING);
        if (classMapping != null) {
            classPaths.addAll(classMapping.getValues("value"));
            classPaths.addAll(classMapping.getValues("path"));
        }
        if (classPaths.isEmpty()) classPaths.add("");

        for (MethodInfo mi : ci.methods) {
            if (filterAnnotations != null && !filterAnnotations.isEmpty()) {
                if (!classMatchesFilter && !mi.hasAnnotationContaining(filterAnnotations)) continue;
            }

            String httpMethod = null;
            List<String> methodPaths = new ArrayList<>();

            if (mi.hasAnnotation(DESC_REQUEST_MAPPING)) {
                AnnInfo tag = mi.getAnnotation(DESC_REQUEST_MAPPING);
                methodPaths.addAll(tag.getValues("value"));
                methodPaths.addAll(tag.getValues("path"));
                List<String> methods = tag.getValues("method");
                httpMethod = methods.isEmpty() ? "ALL" : methods.get(0).replace("RequestMethod.", "");
            } else if (mi.hasAnnotation(DESC_GET_MAPPING)) {
                AnnInfo tag = mi.getAnnotation(DESC_GET_MAPPING);
                methodPaths.addAll(tag.getValues("value"));
                methodPaths.addAll(tag.getValues("path"));
                httpMethod = "GET";
            } else if (mi.hasAnnotation(DESC_POST_MAPPING)) {
                AnnInfo tag = mi.getAnnotation(DESC_POST_MAPPING);
                methodPaths.addAll(tag.getValues("value"));
                methodPaths.addAll(tag.getValues("path"));
                httpMethod = "POST";
            } else if (mi.hasAnnotation(DESC_PUT_MAPPING)) {
                AnnInfo tag = mi.getAnnotation(DESC_PUT_MAPPING);
                methodPaths.addAll(tag.getValues("value"));
                methodPaths.addAll(tag.getValues("path"));
                httpMethod = "PUT";
            } else if (mi.hasAnnotation(DESC_DELETE_MAPPING)) {
                AnnInfo tag = mi.getAnnotation(DESC_DELETE_MAPPING);
                methodPaths.addAll(tag.getValues("value"));
                methodPaths.addAll(tag.getValues("path"));
                httpMethod = "DELETE";
            } else if (mi.hasAnnotation(DESC_PATCH_MAPPING)) {
                AnnInfo tag = mi.getAnnotation(DESC_PATCH_MAPPING);
                methodPaths.addAll(tag.getValues("value"));
                methodPaths.addAll(tag.getValues("path"));
                httpMethod = "PATCH";
            }

            if (httpMethod != null) {
                if (methodPaths.isEmpty()) methodPaths.add("");
                RouteMetadata meta = extractSpringMeta(mi);
                String subSig = buildSubsignature(mi);
                for (String cp : classPaths) {
                    for (String mp : methodPaths) {
                        routes.add(new ApiRoute(httpMethod, combinePaths(cp, mp),
                                ci.className, subSig,
                                meta.parameters, meta.paramAnnotations, meta.contentType));
                    }
                }
            }
        }
        return routes;
    }

    private List<ApiRoute> extractServletRoutes(ClassInfo ci) {
        List<ApiRoute> routes = new ArrayList<>();
        if (filterAnnotations != null && !filterAnnotations.isEmpty()) {
            if (!ci.hasAnnotationContaining(filterAnnotations)) return routes;
        }

        List<String> paths = new ArrayList<>();
        AnnInfo webServlet = ci.getAnnotation(DESC_WEB_SERVLET);
        if (webServlet != null) {
            paths.addAll(webServlet.getValues("value"));
            paths.addAll(webServlet.getValues("urlPatterns"));
        }
        if (paths.isEmpty()) {
            paths.add("/servlet/" + simpleClassName(ci.className));
        }
        for (String path : paths) {
            routes.add(new ApiRoute("ALL", path, ci.className, "service"));
        }
        return routes;
    }

    private List<ApiRoute> extractJaxRsRoutes(ClassInfo ci) {
        List<ApiRoute> routes = new ArrayList<>();
        boolean classMatchesFilter = ci.hasAnnotationContaining(filterAnnotations);

        AnnInfo classPathAnn = ci.getAnnotation(DESC_PATH);
        List<String> classPaths = classPathAnn != null
                ? new ArrayList<>(classPathAnn.getValues("value"))
                : new ArrayList<>();
        if (classPaths.isEmpty()) classPaths.add("");

        for (MethodInfo mi : ci.methods) {
            String httpMethod = null;
            if (mi.hasAnnotation(DESC_GET))     httpMethod = "GET";
            else if (mi.hasAnnotation(DESC_POST))    httpMethod = "POST";
            else if (mi.hasAnnotation(DESC_PUT))     httpMethod = "PUT";
            else if (mi.hasAnnotation(DESC_DELETE))  httpMethod = "DELETE";
            else if (mi.hasAnnotation(DESC_HEAD))    httpMethod = "HEAD";
            else if (mi.hasAnnotation(DESC_OPTIONS)) httpMethod = "OPTIONS";
            else if (mi.hasAnnotation(DESC_PATCH))   httpMethod = "PATCH";

            AnnInfo methodPathAnn = mi.getAnnotation(DESC_PATH);
            List<String> methodPaths = new ArrayList<>();
            if (methodPathAnn != null) {
                methodPaths.addAll(methodPathAnn.getValues("value"));
                if (methodPaths.isEmpty()) methodPaths.add("");
                if (httpMethod == null) httpMethod = "GET";
            } else if (httpMethod != null) {
                methodPaths.add("");
            }

            if (filterAnnotations != null && !filterAnnotations.isEmpty()) {
                if (!classMatchesFilter && !mi.hasAnnotationContaining(filterAnnotations)) continue;
            }

            if (httpMethod != null && !methodPaths.isEmpty()) {
                RouteMetadata meta = extractJaxRsMeta(mi);
                String subSig = buildSubsignature(mi);
                for (String cp : classPaths) {
                    for (String mp : methodPaths) {
                        routes.add(new ApiRoute(httpMethod, combinePaths(cp, mp),
                                ci.className, subSig,
                                meta.parameters, meta.paramAnnotations, meta.contentType));
                    }
                }
            }
        }
        return routes;
    }

    // ---- Metadata Extraction ----

    private static class RouteMetadata {
        List<String> parameters = new ArrayList<>();
        Map<String, String> paramAnnotations = new LinkedHashMap<>();
        String contentType = "application/x-www-form-urlencoded";
    }

    private RouteMetadata extractSpringMeta(MethodInfo mi) {
        RouteMetadata meta = new RouteMetadata();
        List<String> paramTypes = parseParamTypes(mi.descriptor);
        for (int i = 0; i < paramTypes.size(); i++) {
            String type = paramTypes.get(i);
            String name = "arg" + i;
            meta.parameters.add(name + ":" + type);
            if (type.contains("MultipartFile")) meta.contentType = "multipart/form-data";
            for (AnnInfo pa : mi.getParamAnnotations(i)) {
                if (DESC_REQUEST_BODY.equals(pa.descriptor)) {
                    meta.paramAnnotations.put(name, "RequestBody");
                    meta.contentType = "application/json";
                } else if (DESC_REQUEST_PARAM.equals(pa.descriptor)) {
                    meta.paramAnnotations.put(name, "RequestParam");
                } else if (DESC_PATH_VARIABLE.equals(pa.descriptor)) {
                    meta.paramAnnotations.put(name, "PathVariable");
                }
            }
        }
        return meta;
    }

    private RouteMetadata extractJaxRsMeta(MethodInfo mi) {
        RouteMetadata meta = new RouteMetadata();
        // Method-level @Consumes
        AnnInfo consumesAnn = mi.getAnnotation(DESC_CONSUMES);
        if (consumesAnn != null) {
            for (String v : consumesAnn.getValues("value")) {
                String lv = v.toLowerCase();
                if (lv.contains("json"))      { meta.contentType = "application/json"; break; }
                else if (lv.contains("xml"))  { meta.contentType = "application/xml"; break; }
                else if (lv.contains("form")) { meta.contentType = "application/x-www-form-urlencoded"; break; }
                else if (lv.contains("multipart")) { meta.contentType = "multipart/form-data"; break; }
            }
        }
        List<String> paramTypes = parseParamTypes(mi.descriptor);
        for (int i = 0; i < paramTypes.size(); i++) {
            String type = paramTypes.get(i);
            String name = "arg" + i;
            meta.parameters.add(name + ":" + type);
            for (AnnInfo pa : mi.getParamAnnotations(i)) {
                if (DESC_QUERY_PARAM.equals(pa.descriptor))       meta.paramAnnotations.put(name, "QueryParam");
                else if (DESC_PATH_PARAM.equals(pa.descriptor))   meta.paramAnnotations.put(name, "PathParam");
                else if (DESC_HEADER_PARAM.equals(pa.descriptor)) meta.paramAnnotations.put(name, "HeaderParam");
                else if (DESC_FORM_PARAM.equals(pa.descriptor))   meta.paramAnnotations.put(name, "FormParam");
                else if (DESC_COOKIE_PARAM.equals(pa.descriptor)) meta.paramAnnotations.put(name, "CookieParam");
                else if (DESC_MATRIX_PARAM.equals(pa.descriptor)) meta.paramAnnotations.put(name, "MatrixParam");
            }
        }
        return meta;
    }

    // ---- Method Signature Building ----

    /**
     * Build the Tai-e subsignature string for a method.
     * Format: {@code returnType methodName(param1,param2,...)}
     * e.g. {@code java.lang.String getUser(java.lang.String,int)}
     *
     * <p>This must match the output of {@code JMethod.getSubsignature().toString()} so that
     * TaintEngine can reconstruct the full Tai-e signature:
     * {@code <com.example.Class: returnType methodName(params)>}
     */
    private static String buildSubsignature(MethodInfo mi) {
        String returnType = parseReturnType(mi.descriptor);
        List<String> paramTypes = parseParamTypes(mi.descriptor);
        return returnType + " " + mi.name + "(" + String.join(",", paramTypes) + ")";
    }

    /** Parse the return type from an ASM method descriptor. */
    private static String parseReturnType(String descriptor) {
        int closeParen = descriptor.lastIndexOf(')');
        return internalTypeToJava(descriptor.substring(closeParen + 1));
    }

    /**
     * Parse parameter types from an ASM method descriptor.
     * e.g. {@code (Ljava/lang/String;I)V} → ["java.lang.String", "int"]
     */
    static List<String> parseParamTypes(String descriptor) {
        List<String> result = new ArrayList<>();
        int i = 1; // skip opening '('
        while (i < descriptor.length() && descriptor.charAt(i) != ')') {
            int[] next = new int[1];
            result.add(parseOneType(descriptor, i, next));
            i = next[0];
        }
        return result;
    }

    /**
     * Parse a single JVM type descriptor starting at {@code start}, setting
     * {@code next[0]} to the index of the first character after this type.
     */
    private static String parseOneType(String descriptor, int start, int[] next) {
        char c = descriptor.charAt(start);
        if (c == '[') {
            // Array type: recurse on element type
            int[] inner = new int[1];
            String elementType = parseOneType(descriptor, start + 1, inner);
            next[0] = inner[0];
            return elementType + "[]";
        } else if (c == 'L') {
            // Object type: Lfully/qualified/Name;
            int semi = descriptor.indexOf(';', start);
            next[0] = semi + 1;
            return descriptor.substring(start + 1, semi).replace('/', '.');
        } else {
            // Primitive type
            next[0] = start + 1;
            return primitiveDescToJava(c);
        }
    }

    private static String internalTypeToJava(String typeDesc) {
        if (typeDesc.isEmpty()) return "void";
        int[] idx = new int[1];
        return parseOneType(typeDesc, 0, idx);
    }

    private static String primitiveDescToJava(char c) {
        switch (c) {
            case 'B': return "byte";
            case 'C': return "char";
            case 'D': return "double";
            case 'F': return "float";
            case 'I': return "int";
            case 'J': return "long";
            case 'S': return "short";
            case 'V': return "void";
            case 'Z': return "boolean";
            default:  return String.valueOf(c);
        }
    }

    /** Convert an ASM annotation descriptor to a dot-separated class name. */
    private static String descriptorToClassName(String descriptor) {
        if (descriptor.startsWith("L") && descriptor.endsWith(";")) {
            return descriptor.substring(1, descriptor.length() - 1).replace('/', '.');
        }
        return descriptor;
    }

    private static String simpleClassName(String className) {
        int idx = className.lastIndexOf('.');
        return idx >= 0 ? className.substring(idx + 1) : className;
    }

    private String combinePaths(String p1, String p2) {
        if (!p1.startsWith("/")) p1 = "/" + p1;
        if (!p2.startsWith("/") && !p2.isEmpty()) p2 = "/" + p2;
        if (p1.endsWith("/") && p2.startsWith("/")) return p1 + p2.substring(1);
        if (p1.equals("/") && p2.startsWith("/")) return p2;
        return p1 + p2;
    }
}
