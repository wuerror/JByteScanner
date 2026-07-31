package com.jbytescanner.report;

import com.jbytescanner.model.ApiRoute;
import com.jbytescanner.model.Vulnerability;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Builds Burp-style HTTP request PoCs from API route metadata.
 *
 * <p>Must not depend on a live Tai-e World: after worker-mode analysis the host JVM
 * has no World, so field reflection via class hierarchy is unavailable. Prefer route
 * parameter/annotation metadata collected during discovery.
 */
public class PoCGenerator {

    private static final String HOST_PLACEHOLDER = "{{TARGET_HOST}}";

    private static final Map<String, String> PAYLOADS = new HashMap<>();
    static {
        PAYLOADS.put("sqli", "' OR '1'='1");
        PAYLOADS.put("rce", "whoami");
        PAYLOADS.put("ssrf", "http://dnslog.cn");
        PAYLOADS.put("xss", "<script>alert(1)</script>");
        PAYLOADS.put("path-traversal", "../../../../etc/passwd");
        PAYLOADS.put("deserialization",
                "{\"@type\":\"com.example.Evil\",\"cmd\":\"whoami\"}");
        PAYLOADS.put("xxe",
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>");
        PAYLOADS.put("default", "{{PAYLOAD}}");
    }

    public String generate(Vulnerability vuln, ApiRoute route) {
        if (route == null) {
            return "No Route Found for Vulnerability in " + vuln.getSourceMethod();
        }

        StringBuilder poc = new StringBuilder();
        poc.append(route.getHttpMethod() != null ? route.getHttpMethod() : "POST")
                .append(" ")
                .append(adjustPath(route))
                .append(" HTTP/1.1\n");
        poc.append("Host: ").append(HOST_PLACEHOLDER).append("\n");
        poc.append("User-Agent: JByteScanner/1.0\n");
        String contentType = route.getContentType() != null
                ? route.getContentType()
                : "application/json";
        poc.append("Content-Type: ").append(contentType).append("\n");
        poc.append("Accept: */*\n");
        String path = route.getPath() != null ? route.getPath() : "";
        if (path.contains("/admin") || path.contains("/private")) {
            poc.append("Authorization: Bearer {{TOKEN}}\n");
        }
        poc.append("\n");

        String payload = getPayload(vuln.getType());
        poc.append(generateBody(route, payload, contentType));
        return poc.toString();
    }

    private String getPayload(String vulnType) {
        if (vulnType == null) {
            return PAYLOADS.get("default");
        }
        String key = vulnType.toLowerCase(Locale.ROOT);
        if (key.contains("sql")) {
            return PAYLOADS.get("sqli");
        }
        if (key.contains("exec") || key.contains("command") || key.contains("rce")) {
            return PAYLOADS.get("rce");
        }
        if (key.contains("ssrf")) {
            return PAYLOADS.get("ssrf");
        }
        if (key.contains("xss")) {
            return PAYLOADS.get("xss");
        }
        if (key.contains("path") || key.contains("file")) {
            return PAYLOADS.get("path-traversal");
        }
        if (key.contains("deserial")) {
            return PAYLOADS.get("deserialization");
        }
        if (key.contains("xml") || key.contains("xxe")) {
            return PAYLOADS.get("xxe");
        }
        return PAYLOADS.get("default");
    }

    private String adjustPath(ApiRoute route) {
        String path = route.getPath() != null ? route.getPath() : "/";
        if (path.contains("{")) {
            path = path.replaceAll("\\{[^}]+\\}", "123");
        }
        return path;
    }

    private String generateBody(ApiRoute route, String payload, String contentType) {
        if (contentType.contains("json")) {
            return generateJsonBody(route, payload);
        }
        if (contentType.contains("form-urlencoded")) {
            return generateFormBody(route, payload);
        }
        if (contentType.contains("multipart")) {
            return generateMultipartBody(route, payload);
        }
        return payload != null ? payload : "";
    }

    private String generateFormBody(ApiRoute route, String payload) {
        List<String> params = route.getParameters();
        if (params == null || params.isEmpty()) {
            return "param=" + urlEncode(payload);
        }
        List<String> pairs = new ArrayList<>();
        Map<String, String> anns = route.getParamAnnotations();
        for (String p : params) {
            String name = paramName(p);
            if (anns != null && "PathVariable".equals(anns.get(name))) {
                continue;
            }
            pairs.add(name + "=" + urlEncode(payload));
        }
        if (pairs.isEmpty()) {
            return "param=" + urlEncode(payload);
        }
        return String.join("&", pairs);
    }

    private String generateMultipartBody(ApiRoute route, String payload) {
        String boundary = "----JByteScannerBoundary7MA4YWxkTrZu0gW";
        StringBuilder sb = new StringBuilder();
        List<String> params = route.getParameters();
        if (params == null || params.isEmpty()) {
            sb.append("--").append(boundary).append("\r\n");
            sb.append("Content-Disposition: form-data; name=\"file\"; filename=\"poc.txt\"\r\n");
            sb.append("Content-Type: text/plain\r\n\r\n");
            sb.append(payload).append("\r\n");
            sb.append("--").append(boundary).append("--");
            return sb.toString();
        }
        Map<String, String> anns = route.getParamAnnotations();
        for (String p : params) {
            String name = paramName(p);
            if (anns != null && "PathVariable".equals(anns.get(name))) {
                continue;
            }
            sb.append("--").append(boundary).append("\r\n");
            sb.append("Content-Disposition: form-data; name=\"").append(name).append("\"\r\n\r\n");
            sb.append(payload).append("\r\n");
        }
        sb.append("--").append(boundary).append("--");
        return sb.toString();
    }

    private String generateJsonBody(ApiRoute route, String payload) {
        String requestBodyType = null;
        String requestBodyName = null;
        Map<String, String> anns = route.getParamAnnotations();
        List<String> params = route.getParameters();

        if (anns != null) {
            for (Map.Entry<String, String> entry : anns.entrySet()) {
                if (entry.getValue() != null && entry.getValue().contains("RequestBody")) {
                    requestBodyName = entry.getKey();
                    break;
                }
            }
        }
        if (requestBodyName != null && params != null) {
            for (String p : params) {
                if (p.startsWith(requestBodyName + ":")) {
                    requestBodyType = paramType(p);
                    break;
                }
            }
        }
        if (requestBodyType == null && params != null) {
            for (String p : params) {
                String name = paramName(p);
                if (anns != null && "PathVariable".equals(anns.get(name))) {
                    continue;
                }
                requestBodyType = paramType(p);
                break;
            }
        }
        if (requestBodyType == null) {
            return payloadJsonLiteral(payload);
        }
        if (isSimpleType(requestBodyType)) {
            return payloadJsonLiteral(payload);
        }
        if (requestBodyType.startsWith("java.util.List")
                || requestBodyType.startsWith("java.util.Collection")
                || requestBodyType.startsWith("java.util.Set")
                || requestBodyType.endsWith("[]")) {
            return "[" + payloadJsonLiteral(payload) + "]";
        }
        if (requestBodyType.startsWith("java.util.Map")) {
            return "{\"key\": " + payloadJsonLiteral(payload) + "}";
        }
        // POJO without World: minimal object with common field names + type hint.
        return "{\n"
                + "  \"_typeHint\": \"" + escapeJson(requestBodyType) + "\",\n"
                + "  \"payload\": " + payloadJsonLiteral(payload) + ",\n"
                + "  \"data\": " + payloadJsonLiteral(payload) + ",\n"
                + "  \"content\": " + payloadJsonLiteral(payload) + ",\n"
                + "  \"value\": " + payloadJsonLiteral(payload) + ",\n"
                + "  \"body\": " + payloadJsonLiteral(payload) + "\n"
                + "}\n";
    }

    private static String payloadJsonLiteral(String payload) {
        if (payload == null) {
            return "\"\"";
        }
        String trimmed = payload.trim();
        if ((trimmed.startsWith("{") && trimmed.endsWith("}"))
                || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
            return trimmed;
        }
        return "\"" + escapeJson(payload) + "\"";
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String urlEncode(String s) {
        if (s == null) {
            return "";
        }
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
    }

    private static String paramName(String p) {
        int i = p.indexOf(':');
        return i < 0 ? p : p.substring(0, i);
    }

    private static String paramType(String p) {
        int i = p.indexOf(':');
        return i < 0 ? "java.lang.String" : p.substring(i + 1);
    }

    private static boolean isSimpleType(String type) {
        if (type == null) {
            return true;
        }
        return type.startsWith("java.lang.")
                || type.equals("int") || type.equals("long") || type.equals("boolean")
                || type.equals("double") || type.equals("float") || type.equals("short")
                || type.equals("byte") || type.equals("char");
    }
}
