package com.jbytescanner.finding;

import java.util.List;
import java.util.Locale;

/**
 * Default library-internal package prefixes used with weak-sink family predicates.
 */
public final class LibraryInternalPackages {

    public static final List<String> DEFAULT_PREFIXES = List.of(
            "oracle.xml.",
            "oracle.xdo.",
            "com.fasterxml.jackson.databind.",
            "com.alibaba.fastjson.serializer.",
            "com.alibaba.fastjson.parser.",
            "com.aliyun.openservices.shade.com.alibaba.fastjson.",
            "org.apache.cxf.",
            "org.apache.ws.commons.",
            "org.springframework.core."
    );

    private LibraryInternalPackages() {
    }

    public static boolean matches(String className, List<String> extra) {
        if (className == null || className.isBlank()) {
            return false;
        }
        String cn = className;
        for (String p : DEFAULT_PREFIXES) {
            if (cn.startsWith(p)) {
                return true;
            }
        }
        if (extra != null) {
            for (String p : extra) {
                if (p != null && !p.isBlank() && cn.startsWith(p.trim())) {
                    return true;
                }
            }
        }
        return false;
    }

    public static String classNameFromSignature(String methodSig) {
        if (methodSig == null || !methodSig.startsWith("<")) {
            return "";
        }
        int colon = methodSig.indexOf(':');
        if (colon <= 1) {
            return "";
        }
        return methodSig.substring(1, colon).trim();
    }

    public static boolean isWeakFamily(SinkStrength strength) {
        return strength == SinkStrength.CONSTRUCTOR
                || strength == SinkStrength.PARSER
                || strength == SinkStrength.INTERMEDIATE;
    }
}
