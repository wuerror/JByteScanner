package com.jbytescanner.engine;

import soot.tagkit.*;
import java.util.ArrayList;
import java.util.List;

public class AnnotationHelper {

    public static VisibilityAnnotationTag getAnnotationTag(Host host) {
        return (VisibilityAnnotationTag) host.getTag("VisibilityAnnotationTag");
    }

    public static AnnotationTag getAnnotation(Host host, String annotationType) {
        VisibilityAnnotationTag tag = getAnnotationTag(host);
        if (tag == null) return null;

        for (AnnotationTag at : tag.getAnnotations()) {
            if (at.getType().equals(formatType(annotationType))) {
                return at;
            }
        }
        return null;
    }

    public static boolean hasAnnotation(Host host, String annotationType) {
        return getAnnotation(host, annotationType) != null;
    }

    /**
     * Check if the host (Class or Method) has any annotation whose class name OR values contain any of the keywords.
     * Supports nested annotations.
     */
    public static boolean hasAnnotationContaining(Host host, List<String> keywords) {
        if (keywords == null || keywords.isEmpty()) return true; // No filter = match all

        VisibilityAnnotationTag tag = getAnnotationTag(host);
        if (tag == null) return false;

        for (AnnotationTag at : tag.getAnnotations()) {
            if (matchesKeyword(at, keywords)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matchesKeyword(AnnotationTag at, List<String> keywords) {
        // 1. Check Annotation Type Name
        String type = at.getType();
        String normalized = type.substring(1, type.length() - 1).replace('/', '.');
        for (String keyword : keywords) {
            if (normalized.contains(keyword)) return true;
        }

        // 2. Check Elements (Values)
        for (AnnotationElem elem : at.getElems()) {
            if (matchesKeyword(elem, keywords)) return true;
        }
        
        return false;
    }

    private static boolean matchesKeyword(AnnotationElem elem, List<String> keywords) {
        if (elem instanceof AnnotationStringElem) {
            String val = ((AnnotationStringElem) elem).getValue();
            for (String keyword : keywords) {
                if (val.contains(keyword)) return true;
            }
        } else if (elem instanceof AnnotationEnumElem) {
            String val = ((AnnotationEnumElem) elem).getConstantName();
             for (String keyword : keywords) {
                if (val.contains(keyword)) return true;
            }
        } else if (elem instanceof AnnotationArrayElem) {
            for (AnnotationElem subElem : ((AnnotationArrayElem) elem).getValues()) {
                if (matchesKeyword(subElem, keywords)) return true;
            }
        } else if (elem instanceof AnnotationAnnotationElem) {
            // Recursive check for nested annotations (e.g. @AuthValidator inside @AuthValidators)
            return matchesKeyword(((AnnotationAnnotationElem) elem).getValue(), keywords);
        }
        // Primitives (Int, Boolean) are usually not targets for keyword search
        return false;
    }

    /**
     * Extracts the value of a specific element from an annotation.
     * e.g., @RequestMapping(value="/path") -> extract "value"
     */
    public static List<String> getAnnotationValues(AnnotationTag tag, String elemName) {
        List<String> values = new ArrayList<>();
        if (tag == null) return values;

        for (AnnotationElem elem : tag.getElems()) {
            if (elem.getName().equals(elemName)) {
                extractValuesFromElem(elem, values);
            }
        }
        return values;
    }

    private static void extractValuesFromElem(AnnotationElem elem, List<String> result) {
        if (elem instanceof AnnotationStringElem) {
            result.add(((AnnotationStringElem) elem).getValue());
        } else if (elem instanceof AnnotationArrayElem) {
            for (AnnotationElem subElem : ((AnnotationArrayElem) elem).getValues()) {
                extractValuesFromElem(subElem, result);
            }
        }
        // Handle other types if necessary (Int, Boolean, etc.)
    }

    /**
     * Helper to format Java type to bytecode signature format
     * e.g., org.springframework.web.bind.annotation.RestController -> Lorg/springframework/web/bind/annotation/RestController;
     */
    private static String formatType(String type) {
        if (type.startsWith("L") && type.endsWith(";")) return type;
        return "L" + type.replace('.', '/') + ";";
    }
}
