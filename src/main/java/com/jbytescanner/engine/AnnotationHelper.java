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
