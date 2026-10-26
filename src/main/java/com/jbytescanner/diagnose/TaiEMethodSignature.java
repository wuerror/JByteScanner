package com.jbytescanner.diagnose;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Strict parser for Tai-e method signatures.
 *
 * <p>Accepted form: {@code <owner: returnType methodName(paramType1,paramType2)>}.
 * Owner, return type, method name, and the complete parameter list are mandatory.
 * No owner/name-only fallback is performed because overloaded sinks and sources
 * must not be conflated.</p>
 */
public final class TaiEMethodSignature {

    private static final Map<String, String> PRIMITIVE_DESCRIPTORS = Map.of(
            "void", "V",
            "boolean", "Z",
            "byte", "B",
            "char", "C",
            "short", "S",
            "int", "I",
            "long", "J",
            "float", "F",
            "double", "D"
    );

    private final String raw;
    private final String owner;
    private final String returnType;
    private final String methodName;
    private final List<String> parameterTypes;
    private final String canonical;
    private final String descriptor;

    private TaiEMethodSignature(String raw, String owner, String returnType, String methodName,
                                List<String> parameterTypes) {
        this.raw = raw;
        this.owner = owner;
        this.returnType = returnType;
        this.methodName = methodName;
        this.parameterTypes = List.copyOf(parameterTypes);
        this.canonical = buildCanonical(owner, returnType, methodName, this.parameterTypes);
        this.descriptor = buildDescriptor(returnType, this.parameterTypes);
    }

    public static TaiEMethodSignature parse(String signature) {
        if (signature == null) {
            throw new IllegalArgumentException("Tai-e method signature is required");
        }
        String trimmed = signature.trim();
        if (!trimmed.startsWith("<") || !trimmed.endsWith(">")) {
            throw new IllegalArgumentException(
                    "Tai-e method signature must be wrapped in '<' and '>': " + signature);
        }
        String inner = trimmed.substring(1, trimmed.length() - 1);
        int colon = inner.indexOf(':');
        if (colon <= 0) {
            throw new IllegalArgumentException(
                    "Tai-e method signature must contain '<owner: return method(params)>': "
                            + signature);
        }
        String owner = inner.substring(0, colon).trim();
        String rest = inner.substring(colon + 1).trim();
        int openParen = rest.indexOf('(');
        int closeParen = rest.lastIndexOf(')');
        if (openParen < 0 || closeParen != rest.length() - 1 || closeParen < openParen) {
            throw new IllegalArgumentException(
                    "Tai-e method signature must include a complete parameter descriptor: "
                            + signature);
        }
        String head = rest.substring(0, openParen).trim();
        int lastSpace = head.lastIndexOf(' ');
        if (lastSpace <= 0 || lastSpace == head.length() - 1) {
            throw new IllegalArgumentException(
                    "Tai-e method signature must contain both return type and method name: "
                            + signature);
        }
        String returnType = head.substring(0, lastSpace).trim();
        String methodName = head.substring(lastSpace + 1).trim();
        validateType(owner, "owner", signature);
        validateType(returnType, "return type", signature);
        validateMethodName(methodName, signature);
        String parameterString = rest.substring(openParen + 1, closeParen).trim();
        List<String> parameterTypes = new ArrayList<>();
        if (!parameterString.isEmpty()) {
            for (String part : parameterString.split(",", -1)) {
                String type = part.trim();
                if (type.isEmpty()) {
                    throw new IllegalArgumentException(
                            "Empty parameter type in Tai-e method signature: " + signature);
                }
                validateType(type, "parameter type", signature);
                parameterTypes.add(type);
            }
        }
        if ("void".equals(returnType) && !"<init>".equals(methodName)) {
            // void is valid for ordinary methods, but constructors must also use void.
        }
        return new TaiEMethodSignature(trimmed, owner, returnType, methodName, parameterTypes);
    }

    public static TaiEMethodSignature parseNullable(String signature) {
        if (signature == null || signature.isBlank()) {
            return null;
        }
        try {
            return parse(signature);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    public static String canonicalize(String signature) {
        try {
            return parse(signature).canonical();
        } catch (IllegalArgumentException e) {
            return signature == null ? null : signature.trim();
        }
    }

    public static String normalizeIndex(Object index) {
        if (index == null) {
            return null;
        }
        String value = String.valueOf(index).trim();
        if (value.isEmpty()) {
            return null;
        }
        String lower = value.toLowerCase(Locale.ROOT);
        if ("base".equals(lower) || "result".equals(lower) || "this".equals(lower)) {
            return lower;
        }
        return value;
    }

    public static String callerSignature(String internalOwner, String methodName,
                                         String descriptor) {
        org.objectweb.asm.Type[] args = org.objectweb.asm.Type.getArgumentTypes(descriptor);
        StringBuilder params = new StringBuilder();
        for (int i = 0; i < args.length; i++) {
            if (i > 0) {
                params.append(',');
            }
            params.append(args[i].getClassName());
        }
        String owner = internalOwner.replace('/', '.');
        return "<" + owner + ": " + org.objectweb.asm.Type.getReturnType(descriptor).getClassName()
                + " " + methodName + "(" + params + ")>";
    }

    public static String methodDescriptor(String internalOwner, String methodName,
                                          String descriptor) {
        return internalOwner + "." + methodName + descriptor;
    }

    public String raw() {
        return raw;
    }

    public String owner() {
        return owner;
    }

    public String returnType() {
        return returnType;
    }

    public String methodName() {
        return methodName;
    }

    public List<String> parameterTypes() {
        return parameterTypes;
    }

    public int parameterCount() {
        return parameterTypes.size();
    }

    public String canonical() {
        return canonical;
    }

    public String descriptor() {
        return descriptor;
    }

    public String invokeKey() {
        return owner.replace('.', '/') + "." + methodName + descriptor;
    }

    public boolean matchesInvoke(String internalOwner, String name, String invokeDescriptor) {
        return owner.replace('.', '/').equals(internalOwner)
                && methodName.equals(name)
                && descriptor.equals(invokeDescriptor);
    }

    public boolean sameMethod(TaiEMethodSignature other) {
        return other != null
                && owner.equals(other.owner)
                && returnType.equals(other.returnType)
                && methodName.equals(other.methodName)
                && parameterTypes.equals(other.parameterTypes);
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof TaiEMethodSignature other)) {
            return false;
        }
        return owner.equals(other.owner)
                && returnType.equals(other.returnType)
                && methodName.equals(other.methodName)
                && parameterTypes.equals(other.parameterTypes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(owner, returnType, methodName, parameterTypes);
    }

    @Override
    public String toString() {
        return canonical;
    }

    private static String buildCanonical(String owner, String returnType, String methodName,
                                         List<String> parameterTypes) {
        return "<" + owner + ": " + returnType + " " + methodName
                + "(" + String.join(",", parameterTypes) + ")>";
    }

    private static String buildDescriptor(String returnType, List<String> parameterTypes) {
        StringBuilder descriptor = new StringBuilder("(");
        for (String parameterType : parameterTypes) {
            descriptor.append(typeDescriptor(parameterType));
        }
        descriptor.append(')').append(typeDescriptor(returnType));
        return descriptor.toString();
    }

    private static String typeDescriptor(String typeName) {
        String normalized = typeName.trim();
        int arrayDepth = 0;
        while (normalized.endsWith("[]")) {
            arrayDepth++;
            normalized = normalized.substring(0, normalized.length() - 2).trim();
        }
        String base = PRIMITIVE_DESCRIPTORS.get(normalized);
        if (base == null) {
            base = "L" + normalized.replace('.', '/') + ";";
        }
        if (arrayDepth == 0) {
            return base;
        }
        StringBuilder result = new StringBuilder();
        result.append("[".repeat(arrayDepth));
        result.append(base);
        return result.toString();
    }

    private static void validateType(String type, String label, String signature) {
        if (type == null || type.isBlank()) {
            throw new IllegalArgumentException("Missing " + label + " in Tai-e signature: " + signature);
        }
        if (type.contains(" ") || type.contains(",") || type.contains("<")
                || type.contains(">") || type.contains(":") || type.contains(";")) {
            throw new IllegalArgumentException("Malformed " + label + " '" + type
                    + "' in Tai-e signature: " + signature);
        }
        String stripped = type;
        while (stripped.endsWith("[]")) {
            stripped = stripped.substring(0, stripped.length() - 2);
        }
        if (stripped.isEmpty()) {
            throw new IllegalArgumentException("Malformed " + label + " '" + type
                    + "' in Tai-e signature: " + signature);
        }
    }

    private static void validateMethodName(String methodName, String signature) {
        if (methodName == null || methodName.isBlank()
                || methodName.contains(" ") || methodName.contains("(")
                || methodName.contains(")") || methodName.contains(":")) {
            throw new IllegalArgumentException("Malformed method name '" + methodName
                    + "' in Tai-e signature: " + signature);
        }
    }
}
