package com.jbytescanner.diagnose;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TaiEMethodSignatureTest {

    @Test
    void parsesExactOwnerReturnNameAndParameters() {
        TaiEMethodSignature signature = TaiEMethodSignature.parse(
                "<java.io.File: void <init>(java.lang.String)>");

        assertEquals("java.io.File", signature.owner());
        assertEquals("void", signature.returnType());
        assertEquals("<init>", signature.methodName());
        assertEquals(java.util.List.of("java.lang.String"), signature.parameterTypes());
        assertEquals("(Ljava/lang/String;)V", signature.descriptor());
        assertEquals("<java.io.File: void <init>(java.lang.String)>",
                signature.canonical());
    }

    @Test
    void overloadsDifferByCompleteParameterList() {
        TaiEMethodSignature one = TaiEMethodSignature.parse(
                "<java.io.File: void <init>(java.lang.String)>");
        TaiEMethodSignature two = TaiEMethodSignature.parse(
                "<java.io.File: void <init>(java.lang.String,java.lang.String)>");

        assertNotEquals(one, two);
        assertFalse(one.matchesInvoke("java/io/File", "<init>",
                "(Ljava/lang/String;Ljava/lang/String;)V"));
        assertTrue(two.matchesInvoke("java/io/File", "<init>",
                "(Ljava/lang/String;Ljava/lang/String;)V"));
    }

    @Test
    void arraysAndPrimitivesUseJvmDescriptors() {
        TaiEMethodSignature signature = TaiEMethodSignature.parse(
                "<com.example.Sink: int run(int,java.lang.String[],boolean[])>");

        assertEquals("(I[Ljava/lang/String;[Z)I", signature.descriptor());
        assertTrue(signature.matchesInvoke("com/example/Sink", "run",
                "(I[Ljava/lang/String;[Z)I"));
    }

    @Test
    void rejectsOwnerOrNameOnlyAndIncompleteSignatures() {
        assertThrows(IllegalArgumentException.class,
                () -> TaiEMethodSignature.parse("<com.example.Sink: void consume>"));
        assertThrows(IllegalArgumentException.class,
                () -> TaiEMethodSignature.parse("<com.example.Sink: consume(java.lang.String)>"));
        assertThrows(IllegalArgumentException.class,
                () -> TaiEMethodSignature.parse("com.example.Sink consume(java.lang.String)"));
        assertThrows(IllegalArgumentException.class,
                () -> TaiEMethodSignature.parse("<com.example.Sink: void consume(,)>"));
    }

    @Test
    void normalizedIndexPreservesNumericAndNamedSelectors() {
        assertEquals("0", TaiEMethodSignature.normalizeIndex(0));
        assertEquals("base", TaiEMethodSignature.normalizeIndex("BASE"));
        assertEquals("result", TaiEMethodSignature.normalizeIndex(" result "));
        assertEquals(null, TaiEMethodSignature.normalizeIndex(null));
    }
}
