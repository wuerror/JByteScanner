package com.jbytescanner.engine;

import com.jbytescanner.config.Config;
import com.jbytescanner.config.ScanConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.MethodNode;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RuleManagerTransferTest {

    @TempDir
    Path tempDir;

    @Test
    void parseParamTypesExtractsFqcnList() {
        List<String> types = RuleManager.parseParamTypes(
                "<com.example.C: void m(com.example.Bean,java.lang.String,int)>");
        assertEquals(List.of("com.example.Bean", "java.lang.String", "int"), types);
        assertTrue(RuleManager.parseParamTypes("<com.example.C: void m()>").isEmpty());
    }

    @Test
    void frameworkAndJdkTypesAreExcludedAsBeans() {
        assertTrue(RuleManager.isFrameworkOrJdkType("java.lang.String"));
        assertTrue(RuleManager.isFrameworkOrJdkType("javax.servlet.http.HttpServletRequest"));
        assertTrue(RuleManager.isFrameworkOrJdkType("org.springframework.web.multipart.MultipartFile"));
        assertFalse(RuleManager.isFrameworkOrJdkType("com.example.DatabaseProperties"));
    }

    @Test
    void isBeanGetterAcceptsJavaBeansAccessors() {
        MethodNode getHost = method("getHost", "()Ljava/lang/String;", 0);
        MethodNode isEnabled = method("isEnabled", "()Ljava/lang/Boolean;", 0);
        MethodNode getclass = method("getclass", "()Ljava/lang/String;", 0);
        MethodNode withArg = method("getHost", "(I)Ljava/lang/String;", 0);
        MethodNode getClassMethod = method("getClass", "()Ljava/lang/Class;", 0);

        assertTrue(RuleManager.isBeanGetter(getHost));
        assertTrue(RuleManager.isBeanGetter(isEnabled));
        assertFalse(RuleManager.isBeanGetter(getclass));
        assertFalse(RuleManager.isBeanGetter(withArg));
        assertFalse(RuleManager.isBeanGetter(getClassMethod));
    }

    @Test
    void emitsFormattingAndRequestBeanGetterTransfers() throws Exception {
        Path classes = tempDir.resolve("classes");
        Path packageDir = classes.resolve("com/example");
        Files.createDirectories(packageDir);

        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "com/example/DatabaseProperties",
                null, "java/lang/Object", null);
        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();
        MethodVisitor getHost = cw.visitMethod(Opcodes.ACC_PUBLIC, "getHost",
                "()Ljava/lang/String;", null, null);
        getHost.visitCode();
        getHost.visitInsn(Opcodes.ACONST_NULL);
        getHost.visitInsn(Opcodes.ARETURN);
        getHost.visitMaxs(1, 1);
        getHost.visitEnd();
        MethodVisitor getConnectionUrl = cw.visitMethod(Opcodes.ACC_PUBLIC, "getConnectionUrl",
                "()Ljava/lang/String;", null, null);
        getConnectionUrl.visitCode();
        getConnectionUrl.visitInsn(Opcodes.ACONST_NULL);
        getConnectionUrl.visitInsn(Opcodes.ARETURN);
        getConnectionUrl.visitMaxs(1, 1);
        getConnectionUrl.visitEnd();
        cw.visitEnd();
        Files.write(packageDir.resolve("DatabaseProperties.class"), cw.toByteArray());

        Config config = new Config();
        config.setScanConfig(new ScanConfig());
        config.setSources(new ArrayList<>());
        config.setSinks(new ArrayList<>());
        config.setTransfers(new ArrayList<>());

        List<String> entries = List.of(
                "<com.example.SetupController: void dbtest(com.example.DatabaseProperties)>",
                "<com.example.SetupController: void plain(java.lang.String)>");

        Path workspace = tempDir.resolve("ws");
        Files.createDirectories(workspace);
        String generated = new RuleManager(config)
                .generateTaieConfig(entries, workspace.toFile(), List.of(classes.toString()));

        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        Map<String, Object> document = mapper.readValue(Path.of(generated).toFile(), new TypeReference<>() {});
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> transfers = (List<Map<String, Object>>) document.get("transfers");

        assertTrue(transfers.stream().anyMatch(t ->
                String.valueOf(t.get("method")).contains("MessageFormatter")
                        && "arrayFormat".equals(methodName(String.valueOf(t.get("method"))))));
        assertTrue(transfers.stream().anyMatch(t ->
                String.valueOf(t.get("method")).contains("FormattingTuple: java.lang.String getMessage()")));
        assertTrue(transfers.stream().anyMatch(t ->
                "<com.example.DatabaseProperties: java.lang.String getHost()>".equals(t.get("method"))
                        && "base".equals(String.valueOf(t.get("from")))
                        && "result".equals(String.valueOf(t.get("to")))));
        assertTrue(transfers.stream().anyMatch(t ->
                "<com.example.DatabaseProperties: java.lang.String getConnectionUrl()>".equals(t.get("method"))
                        && "base".equals(String.valueOf(t.get("from")))
                        && "result".equals(String.valueOf(t.get("to")))));

        Set<String> beanTypes = RuleManager.extractAppEntryBeanTypes(entries, List.of(classes.toString()));
        assertEquals(Set.of("com.example.DatabaseProperties"), beanTypes);
    }

    private static String methodName(String signature) {
        int open = signature.lastIndexOf('(');
        int space = signature.lastIndexOf(' ', open);
        if (space < 0 || open < 0) {
            return "";
        }
        return signature.substring(space + 1, open);
    }

    private static MethodNode method(String name, String desc, int access) {
        return new MethodNode(Opcodes.ASM9, access | Opcodes.ACC_PUBLIC, name, desc, null, null);
    }
}
