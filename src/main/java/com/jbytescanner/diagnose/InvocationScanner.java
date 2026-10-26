package com.jbytescanner.diagnose;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Deterministic ASM scan for an exact invoke site (owner + name + descriptor).
 *
 * <p>This check is intentionally independent of Tai-e. It proves only that a
 * matching bytecode invocation exists in the scanned artifact; it does not
 * prove reachability.</p>
 */
public final class InvocationScanner {

    private InvocationScanner() {
    }

    public record ArtifactPath(String path, String role) {
    }

    public record InvocationEvidence(
            String artifactPath,
            String artifactRole,
            String owner,
            String methodName,
            String descriptor,
            String callerSignature,
            int lineNumber,
            int opcode,
            boolean interfaceCall
    ) {
    }

    public record ScanResult(
            List<InvocationEvidence> matches,
            int artifactsScanned,
            List<String> errors,
            boolean truncated,
            int totalMatches
    ) {
        public boolean complete() {
            return errors.isEmpty() && !truncated;
        }
    }

    public static ScanResult scan(List<ArtifactPath> artifacts, TaiEMethodSignature target,
                                  int maxMatches) {
        if (target == null) {
            throw new IllegalArgumentException("Target signature is required");
        }
        int limit = maxMatches > 0 ? maxMatches : 200;
        List<InvocationEvidence> matches = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        int[] total = {0};
        int scanned = 0;
        for (ArtifactPath artifact : artifacts == null ? List.<ArtifactPath>of() : artifacts) {
            if (artifact == null || artifact.path() == null || artifact.path().isBlank()) {
                continue;
            }
            File file = new File(artifact.path());
            if (!file.exists()) {
                errors.add("artifact not found: " + artifact.path());
                continue;
            }
            scanned++;
            if (file.isDirectory()) {
                scanDirectory(file.toPath(), artifact, target, limit, matches, errors, total);
            } else {
                scanFile(file, artifact, target, limit, matches, errors, total);
            }
        }
        return new ScanResult(List.copyOf(matches), scanned, List.copyOf(errors),
                total[0] > matches.size(), total[0]);
    }

    private static void scanFile(File file, ArtifactPath artifact, TaiEMethodSignature target,
                                 int limit, List<InvocationEvidence> matches, List<String> errors,
                                 int[] total) {
        String name = file.getName().toLowerCase();
        if (name.endsWith(".jar") || name.endsWith(".war") || name.endsWith(".ear")) {
            scanJar(file, artifact, target, limit, matches, errors, total);
        } else if (name.endsWith(".class")) {
            try {
                scanClass(Files.readAllBytes(file.toPath()), artifact, target, limit, matches, total);
            } catch (Exception e) {
                errors.add(file.getAbsolutePath() + ": " + e.getMessage());
            }
        } else {
            errors.add("unsupported artifact type: " + file.getAbsolutePath());
        }
    }

    private static void scanDirectory(Path root, ArtifactPath artifact, TaiEMethodSignature target,
                                      int limit, List<InvocationEvidence> matches,
                                      List<String> errors, int[] total) {
        try (var stream = Files.walk(root)) {
            List<Path> classes = stream
                    .filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().endsWith(".class"))
                    .sorted(Comparator.comparing(Path::toString))
                    .toList();
            for (Path classFile : classes) {
                try {
                    scanClass(Files.readAllBytes(classFile), artifact, target, limit, matches, total);
                } catch (Exception e) {
                    errors.add(classFile + ": " + e.getMessage());
                }
            }
        } catch (IOException e) {
            errors.add(root + ": " + e.getMessage());
        }
    }

    private static void scanJar(File jarFile, ArtifactPath artifact, TaiEMethodSignature target,
                                int limit, List<InvocationEvidence> matches, List<String> errors,
                                int[] total) {
        try (JarFile jar = new JarFile(jarFile)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (!entry.getName().endsWith(".class")) {
                    continue;
                }
                try (InputStream in = jar.getInputStream(entry)) {
                    scanClass(in.readAllBytes(), artifact, target, limit, matches, total);
                } catch (Exception e) {
                    errors.add(jarFile.getAbsolutePath() + "!" + entry.getName()
                            + ": " + e.getMessage());
                }
            }
        } catch (IOException e) {
            errors.add(jarFile.getAbsolutePath() + ": " + e.getMessage());
        }
    }

    private static void scanClass(byte[] classBytes, ArtifactPath artifact,
                                  TaiEMethodSignature target, int limit,
                                  List<InvocationEvidence> matches, int[] total) {
        ClassReader reader = new ClassReader(classBytes);
        reader.accept(new ClassVisitor(Opcodes.ASM9) {
            private String className;

            @Override
            public void visit(int version, int access, String name, String signature,
                              String superName, String[] interfaces) {
                this.className = name;
            }

            @Override
            public MethodVisitor visitMethod(int access, String methodName,
                                             String methodDescriptor, String signature,
                                             String[] exceptions) {
                String containerSignature = TaiEMethodSignature.callerSignature(
                        className, methodName, methodDescriptor);
                return new MethodVisitor(Opcodes.ASM9) {
                    private int currentLine = -1;

                    @Override
                    public void visitLineNumber(int line, Label start) {
                        this.currentLine = line;
                    }

                    @Override
                    public void visitMethodInsn(int opcode, String owner, String calleeName,
                                                String calleeDescriptor, boolean isInterface) {
                        if (!target.matchesInvoke(owner, calleeName, calleeDescriptor)) {
                            return;
                        }
                        total[0]++;
                        if (matches.size() >= limit) {
                            return;
                        }
                        matches.add(new InvocationEvidence(
                                artifact.path(),
                                artifact.role(),
                                owner.replace('/', '.'),
                                calleeName,
                                calleeDescriptor,
                                containerSignature,
                                currentLine,
                                opcode,
                                isInterface
                        ));
                    }
                };
            }
        }, ClassReader.SKIP_FRAMES);
    }
}
