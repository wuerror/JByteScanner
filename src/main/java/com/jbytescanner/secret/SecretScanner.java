package com.jbytescanner.secret;

import com.jbytescanner.core.JarLoader;
import com.jbytescanner.secret.asm.AsmStringCollector;
import org.objectweb.asm.ClassReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.StringConstant;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class SecretScanner {
    private static final Logger logger = LoggerFactory.getLogger(SecretScanner.class);
    
    // Regex Patterns
    private static final Pattern AWS_ACCESS_KEY = Pattern.compile("AKIA[0-9A-Z]{16}");
    private static final Pattern GENERIC_SECRET = Pattern.compile("(?i)(password|secret|token|api_?key|access_?key)\\s*[:=]\\s*['\"]?([^\\s'\"]{5,})['\"]?");
    private static final Pattern BASE64_PATTERN = Pattern.compile("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$");
    private static final Pattern JDBC_PATTERN = Pattern.compile("jdbc:[a-z:]+://.*");
    
    // Hash Patterns
    private static final Pattern HEX_HASH_PATTERN = Pattern.compile("^[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}$");
    private static final Pattern SENSITIVE_VAR_NAME = Pattern.compile("(?i)(token|secret|admin|pass|auth|pwd|key|sign|md5|sha)");

    public List<SecretFinding> scan(List<String> targetAppJars) {
        List<SecretFinding> findings = new ArrayList<>();
        
        logger.info("Starting Secret Scanner (Hybrid Mode: ASM + Soot)...");

        // 1. Scan Configuration Files
        for (String path : targetAppJars) {
            File file = new File(path);
            if (file.isDirectory()) {
                findings.addAll(scanDirectory(file));
            }
        }

        // 2. Scan Constant Pool using ASM (Fast Scan)
        findings.addAll(scanWithAsm(targetAppJars));

        logger.info("Secret Scanner found {} potential secrets.", findings.size());
        return findings;
    }

    private List<SecretFinding> scanDirectory(File dir) {
        List<SecretFinding> findings = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(dir.toPath())) {
            walk.filter(p -> !Files.isDirectory(p))
                .filter(this::isConfigFile)
                .forEach(p -> findings.addAll(scanFile(p.toFile())));
        } catch (IOException e) {
            logger.error("Error walking directory: {}", dir, e);
        }
        return findings;
    }

    private boolean isConfigFile(Path p) {
        String name = p.getFileName().toString().toLowerCase();
        return name.endsWith(".properties") || 
               name.endsWith(".yml") || 
               name.endsWith(".yaml") || 
               name.endsWith(".xml") ||
               name.endsWith(".json");
    }

    private List<SecretFinding> scanFile(File file) {
        List<SecretFinding> findings = new ArrayList<>();
        try {
            List<String> lines = Files.readAllLines(file.toPath());
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                
                Matcher m = GENERIC_SECRET.matcher(line);
                if (m.find()) {
                    String match = m.group(0);
                    findings.add(new SecretFinding(
                        "Config Secret",
                        file.getAbsolutePath(),
                        m.group(2),
                        "Line " + (i + 1) + ": " + match.trim(),
                        "MEDIUM"
                    ));
                }

                Matcher aws = AWS_ACCESS_KEY.matcher(line);
                if (aws.find()) {
                    findings.add(new SecretFinding(
                        "AWS Access Key",
                        file.getAbsolutePath(),
                        aws.group(0),
                        "Line " + (i + 1),
                        "HIGH"
                    ));
                }
            }
        } catch (IOException e) {
            logger.warn("Could not read file: {}", file);
        }
        return findings;
    }

    private List<SecretFinding> scanWithAsm(List<String> targetAppJars) {
        List<SecretFinding> findings = new ArrayList<>();
        AsmStringCollector collector = new AsmStringCollector();
        
        logger.info("Scanning .class files with ASM...");
        
        for (String jarPath : targetAppJars) {
            File jarFile = new File(jarPath);
            if (jarFile.isDirectory()) {
                scanDirWithAsm(jarFile, collector);
            } else if (jarFile.isFile() && jarPath.endsWith(".jar")) {
                scanJarWithAsm(jarFile, collector);
            }
        }
        
        Map<String, List<String>> collected = collector.getCollectedStrings();
        logger.info("ASM extracted strings from {} methods. Processing...", collected.size());
        
        Set<String> methodsRequiringContext = new HashSet<>();
        
        // Analyze extracted strings
        for (Map.Entry<String, List<String>> entry : collected.entrySet()) {
            String methodSig = entry.getKey();
            List<String> strings = entry.getValue();
            
            for (String value : strings) {
                // If it's a simple secret, report immediately
                // If it's a Hash, mark method for Soot Analysis
                
                // AWS
                if (AWS_ACCESS_KEY.matcher(value).find()) {
                    findings.add(new SecretFinding("AWS Access Key", methodSig, value, "ASM Fast Scan", "HIGH"));
                    continue;
                }
                
                // JDBC
                if (JDBC_PATTERN.matcher(value).matches() && value.contains("password=")) {
                     findings.add(new SecretFinding("JDBC Connection String", methodSig, value, "Hardcoded JDBC", "MEDIUM"));
                     continue;
                }
                
                // Hash Check
                if (HEX_HASH_PATTERN.matcher(value).matches()) {
                    methodsRequiringContext.add(methodSig); // Delegate to Soot
                    continue;
                }
                
                // High Entropy & Base64
                if (value.length() > 16) {
                    if (value.startsWith("HTTP/") || value.contains(" ")) {
                        if (!value.toLowerCase().startsWith("bearer ")) continue; 
                    }

                    double entropy = calculateEntropy(value);
                    if (entropy > 4.6) {
                        if (isBase64(value)) {
                             try {
                                 String decoded = new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8);
                                 if (GENERIC_SECRET.matcher("val=" + decoded).find()) {
                                      findings.add(new SecretFinding("Encoded Secret (Base64)", methodSig, value + " -> " + decoded, "Base64 High Entropy", "HIGH"));
                                 } else {
                                      findings.add(new SecretFinding("High Entropy String", methodSig, value, "Entropy: " + String.format("%.2f", entropy), "LOW"));
                                 }
                             } catch (IllegalArgumentException e) {
                                 findings.add(new SecretFinding("High Entropy String", methodSig, value, "Entropy: " + String.format("%.2f", entropy), "LOW"));
                             }
                        } else {
                             findings.add(new SecretFinding("High Entropy String", methodSig, value, "Entropy: " + String.format("%.2f", entropy), "LOW"));
                        }
                    }
                }
            }
        }
        
        // Phase 2: Context Analysis with Soot (Only for identified methods)
        if (!methodsRequiringContext.isEmpty()) {
            logger.info("Performing deep context analysis on {} suspicious methods...", methodsRequiringContext.size());
            findings.addAll(analyzeContextWithSoot(methodsRequiringContext));
        }
        
        return findings;
    }
    
    private void scanDirWithAsm(File dir, AsmStringCollector collector) {
        try (Stream<Path> walk = Files.walk(dir.toPath())) {
            walk.filter(p -> p.toString().endsWith(".class"))
                .forEach(p -> {
                    try (InputStream is = Files.newInputStream(p)) {
                        new ClassReader(is).accept(collector, 0);
                    } catch (Exception e) {
                        // ignore broken class
                    }
                });
        } catch (IOException e) {
            logger.error("Error walking directory for ASM: {}", dir, e);
        }
    }
    
    private void scanJarWithAsm(File jarFile, AsmStringCollector collector) {
        try (ZipFile zip = new ZipFile(jarFile)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".class")) {
                    try (InputStream is = zip.getInputStream(entry)) {
                        new ClassReader(is).accept(collector, 0);
                    } catch (Exception e) {
                        // ignore
                    }
                }
            }
        } catch (IOException e) {
            logger.error("Error reading jar for ASM: {}", jarFile, e);
        }
    }

    private List<SecretFinding> analyzeContextWithSoot(Set<String> methodSigs) {
        List<SecretFinding> findings = new ArrayList<>();
        
        for (String methodId : methodSigs) {
            // methodId is "com.example.Class#methodName"
            String className = methodId.split("#")[0];
            String methodName = methodId.split("#")[1];
            
            if (!Scene.v().containsClass(className)) continue;
            
            SootClass sc = Scene.v().getSootClass(className);
            if (sc.isPhantom()) continue;
            
            // Iterate over all methods with that name (handling overloads)
            for (SootMethod sm : sc.getMethods()) {
                if (sm.getName().equals(methodName)) {
                    if (!sm.hasActiveBody()) {
                        try {
                            sm.retrieveActiveBody();
                        } catch (Exception e) {
                            continue;
                        }
                    }
                    
                    try {
                        for (Unit u : sm.getActiveBody().getUnits()) {
                            for (ValueBox vb : u.getUseBoxes()) {
                                if (vb.getValue() instanceof StringConstant) {
                                    String value = ((StringConstant) vb.getValue()).value;
                                    // Check Hash again in context
                                    if (HEX_HASH_PATTERN.matcher(value).matches()) {
                                        checkHashUsage(value, sc.getName() + "." + sm.getName(), findings, u);
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        // ignore
                    }
                }
            }
        }
        return findings;
    }

    private void checkHashUsage(String value, String location, List<SecretFinding> findings, Unit u) {
        boolean isSuspicious = false;
        String reason = "";

        // Context 1: Method Call (e.g., equals, unknown_check)
        if (u instanceof soot.jimple.InvokeStmt) {
            soot.jimple.InvokeExpr invoke = ((soot.jimple.InvokeStmt) u).getInvokeExpr();
            String methodName = invoke.getMethod().getName();
            if (methodName.equals("equals") || methodName.equals("equalsIgnoreCase") || methodName.equals("contentEquals")) {
                isSuspicious = true;
                reason = "Hardcoded Hash in equality check";
            }
        } else if (u instanceof soot.jimple.AssignStmt) {
             soot.jimple.AssignStmt assign = (soot.jimple.AssignStmt) u;
             
             // Context 2: Assignment to Field/Variable with sensitive name
             // Check Left Hand Side (Target)
             Value left = assign.getLeftOp();
             if (left instanceof soot.jimple.FieldRef) {
                 String fieldName = ((soot.jimple.FieldRef) left).getField().getName();
                 if (SENSITIVE_VAR_NAME.matcher(fieldName).find()) {
                     isSuspicious = true;
                     reason = "Assigned to sensitive field: " + fieldName;
                 }
             } 
             
             // Check Right Hand Side (Invoke)
             // e.g., boolean x = token.equals("hash");
             if (assign.getRightOp() instanceof soot.jimple.InvokeExpr) {
                 soot.jimple.InvokeExpr invoke = (soot.jimple.InvokeExpr) assign.getRightOp();
                 String methodName = invoke.getMethod().getName();
                 if (methodName.equals("equals") || methodName.equals("equalsIgnoreCase") || methodName.equals("contentEquals")) {
                     // Verify if our string is one of the args
                     for (Value arg : invoke.getArgs()) {
                         if (arg instanceof StringConstant && ((StringConstant)arg).value.equals(value)) {
                             isSuspicious = true;
                             reason = "Hardcoded Hash in equality check";
                             break;
                         }
                     }
                 }
             }
         }
        
        if (isSuspicious) {
            findings.add(new SecretFinding("Hardcoded Hash Credential", location, value, reason, "HIGH"));
        }
    }
    
    private boolean isBase64(String s) {
        return BASE64_PATTERN.matcher(s).matches();
    }

    private double calculateEntropy(String s) {
        if (s == null || s.isEmpty()) return 0.0;
        java.util.Map<Character, Integer> frequency = new java.util.HashMap<>();
        for (char c : s.toCharArray()) {
            frequency.put(c, frequency.getOrDefault(c, 0) + 1);
        }
        double entropy = 0.0;
        for (int count : frequency.values()) {
            double p = (double) count / s.length();
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    public void writeReport(File workspaceDir, List<SecretFinding> findings) {
        File reportFile = new File(workspaceDir, "secrets.txt");
        List<String> lines = new ArrayList<>();
        lines.add("### Secret Scan Report ###");
        lines.add("Total Findings: " + findings.size());
        lines.add("--------------------------------------------------");

        for (SecretFinding finding : findings) {
            lines.add(String.format("[%s] %s", finding.getSeverity(), finding.getType()));
            lines.add("Location: " + finding.getLocation());
            lines.add("Context: " + finding.getContext());
            lines.add("Value: " + finding.getMatchedValue()); 
            lines.add("--------------------------------------------------");
        }

        try {
            Files.write(reportFile.toPath(), lines);
            logger.info("Secret report written to: {}", reportFile.getAbsolutePath());
        } catch (IOException e) {
            logger.error("Failed to write secret report", e);
        }
    }
}
