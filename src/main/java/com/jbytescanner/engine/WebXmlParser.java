package com.jbytescanner.engine;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.InputStream;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class WebXmlParser {
    private static final Logger logger = LoggerFactory.getLogger(WebXmlParser.class);

    /**
     * Parse web.xml inside a JAR file and return a map of Servlet Class -> List of URL Patterns
     */
    public Map<String, List<String>> parse(File jarFile) {
        Map<String, List<String>> routes = new HashMap<>();
        
        if (!jarFile.exists() || !jarFile.getName().endsWith(".jar")) {
            return routes;
        }

        try (JarFile jar = new JarFile(jarFile)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                
                // Recursively search for web.xml (e.g., WEB-INF/web.xml, webapp/web.xml)
                // Using exact name match or suffix match to be safe
                if (name.endsWith("web.xml") && !name.contains("classes/")) { // Avoid resources inside classes if any
                    logger.debug("Found web.xml in {}: {}", jarFile.getName(), name);
                    try (InputStream is = jar.getInputStream(entry)) {
                        parseWebXml(is, routes);
                    } catch (Exception e) {
                        logger.error("Failed to parse web.xml in {}", jarFile.getName(), e);
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Failed to process JAR for web.xml: {}", jarFile.getName(), e);
        }
        
        return routes;
    }

    private void parseWebXml(InputStream is, Map<String, List<String>> routes) throws Exception {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        // Secure processing to prevent XXE
        dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbFactory.setNamespaceAware(true); // Handle namespaces if present

        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(is);
        doc.getDocumentElement().normalize();

        // 1. Extract Servlets: Name -> Class
        Map<String, String> servletNameMap = new HashMap<>();
        NodeList servletNodes = doc.getElementsByTagName("servlet"); // Simple tag name search ignores namespace
        if (servletNodes.getLength() == 0) {
            // Try with namespace awareness if simple search fails (though getElementsByTagName usually works)
            servletNodes = doc.getElementsByTagNameNS("*", "servlet");
        }

        for (int i = 0; i < servletNodes.getLength(); i++) {
            Element element = (Element) servletNodes.item(i);
            String servletName = getTagValue("servlet-name", element);
            String servletClass = getTagValue("servlet-class", element);
            
            if (servletName != null && servletClass != null) {
                servletNameMap.put(servletName, servletClass);
            }
        }

        // 2. Extract Mappings: Name -> URL Pattern
        NodeList mappingNodes = doc.getElementsByTagName("servlet-mapping");
        if (mappingNodes.getLength() == 0) {
            mappingNodes = doc.getElementsByTagNameNS("*", "servlet-mapping");
        }

        for (int i = 0; i < mappingNodes.getLength(); i++) {
            Element element = (Element) mappingNodes.item(i);
            String servletName = getTagValue("servlet-name", element);
            String urlPattern = getTagValue("url-pattern", element);
            
            if (servletName != null && urlPattern != null) {
                String servletClass = servletNameMap.get(servletName);
                if (servletClass != null) {
                    routes.computeIfAbsent(servletClass, k -> new ArrayList<>()).add(urlPattern);
                }
            }
        }
    }

    private String getTagValue(String tag, Element element) {
        NodeList nodeList = element.getElementsByTagName(tag);
        if (nodeList.getLength() == 0) {
            nodeList = element.getElementsByTagNameNS("*", tag);
        }
        
        if (nodeList.getLength() > 0) {
            Node node = nodeList.item(0).getFirstChild();
            if (node != null) {
                return node.getNodeValue().trim();
            }
        }
        return null;
    }
}
