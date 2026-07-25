package com.jbytescanner.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanConfigPersistentSourceTest {

    @Test
    void acceptsLegacyBooleanAndStringModes() {
        ScanConfig c = new ScanConfig();
        c.setPersistentSourceAnalysis(true);
        assertEquals("on", c.getPersistentSourceMode());
        c.setPersistentSourceAnalysis(false);
        assertEquals("off", c.getPersistentSourceMode());
        c.setPersistentSourceAnalysis("auto");
        assertEquals("auto", c.getPersistentSourceMode());
    }

    @Test
    void autoDisablesAboveClasspathThreshold() {
        ScanConfig c = new ScanConfig();
        c.setPersistentSourceAnalysis("auto");
        c.setPersistentSourceAutoMaxAppClasspath(120);
        ScanConfig.PersistentSourceDecision on = c.resolvePersistentSourceEnabled(50);
        assertTrue(on.enabled());
        ScanConfig.PersistentSourceDecision off = c.resolvePersistentSourceEnabled(200);
        assertFalse(off.enabled());
        assertTrue(off.reason().contains("appClasspathCount"));
    }

    @Test
    void offModeAlwaysDisabled() {
        ScanConfig c = new ScanConfig();
        c.setPersistentSourceAnalysis("off");
        assertFalse(c.resolvePersistentSourceEnabled(1).enabled());
    }

    @Test
    void onModeDefaultKeepsEnabled() {
        ScanConfig c = new ScanConfig();
        assertEquals("on", c.getPersistentSourceMode());
        assertTrue(c.resolvePersistentSourceEnabled(9999).enabled());
        assertFalse(c.isSpringServiceEntryFallback());
        assertTrue(c.isTaintCallSiteMode());
        assertTrue(c.isSpringAnalysis());
    }
}
