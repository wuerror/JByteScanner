package com.jbytescanner.engine;

import pascal.taie.frontend.java.JavaWorldBuilder;

/**
 * Compatibility alias retained for configurations that referenced the old
 * JByteScanner Soot workaround by class name.
 *
 * <p>Tai-e 0.5.4 uses {@link JavaWorldBuilder} by default. The new frontend no
 * longer relies on Soot for bytecode-to-IR conversion, so the reflective Soot
 * exclusion workaround previously implemented here is neither needed nor
 * compatible with the new {@code WorldBuilder} API.</p>
 *
 * @deprecated Omit {@code --world-builder} or use
 * {@code pascal.taie.frontend.java.JavaWorldBuilder} directly.
 */
@Deprecated
public class ResilientSootWorldBuilder extends JavaWorldBuilder {
}
