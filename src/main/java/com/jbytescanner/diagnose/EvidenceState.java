package com.jbytescanner.diagnose;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Three-valued evidence state used by diagnostic stages.
 *
 * <p>{@code NO} means the absence was proven for the stated scope. It must never
 * be used when the evidence source was unavailable, incomplete, or stale.</p>
 */
public enum EvidenceState {
    YES("yes"),
    NO("no"),
    UNKNOWN("unknown");

    private final String value;

    EvidenceState(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }
}
