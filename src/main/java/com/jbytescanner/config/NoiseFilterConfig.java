package com.jbytescanner.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * P0.6 noise / precision controls applied after taint flows are captured.
 */
@Data
public class NoiseFilterConfig {

    @JsonProperty("enabled")
    private boolean enabled = true;

    /** outside package + weak sink: suppress | demote */
    @JsonProperty("weak_sink_outside_package")
    private String weakSinkOutsidePackage = "suppress";

    /** terminal outside package: keep_demote_confidence | keep */
    @JsonProperty("terminal_outside_package")
    private String terminalOutsidePackage = "keep_demote_confidence";

    @JsonProperty("library_internal_weak")
    private String libraryInternalWeak = "suppress";

    @JsonProperty("library_package_deny")
    private List<String> libraryPackageDeny = new ArrayList<>();

    @JsonProperty("demote_plain_json_parse")
    private boolean demotePlainJsonParse = true;

    @JsonProperty("demote_template_without_path_evidence")
    private boolean demoteTemplateWithoutPathEvidence = true;

    /**
     * Outside/library constructors without same-method side effect: suppress | demote | keep.
     * In-app constructors are always demoted (never hard-suppressed) to avoid cross-method SSRF FN.
     */
    @JsonProperty("constructor_without_side_effect")
    private String constructorWithoutSideEffect = "suppress";

    /** off | exact */
    @JsonProperty("dedupe")
    private String dedupe = "exact";

    /** Vuln types that aggregate instances by sink location. */
    @JsonProperty("fan_in_rules")
    private List<String> fanInRules = new ArrayList<>(List.of(
            "SQL_Injection",
            "Velocity_Injection",
            "FreeMarker_Injection",
            "Thymeleaf_Injection",
            "Pebble_Injection"
    ));

    @JsonProperty("main_sarif_min_confidence")
    private double mainSarifMinConfidence = 0.5;

    @JsonProperty("main_sarif_always_include_terminal")
    private boolean mainSarifAlwaysIncludeTerminal = true;

    @JsonProperty("max_instances_in_sarif")
    private int maxInstancesInSarif = 10;

    @JsonProperty("emit_raw_flows")
    private boolean emitRawFlows = false;

    @JsonProperty("emit_suppressed_file")
    private boolean emitSuppressedFile = true;

    @JsonProperty("emit_low_confidence_file")
    private boolean emitLowConfidenceFile = true;

    public List<String> getLibraryPackageDeny() {
        if (libraryPackageDeny == null) {
            libraryPackageDeny = new ArrayList<>();
        }
        return libraryPackageDeny;
    }

    public List<String> getFanInRules() {
        if (fanInRules == null) {
            fanInRules = new ArrayList<>();
        }
        return fanInRules;
    }
}
