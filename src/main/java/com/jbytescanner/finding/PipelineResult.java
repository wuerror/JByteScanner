package com.jbytescanner.finding;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class PipelineResult {

    public int flowsRaw;
    public int findingsAfterExactDedupe;
    public int findingsAfterFanIn;

    public final List<CanonicalFinding> mainFindings = new ArrayList<>();
    public final List<CanonicalFinding> lowConfidenceFindings = new ArrayList<>();
    public final List<CanonicalFinding> suppressedFindings = new ArrayList<>();

    public final Map<String, Integer> suppressedByReason = new LinkedHashMap<>();
    public final Map<String, Integer> lowConfidenceByReason = new LinkedHashMap<>();

    public String authSource = "unavailable";

    public void bumpReason(Map<String, Integer> map, List<String> reasons) {
        if (reasons == null) {
            return;
        }
        for (String r : reasons) {
            map.merge(r, 1, Integer::sum);
        }
    }

    public Map<String, Object> toBenchmarkMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("flowsRaw", flowsRaw);
        m.put("findingsAfterExactDedupe", findingsAfterExactDedupe);
        m.put("findingsAfterFanIn", findingsAfterFanIn);
        m.put("mainSarifResults", mainFindings.size());
        m.put("lowConfidenceResults", lowConfidenceFindings.size());
        m.put("suppressedResults", suppressedFindings.size());
        m.put("flowsSuppressedByReason", new LinkedHashMap<>(suppressedByReason));
        m.put("flowsLowConfidenceByReason", new LinkedHashMap<>(lowConfidenceByReason));
        m.put("authSource", authSource);
        return m;
    }
}
