package com.jbytescanner.worker;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class EntryCheckEvidence {

    @JsonProperty("signature")
    public String signature;

    @JsonProperty("status")
    public String status;

    @JsonProperty("inApplicationScope")
    public boolean inApplicationScope;

    @JsonProperty("declaringClassPhantom")
    public boolean declaringClassPhantom;

    @JsonProperty("detail")
    public String detail;
}
