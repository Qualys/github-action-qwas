package com.example.GitHubActionsQWas.WASClient;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.google.gson.JsonObject;
import lombok.*;
import lombok.extern.slf4j.Slf4j;

@Getter
@Setter
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class QualysWASResponse extends QualysAPIResponse{
    public JsonObject response;

    public QualysWASResponse() {
        super();
        response = null;
    }
}
