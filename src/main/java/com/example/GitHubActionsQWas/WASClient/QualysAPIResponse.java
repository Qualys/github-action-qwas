package com.example.GitHubActionsQWas.WASClient;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class QualysAPIResponse {
    public int responseCode;
    public boolean errored;
    public String errorMessage;

    public QualysAPIResponse() {
        this.responseCode = 0;
        this.errored = false;
        this.errorMessage = "";
    }
}
