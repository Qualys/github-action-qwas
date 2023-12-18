package com.example.GitHubActionsQWas.WASClient;

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
