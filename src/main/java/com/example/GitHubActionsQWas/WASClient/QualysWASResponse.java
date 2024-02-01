package com.example.GitHubActionsQWas.WASClient;

import com.google.gson.JsonObject;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class QualysWASResponse extends QualysAPIResponse{
    public JsonObject response;

    public QualysWASResponse() {
        super();
        response = null;
    }
}
