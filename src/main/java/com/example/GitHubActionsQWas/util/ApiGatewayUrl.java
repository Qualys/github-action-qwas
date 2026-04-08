package com.example.GitHubActionsQWas.util;

import lombok.Getter;

@Getter
public enum ApiGatewayUrl {
  US1 ("https://gateway.qualys.com"),
  US2 ("https://gateway.qg2.apps.qualys.com"),
  US3 ("https://gateway.qg3.apps.qualys.com"),
  US4 ("https://gateway.qg4.apps.qualys.com"),
  EU1 ("https://gateway.qualys.eu"),
  EU2 ("https://gateway.qg2.apps.qualys.eu"),
  EU3 ("https://gateway.qg3.apps.qualys.eu"),
  IN1 ("https://gateway.qg1.apps.qualys.in"),
  CA1 ("https://gateway.qg1.apps.qualys.ca"),
  AE1 ("https://gateway.qg1.apps.qualys.ae"),
  UK1 ("https://gateway.qg1.apps.qualys.co.uk"),
  AU1 ("https://gateway.qg1.apps.qualys.com.au"),
  KSA1 ("https://gateway.qg1.apps.qualysksa.com")
  ;

  private final String url;

  ApiGatewayUrl(String url) {
    this.url = url;
  }

  public static ApiGatewayUrl getByKey(String key) throws Exception {
    try {
      return valueOf(key.toUpperCase());
    } catch (Exception e) {
      String exception = String.format("Exception: You have entered invalid platform {%s}, Please visit following url to identify correct platform - %s",
              key.toUpperCase(),
              "https://www.qualys.com/platform-identification ");
      throw new Exception(exception);
    }
  }
}
