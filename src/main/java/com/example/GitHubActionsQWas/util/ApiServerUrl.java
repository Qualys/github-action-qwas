package com.example.GitHubActionsQWas.util;

import lombok.Getter;

@Getter
public enum ApiServerUrl {
  US1 ("https://qualysapi.qualys.com"),
  US2 ("https://qualysapi.qg2.apps.qualys.com"),
  US3 ("https://qualysapi.qg3.apps.qualys.com"),
  US4 ("https://qualysapi.qg4.apps.qualys.com"),
  EU1 ("https://qualysapi.qualys.eu"),
  EU2 ("https://qualysapi.qg2.apps.qualys.eu"),
  EU3 ("https://qualysapi.qg3.apps.qualys.eu"),
  IN1 ("https://qualysapi.qg1.apps.qualys.in"),
  CA1 ("https://qualysapi.qg1.apps.qualys.ca"),
  AE1 ("https://qualysapi.qg1.apps.qualys.ae"),
  UK1 ("https://qualysapi.qg1.apps.qualys.co.uk"),
  AU1 ("https://qualysapi.qg1.apps.qualys.com.au"),
  KSA1 ("https://qualysapi.qg1.apps.qualysksa.com")
  ;

  private final String url;

  ApiServerUrl(String url) {
    this.url = url;
  }

  public static ApiServerUrl getByKey(String key) throws Exception {
    try {
      return valueOf(key.toUpperCase());
    } catch (IllegalArgumentException e) {
      String exception = String.format("Exception: You have entered invalid platform {%s}, Please visit following url to identify correct platform - %s",
              key.toUpperCase(),
              "https://www.qualys.com/platform-identification ");
      throw new Exception(exception);
    }
  }
}
