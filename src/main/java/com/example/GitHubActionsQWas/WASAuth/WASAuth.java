package com.example.GitHubActionsQWas.WASAuth;

import ch.qos.logback.core.util.StringUtil;
import com.example.GitHubActionsQWas.WASClient.WASClient;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import lombok.Getter;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.nio.charset.StandardCharsets;

@Getter
public class WASAuth {
    private String server;
    private String username;
    private String password;
    private String clientId;
    private String clientSecret;
    private String authKey;
    private String authType;
    private String apiServer;
    private String proxyServer;
    private String proxyUsername;
    private String proxyPassword;
    private int proxyPort;
    private String idpTokenUrl;
    private String idpScope;
    private String idpAudience;
    private final Logger logger = LoggerFactory.getLogger(WASClient.class);

    public WASAuth(String apiServer) {
        this.apiServer = apiServer;
    }

    public void setWasCredentials(String server, String username, String password, String authType) {
        this.server = server;
        this.username = username;
        this.password = password;
        this.authType = authType;
    }

    public void setWasOAuthCredentials(String server, String clientId, String clientSecret, String authType) {
        this.server = server;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.authType = authType;
    }

    public void setWasIDPCredentials(String server, String clientId, String clientSecret, String idpTokenUrl, String idpScope, String idpAudience, String authType) {
        this.server = server;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.idpTokenUrl = idpTokenUrl;
        this.idpScope = idpScope;
        this.idpAudience = idpAudience;
        this.authType = authType;
    }

    public void setOAuthKey() throws Exception {
        WASClient client = new WASClient(this);
        CloseableHttpClient httpClient = client.getCloseableHttpClient();

        URL url = new URL(server + "/auth/oidc");
        logger.info("Making Request: " + url);

        HttpPost postRequest = new HttpPost(url.toString());
        postRequest.addHeader("Content-Type", "application/x-www-form-urlencoded");
        postRequest.addHeader("clientId", this.clientId);
        postRequest.addHeader("clientSecret", this.clientSecret);

        CloseableHttpResponse httpResponse = httpClient.execute(postRequest);
        logger.info("Server returned with ResponseCode: " + httpResponse.getStatusLine().getStatusCode());
        this.authKey = EntityUtils.toString(httpResponse.getEntity(), "UTF-8");
        logger.warn("OAUTH Key is generated successfully...");
        if (StringUtil.notNullNorEmpty(this.apiServer)) {
            this.server = this.apiServer;
        }
    }

    public void refreshOAuthKey() throws Exception {
        logger.info("Refreshing OAuth Auth Token");
        this.authKey = null;
        setOAuthKey();
    }

    public void setIDPOAuthToken() throws Exception {
        logger.info("Starting IDP token acquisition");
        logger.info("IDP Auth Configuration - Token URL: {}, Client ID: {}, Scope: {}, Audience: {}", 
            idpTokenUrl, clientId, idpScope != null ? idpScope : "not set", idpAudience != null ? idpAudience : "not set");

        WASClient client = new WASClient(this);
        CloseableHttpClient httpClient = client.getCloseableHttpClient();

        URL url = new URL(idpTokenUrl);
        logger.info("Making token request to IDP: {}", url);

        HttpPost postRequest = new HttpPost(url.toString());
        postRequest.addHeader("Content-Type", "application/x-www-form-urlencoded");

        // Build request body with client credentials grant
        StringBuilder requestBody = new StringBuilder();
        requestBody.append("grant_type=client_credentials");
        requestBody.append("&client_id=").append(clientId);
        requestBody.append("&client_secret=").append(clientSecret);
        
        if (idpScope != null && !idpScope.isEmpty()) {
            requestBody.append("&scope=").append(idpScope);
        }
        
        if (idpAudience != null && !idpAudience.isEmpty()) {
            requestBody.append("&audience=").append(idpAudience);
        }

        logger.debug("IDP Token Request Body: client_id={}, scope={}, audience={}", 
            clientId, idpScope, idpAudience);

        postRequest.setEntity(new StringEntity(requestBody.toString(), StandardCharsets.UTF_8));

        CloseableHttpResponse httpResponse = httpClient.execute(postRequest);
        int responseCode = httpResponse.getStatusLine().getStatusCode();
        logger.info("IDP Server returned with ResponseCode: {}", responseCode);

        String responseBody = EntityUtils.toString(httpResponse.getEntity(), "UTF-8");
        
        if (responseCode == 200 || responseCode == 201) {
            try {
                JsonObject jsonResponse = JsonParser.parseString(responseBody).getAsJsonObject();
                if (jsonResponse.has("access_token")) {
                    this.authKey = jsonResponse.get("access_token").getAsString();
                    logger.info("IDP OAuth token acquired successfully");
                    logger.debug("Token type: {}, expires_in: {}", 
                        jsonResponse.has("token_type") ? jsonResponse.get("token_type").getAsString() : "not specified",
                        jsonResponse.has("expires_in") ? jsonResponse.get("expires_in").getAsString() : "not specified");
                    
                    if (StringUtil.notNullNorEmpty(this.apiServer)) {
                        this.server = this.apiServer;
                        logger.info("API Server URL set to: {}", this.server);
                    }
                } else {
                    String errorMsg = "IDP response does not contain access_token. Response: " + responseBody;
                    logger.error(errorMsg);
                    throw new Exception(errorMsg);
                }
            } catch (Exception e) {
                String errorMsg = "Failed to parse IDP token response: " + e.getMessage() + ". Response: " + responseBody;
                logger.error(errorMsg);
                throw new Exception(errorMsg);
            }
        } else if (responseCode == 401) {
            String errorMsg = "IDP authentication failed with 401 Unauthorized. Invalid client credentials. Response: " + responseBody;
            logger.error(errorMsg);
            throw new Exception(errorMsg);
        } else {
            String errorMsg = "IDP token request failed with status code: " + responseCode + ". Response: " + responseBody;
            logger.error(errorMsg);
            throw new Exception(errorMsg);
        }
    }

    public void refreshIDPOAuthToken() throws Exception {
        logger.info("Refreshing IDP Auth Token");
        this.authKey = null;
        setIDPOAuthToken();
    }
}
