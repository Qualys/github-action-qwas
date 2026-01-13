package com.example.GitHubActionsQWas.WASAuth;

import com.example.GitHubActionsQWas.WASClient.QualysWASResponse;
import com.example.GitHubActionsQWas.WASClient.WASBaseClient;
import com.example.GitHubActionsQWas.WASClient.WASClient;
import lombok.Getter;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

@Getter
public class WASAuth {
    private String server;
    private String username;
    private String password;
    private String clientId;
    private String clientSecret;
    private String authKey;
    private String authType;
    private String proxyServer;
    private String proxyUsername;
    private String proxyPassword;
    private int proxyPort;
    private final Logger logger = LoggerFactory.getLogger(WASClient.class);

    public WASAuth() {
    }

    public WASAuth(String oauthKey) {
        this.authKey = oauthKey;
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

    public void setOAuthKey() throws NoSuchAlgorithmException, KeyManagementException, IOException {
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
    }
}
