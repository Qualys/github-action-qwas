package com.example.GitHubActions.WASAuth;

public class WASAuth {
    private String server;
    private String username;
    private String password;
    private String authKey;
    private String proxyServer;
    private String proxyUsername;
    private String proxyPassword;
    private int proxyPort;

    public WASAuth() {
    }

    public WASAuth(String oauthKey) {
        this.authKey = oauthKey;
    }

    public String getServer() {
        return server;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getAuthKey() {
        return authKey;
    }

    public String getProxyServer() {
        return proxyServer;
    }

    public String getProxyUsername() {
        return proxyUsername;
    }

    public String getProxyPassword() {
        return proxyPassword;
    }

    public int getProxyPort() {
        return proxyPort;
    }

    public void setWasCredentials(String server, String username, String password) {
        this.server = server;
        this.username = username;
        this.password = password;
    }
    public void setProxyCredentials(String proxyServer, int proxyPort, String proxyUsername, String proxyPassword) {
        this.proxyServer = proxyServer;
        this.proxyUsername = proxyUsername;
        this.proxyPassword = proxyPassword;
        this.proxyPort = proxyPort;
    }
}
