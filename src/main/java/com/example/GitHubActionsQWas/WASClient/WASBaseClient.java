package com.example.GitHubActionsQWas.WASClient;

import com.example.GitHubActionsQWas.WASAuth.WASAuth;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.routing.HttpRoutePlanner;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;

import java.io.PrintStream;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

public class WASBaseClient {
    WASAuth auth;
    protected PrintStream stream;
    protected int timeout = 30;

    public WASBaseClient(WASAuth auth) {
        this.auth = auth;
        this.stream = System.out;
    }

    public WASBaseClient(WASAuth auth, PrintStream stream) {
        this.auth = auth;
        this.stream = stream;
    }

    protected CloseableHttpClient getHttpClient() throws NoSuchAlgorithmException, KeyManagementException {
        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout(this.timeout * 1000)
                .setConnectionRequestTimeout(this.timeout * 1000)
                .setSocketTimeout(this.timeout * 1000)
                .build();

        SSLContextBuilder builder = new SSLContextBuilder();
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build());
        final HttpClientBuilder clientBuilder = HttpClients.custom().setSSLSocketFactory(sslsf);

        final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();

        clientBuilder.setDefaultRequestConfig(config);
        clientBuilder.setDefaultCredentialsProvider(credentialsProvider);

        if (this.auth.getProxyServer() != null && !this.auth.getProxyServer().isEmpty()) {
            final HttpHost proxyHost = new HttpHost(this.auth.getProxyServer(), this.auth.getProxyPort());
            final HttpRoutePlanner routePlanner = new DefaultProxyRoutePlanner(proxyHost);
            clientBuilder.setRoutePlanner(routePlanner);

            String username = this.auth.getProxyUsername();
            String password = this.auth.getProxyPassword();

            if (username != null && !username.trim().equals("")) {
                System.out.println("Using proxy authentication (user=" + username + ")");
                credentialsProvider.setCredentials(new AuthScope(proxyHost),
                        new UsernamePasswordCredentials(username, password));
            }
        }

        return clientBuilder.build();
    }
}
