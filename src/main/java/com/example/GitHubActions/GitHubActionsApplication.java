package com.example.GitHubActions;

import com.example.GitHubActions.WASClient.QualysWASResponse;
import com.example.GitHubActions.WASClient.WASClient;
import com.example.GitHubActions.service.QualysWASScanBuilder;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.Environment;

@SpringBootApplication
public class GitHubActionsApplication {
    private static final Logger logger = LoggerFactory.getLogger(GitHubActionsApplication.class);

    public static void main(String[] args) {

        ConfigurableApplicationContext ctx = SpringApplication.run(GitHubActionsApplication.class, args);
        Environment environment = ctx.getEnvironment();
        String username = environment.getProperty("QUALYS_USERNAME");
        String password = environment.getProperty("QUALYS_PASSWORD");
        String server = environment.getProperty("API_SERVER");
        boolean useProxy = Boolean.parseBoolean(environment.getProperty("USE_PROXY"));
        String scanId = environment.getProperty("SCAN_ID");

        logger.info("[Username: " + username + "]");
        logger.info("[Password: " + password + "]");
        logger.info("[Server: " + server + "]");
        logger.info("[Use-proxy: " + useProxy + "]");
        logger.info("[Scan-id: " + scanId + "]");

        QualysWASScanBuilder builder = new QualysWASScanBuilder(environment);
        logger.info(builder.toString());
        builder.launchWebApplicationScan();

        ctx.getBean(GitHubActionsApplication.class);
        ctx.close();
    }
}
