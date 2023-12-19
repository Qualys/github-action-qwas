package com.example.GitHubActions;

import com.example.GitHubActions.service.QualysWASScanBuilder;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import com.example.GitHubActions.util.Helper;
import org.springframework.core.env.Environment;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

@SpringBootApplication
public class GitHubActionsApplication {
    private static final Logger logger = LoggerFactory.getLogger(GitHubActionsApplication.class);
    private static final Helper helper = new Helper();

    private static final ScheduledExecutorService scheduledExecutorService = Executors.newScheduledThreadPool(1);

    public static void main(String[] args) throws Exception {

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

//        logger.info(status);
        ctx.getBean(GitHubActionsApplication.class);
        ctx.close();
    }
}
