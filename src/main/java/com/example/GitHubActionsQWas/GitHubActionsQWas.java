package com.example.GitHubActionsQWas;

import com.example.GitHubActionsQWas.WASClient.WASClient;
import com.example.GitHubActionsQWas.service.QualysWASScanBuilder;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.Environment;

@SpringBootApplication
public class GitHubActionsQWas {
    private static final Logger logger = LoggerFactory.getLogger(GitHubActionsQWas.class);

    public static void main(String[] args) {

        ConfigurableApplicationContext ctx = SpringApplication.run(GitHubActionsQWas.class, args);
        Environment environment = ctx.getEnvironment();
        QualysWASScanBuilder builder = new QualysWASScanBuilder(environment);
        if (builder.isMandatoryParametersSet()) {
            logger.debug(builder.toString());
            builder.launchWebApplicationScan();
//            WASClient client = builder.getClient();
//            JsonObject result = client.getScanResult("38710139").response;
//            builder.evaluateFailurePolicy(result);
        } else {
            logger.error("Few mandatory parameters are not set. Please set them and try again.");
        }
        ctx.getBean(GitHubActionsQWas.class);
        ctx.close();
    }
}
