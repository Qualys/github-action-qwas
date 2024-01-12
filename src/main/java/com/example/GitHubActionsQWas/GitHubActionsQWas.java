package com.example.GitHubActionsQWas;

import com.example.GitHubActionsQWas.service.QualysWASScanBuilder;
import com.example.GitHubActionsQWas.service.QualysWASScanResultParser;
import com.example.GitHubActionsQWas.util.Helper;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
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

    public static void main(String[] args) throws Exception {
        ConfigurableApplicationContext ctx = SpringApplication.run(GitHubActionsQWas.class, args);
        Environment environment = ctx.getEnvironment();
        QualysWASScanBuilder builder = new QualysWASScanBuilder(environment);
        if (builder.isMandatoryParametersSet()) {
            builder.launchWebApplicationScan();
        } else {
            String message = "Few mandatory parameters are not set. Please set them and try again.";
            if (!builder.getWebAppId().isEmpty()) {
                message = message + " WebAppId: " + builder.getWebAppId();
                Helper.dumpDataIntoFile(message, "Qualys_Wasscan_" + builder.getWebAppId() + ".txt");
            } else {
                Helper.dumpDataIntoFile(message, "Qualys_Wasscan_Report.txt");
            }
            logger.error(message);
            System.exit(1);
        }
        ctx.getBean(GitHubActionsQWas.class);
        ctx.close();
    }
}
