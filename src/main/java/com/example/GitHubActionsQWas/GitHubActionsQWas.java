package com.example.GitHubActionsQWas;

import com.example.GitHubActionsQWas.service.QualysWASScanBuilder;
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
        if (true) {
            logger.info(builder.toString());
            builder.launchWebApplicationScan();
        }
        ctx.getBean(GitHubActionsQWas.class);
        ctx.close();
    }
}
