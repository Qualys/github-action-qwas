package com.example.GitHubActionsQWas.util;

import org.apache.logging.log4j.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

@Component
public class Helper {
    static final Logger logger = LoggerFactory.getLogger(Helper.class);

    public Helper() {

    }

    public static int setTimeoutInMinutes(String timeoutType, int defaultTimeoutInMins, String timeout) {
        if (!(timeout == null || timeout.isEmpty())) {
            try {
                //if timeout is a regex of form 2*60*60 seconds, calculate the timeout in seconds
                String[] numbers = timeout.split("\\*");
                int timeoutInMins = 1;
                for (int i = 0; i < numbers.length; ++i) {
                    timeoutInMins *= Long.parseLong(numbers[i]);
                }
                return timeoutInMins;
            } catch (Exception e) {
                logger.error("Invalid " + timeoutType + " time value. Cannot parse -" + e.getMessage());
                logger.error("Using default period of " + (timeoutType.equals("vulnsTimeout") ? "60*24" : defaultTimeoutInMins) + " minutes for " + timeoutType + ".");
            }
        }
        return defaultTimeoutInMins;
    }

    public static void  dumpDataIntoFile(String data, String fileName) {
        String dirPath = "outputs";
        try {
            File dir = new File(dirPath);
            if (!dir.exists() || !dir.isDirectory()) {
                boolean isDirCreated = dir.mkdirs();
                if (!isDirCreated) {
                    logger.info("Error while creating directory: " + dirPath);

                }
            }
            String filePath = dirPath + "/" + fileName;
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
                writer.write(data);
                logger.info("Result artifact uploaded at location: " + filePath);
            } catch (Exception ex) {
                logger.info("Exception while uploading the result artifact at location: " + filePath + " Reason - " + ex.getMessage());
            }
        } catch (Exception ex) {
            logger.error("Something went wrong: " + ex.getMessage());
        }
    }

    public static String normalizeUrl(String url) {
        String normalized = url.trim();
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    public static String deriveGatewayUrl(String apiServer) {
        if (apiServer.contains("qualysapi.qualys.com")) {
            return apiServer.replace("qualysapi.qualys.com", "gateway.qg1.apps.qualys.com");
        }
        if (apiServer.contains("qualysapi.qualys.eu")) {
            return apiServer.replace("qualysapi.qualys.eu", "gateway.qg1.apps.qualys.eu");
        }
        if (apiServer.contains("qualysapi.gov1.qualys.us") || apiServer.matches("(?i)https?://qualysapi\\.qg\\d+\\.apps\\..+")) {
            return apiServer.replace("qualysapi.", "gateway.");
        }
        return apiServer.replace("qualysapi.", "qualysgateway.");
    }

    public static String derivePortalUrl(String apiServer) {
        return apiServer.replace("qualysapi.", "qualysguard.");
    }

    public static String getCompleteFileName(String fileName) {
        String filePath = Strings.EMPTY;
        String dirPath = "outputs";
        try {
            File dir = new File(dirPath);
            if (!dir.exists() || !dir.isDirectory()) {
                boolean isDirCreated = dir.mkdirs();
                if (!isDirCreated) {
                    logger.info("Error while creating directory: " + dirPath);
                }
            }
            filePath = dirPath + "/" + fileName;
        } catch (Exception ex) {
            logger.error("Something went wrong: " + ex.getMessage());
        }
        return filePath;
    }

}
