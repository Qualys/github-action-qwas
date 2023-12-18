package com.example.GitHubActionsQWas.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class Helper {
    public static final Map<String, Map<String, String>> platformsList;
    private static final Logger logger = LoggerFactory.getLogger(Helper.class);

    static {
        Map<String, Map<String, String>> aList = new LinkedHashMap<String, Map<String, String>>();

        Map<String, String> platform1 = new HashMap<String, String>();
        platform1.put("name", "US Platform 1");
        platform1.put("code", "US_PLATFORM_1");
        platform1.put("url", "https://qualysapi.qualys.com");
        platform1.put("portal", "https://qualysguard.qualys.com");
        aList.put("US_PLATFORM_1", platform1);

        Map<String, String> platform2 = new HashMap<String, String>();
        platform2.put("name", "US Platform 2");
        platform2.put("code", "US_PLATFORM_2");
        platform2.put("url", "https://qualysapi.qg2.apps.qualys.com");
        platform2.put("portal", "https://qualysguard.qg2.apps.qualys.com");
        aList.put("US_PLATFORM_2", platform2);

        Map<String, String> platform3 = new HashMap<String, String>();
        platform3.put("name", "US Platform 3");
        platform3.put("code", "US_PLATFORM_3");
        platform3.put("url", "https://qualysapi.qg3.apps.qualys.com");
        platform3.put("portal", "https://qualysguard.qg3.apps.qualys.com");
        aList.put("US_PLATFORM_3", platform3);

        Map<String, String> platform4 = new HashMap<String, String>();
        platform4.put("name", "US Platform 4");
        platform4.put("code", "US_PLATFORM_4");
        platform4.put("url", "https://qualysapi.qg4.apps.qualys.com");
        platform4.put("portal", "https://qualysguard.qg4.apps.qualys.com");
        aList.put("US_PLATFORM_4", platform4);

        Map<String, String> platform5 = new HashMap<String, String>();
        platform5.put("name", "EU Platform 1");
        platform5.put("code", "EU_PLATFORM_1");
        platform5.put("url", "https://qualysapi.qualys.eu");
        platform5.put("portal", "https://qualysguard.qualys.eu");
        aList.put("EU_PLATFORM_1", platform5);

        Map<String, String> platform6 = new HashMap<String, String>();
        platform6.put("name", "EU Platform 2");
        platform6.put("code", "EU_PLATFORM_2");
        platform6.put("url", "https://qualysapi.qg2.apps.qualys.eu");
        platform6.put("portal", "https://qualysguard.qg2.apps.qualys.eu");
        aList.put("EU_PLATFORM_2", platform6);

        Map<String, String> platform7 = new HashMap<String, String>();
        platform7.put("name", "INDIA Platform");
        platform7.put("code", "INDIA_PLATFORM");
        platform7.put("url", "https://qualysapi.qg1.apps.qualys.in");
        platform7.put("portal", "https://qualysguard.qg1.apps.qualys.in");
        aList.put("INDIA_PLATFORM", platform7);

        Map<String, String> platform8 = new HashMap<String, String>();
        platform8.put("name", "CANADA Platform");
        platform8.put("code", "CANADA_PLATFORM");
        platform8.put("url", "https://qualysapi.qg1.apps.qualys.ca");
        platform8.put("portal", "https://qualysguard.qg1.apps.qualys.ca");
        aList.put("CANADA_PLATFORM", platform8);

        Map<String, String> platform9 = new HashMap<String, String>();
        platform9.put("name", "Private Cloud Platform");
        platform9.put("code", "PCP");
        platform9.put("url", "");
        aList.put("PCP", platform9);

        platformsList = Collections.unmodifiableMap(aList);
    }

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

    public static void dumpDataIntoFile(String data, String fileName) {
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
                logger.info("Data dumped at location: " + filePath);
            } catch (Exception ex) {
                logger.info("Exception while dumping the data at location: " + filePath + " Reason - " + ex.getMessage());
            }
        } catch (Exception ex) {
            logger.error("Something went wrong: " + ex.getMessage());
        }
    }
}
