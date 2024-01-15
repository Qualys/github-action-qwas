package com.example.GitHubActionsQWas.service;

import com.example.GitHubActionsQWas.WASClient.WASClient;
import com.example.GitHubActionsQWas.util.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;

public class QualysWASScanStatusService {
    private static final Logger logger = LoggerFactory.getLogger(QualysWASScanStatusService.class);
    private WASClient client;

    public QualysWASScanStatusService(WASClient client) {
        this.client = client;
    }

    /**
     * @param scanId
     * @return
     */
    public String fetchScanStatus(String scanId, String scanType, boolean severityCheck, String portalUrl, int INTERVAL, int TIMEOUT) {
        long startTime = System.currentTimeMillis();
        long timeoutInMillis = TimeUnit.MINUTES.toMillis(TIMEOUT);
        long intervalInMillis = TimeUnit.MINUTES.toMillis(INTERVAL);
        String status = null;
        boolean failed = false;

        try {
            while ((status = client.getScanFinishedStatus(scanId)) == null) {
                long endTime = System.currentTimeMillis();
                if ((endTime - startTime) > timeoutInMillis) {
                    String message1 = "Failed to get scan result; timeout of " + TIMEOUT + " minutes reached.";
                    String message2 = "Please switch to WAS Classic UI and Check for report...";
                    String message3 = "To check scan result, please follow the url: " + portalUrl + "/portal-front/module/was/#forward=/module/was/&scan-report=" + scanId;
                    logger.info(message1);
                    logger.info(message2);
                    logger.info(message3);
                    if (scanType.equalsIgnoreCase("vulnerability") && severityCheck) {
                        failed = true;
                    }
                    if (failed) {
                        String message = message1 + "\n" + message2 + "\n" + message3;
                        Helper.dumpDataIntoFile(message, "Qualys_Wasscan_" + scanId + ".txt");
                        System.exit(1);
                    }
                } else {
                    try {
                        logger.info("Waiting for " + INTERVAL + " minute(s) before making next attempt for scanResult of scanId:" + scanId + "...");
                        Thread.sleep(intervalInMillis);
                    } catch (Exception ex) {
                        logger.info(ex.getMessage());
                    }
                }
            }
        } catch (Exception ex) {
            logger.info("Exception: " + ex.getMessage());
        }

        return status;
    }
}
