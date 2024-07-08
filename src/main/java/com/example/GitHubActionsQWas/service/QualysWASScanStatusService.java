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
    public String fetchScanStatus(String scanId, String scanType, boolean severityCheck, String portalUrl, long INTERVAL, long TIMEOUT) {
        long startTime = System.currentTimeMillis();
        long timeoutInMillis = TimeUnit.SECONDS.toMillis(TIMEOUT);
        long intervalInMillis = TimeUnit.SECONDS.toMillis(INTERVAL);
        String status = "";
        boolean failed = false;

        try {
            while ((status = client.getScanFinishedStatus(scanId)) == null) {
                long endTime = System.currentTimeMillis();
                if ((endTime - startTime) > timeoutInMillis) {
                    String message1 = "Failed to get scan result; timeout of " + TimeUnit.SECONDS.toMinutes(TIMEOUT) + " minutes reached.";
                    String message2 = "To check scan result on Qualys UI, please follow the url. Note that, scan result URL will work with New WAS UI only: " + portalUrl + "/was/#/reports/online-reports/email-report/scan/" + scanId;

                    logger.info(message1);
                    logger.info(message2);
                    if (scanType.equalsIgnoreCase("vulnerability") && severityCheck) {
                        failed = true;
                    }
                    if (failed) {
                        String message = message1 + "\n" + message2;
                        Helper.dumpDataIntoFile(message, "Qualys_Wasscan_" + scanId + ".txt");
                        System.exit(1);
                    }
                    break;
                } else {
                    try {
                        logger.info("Waiting for " + TimeUnit.SECONDS.toMinutes(INTERVAL) + " minute(s) before making next attempt for scanResult of scanId:" + scanId + "...");
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
