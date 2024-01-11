package com.example.GitHubActionsQWas.service;

import com.example.GitHubActionsQWas.WASClient.WASClient;
import com.example.GitHubActionsQWas.util.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Timestamp;
import java.util.concurrent.TimeUnit;

public class QualysWASScanStatusService {
    private static final Logger logger = LoggerFactory.getLogger(QualysWASScanStatusService.class);
    private final static int TIMEOUT = (60 * 5) + 50; //5Hrs 50Minuts
    private WASClient client;

    public QualysWASScanStatusService(WASClient client) {
        this.client = client;
    }

    /**
     * @param scanId
     * @return
     */
    public String fetchScanStatus(String scanId, String portalUrl, int INTERVAL) {
        long startTime = System.currentTimeMillis();
        long timeoutInMillis = TimeUnit.MINUTES.toMillis(TIMEOUT);
        long intervalInMillis = TimeUnit.MINUTES.toMillis(INTERVAL);
        String status = null;

        try {
            while ((status = client.getScanFinishedStatus(scanId)) == null) {
                long endTime = System.currentTimeMillis();
                if ((endTime - startTime) > timeoutInMillis) {
                    logger.info(new Timestamp(System.currentTimeMillis()) + " Failed to get scan result; timeout of " + TIMEOUT + " minutes reached.");
                    String message1 = "Failed to get scan result; timeout of " + TIMEOUT + " minutes reached.";
                    String message2 = "Please switch to WAS Classic UI and Check for report...";
                    String message3 = "To check scan result, please follow the url: " + portalUrl + "/portal-front/module/was/#forward=/module/was/&scan-report=" + scanId;
                    String message = message1 + "\n" + message2 + "\n" + message3;
                    Helper.dumpDataIntoFile(message, "Qualys_Wasscan_" + scanId + ".txt");
                    System.exit(1);
                } else {
                    try {
                        logger.info(new Timestamp(System.currentTimeMillis()) + " Waiting for " + INTERVAL + " minute(s) before making next attempt for scanResult of scanId:" + scanId + "...");
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
