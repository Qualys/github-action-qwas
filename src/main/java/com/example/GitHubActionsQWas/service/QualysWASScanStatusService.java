package com.example.GitHubActionsQWas.service;

import com.example.GitHubActionsQWas.WASClient.WASClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Timestamp;
import java.util.concurrent.TimeUnit;

public class QualysWASScanStatusService {
    private static final Logger logger = LoggerFactory.getLogger(QualysWASScanStatusService.class);
    private final static int TIMEOUT = (60 * 5) + 50; //5Hrs 50Minuts
    private final static int INTERVAL = 5; //5 minuts
    private WASClient client;

    public QualysWASScanStatusService(WASClient client) {
        this.client = client;
    }

    /**
     * @param scanId
     * @return
     */
    public String fetchScanStatus(String scanId) {
        long startTime = System.currentTimeMillis();
        long timeoutInMillis = TimeUnit.MINUTES.toMillis(TIMEOUT);
        long intervalInMillis = TimeUnit.MINUTES.toMillis(INTERVAL);
        String status = null;

        try {
            while ((status = client.getScanFinishedStatus(scanId)) == null) {
                long endTime = System.currentTimeMillis();
                if ((endTime - startTime) > timeoutInMillis) {
                    logger.info(new Timestamp(System.currentTimeMillis()) + " Failed to get scan result; timeout of " + TIMEOUT + " minutes reached.");
                    throw new Exception("Timeout reached.");
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
