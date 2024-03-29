package com.example.GitHubActionsQWas.service;

import com.example.GitHubActionsQWas.WASClient.QualysWASResponse;
import com.example.GitHubActionsQWas.WASClient.WASClient;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Builder
@Setter
@Getter
public class QualysWASScanService {
    private static final Logger logger = LoggerFactory.getLogger(QualysWASScanBuilder.class);
    private String webAppId;
    private String scanName;
    private String scanType;
    private String authRecord;
    private String optionProfile;
    private boolean cancelOptions;
    private String authRecordId;
    private String optionProfileId;
    private String cancelHours;
    private int pollingIntervalForVulns;
    private int vulnsTimeout;
    private String portalUrl;
    private String apiServer;
    private String apiUser;
    private String apiPass;
    private boolean useProxy;
    private String proxyServer;
    private int proxyPort;
    private String proxyUsername;
    private String proxyPassword;
    private boolean isFailConditionsConfigured;
    private JsonObject criteriaObject;
    private WASClient apiClient;
    private boolean failOnScanError;

    protected String launchScan() {
        JsonObject requestData = new JsonObject();
        try {
            JsonObject requestObj = new JsonObject();
            JsonObject data = new JsonObject();

            JsonObject wasScan = new JsonObject();
            wasScan.addProperty("type", scanType);
            String timestamp = new SimpleDateFormat("yyyy-MM-dd-HH-mm").format(new Date());
            scanName = scanName + "_" + timestamp;
            wasScan.addProperty("name", scanName);

            JsonObject webAppDetails = new JsonObject();
            JsonObject webApp = new JsonObject();
            webAppDetails.addProperty("id", webAppId);
            webApp.add("webApp", webAppDetails);

            if (authRecord != null && authRecord.equals("useDefault")) {
                JsonObject authRecord = new JsonObject();
                authRecord.addProperty("isDefault", true);
                webApp.add("webAppAuthRecord", authRecord);
            } else if (authRecord != null && authRecordId != null && authRecord.equals("other") && !authRecordId.isEmpty()) {
                JsonObject authRecord = new JsonObject();
                authRecord.addProperty("id", authRecordId);
                webApp.add("webAppAuthRecord", authRecord);
            }

            if (optionProfile != null && optionProfileId != null && optionProfile.equals("other") && !optionProfileId.isEmpty()) {
                JsonObject profRec = new JsonObject();
                profRec.addProperty("id", optionProfileId);
                wasScan.add("profile", profRec);
            }

            if (cancelHours != null && cancelOptions && !cancelHours.isEmpty()) {

                wasScan.addProperty("cancelAfterNHours", cancelHours);
            }

            wasScan.add("target", webApp);
            data.add("WasScan", wasScan);
            requestObj.add("data", data);
            requestData.add("ServiceRequest", requestObj);

            List<String> scan_ids = new ArrayList<String>();
            logger.info("Calling Launch Scan API with Payload: " + requestData);

            if (isFailConditionsConfigured) {
                JsonObject criteria = criteriaObject;
                for (int i = 1; i <= 5; i++) {
                    if (criteria.get("failConditions").getAsJsonObject().has("severities") && criteria.get("failConditions").getAsJsonObject().get("severities").getAsJsonObject().has(i + "")) {
                        criteria.get("failConditions").getAsJsonObject().get("severities").getAsJsonObject().addProperty(i + "", true);
                    }

                }
                logger.info("Using Build Failure Conditions configuration: " + criteria);
            }

            QualysWASResponse response = apiClient.launchWASScan(requestData);
            JsonObject result = response.response;
            //parse result
            JsonElement respEl = result.get("ServiceResponse");
            JsonObject respObj = respEl.getAsJsonObject();
            JsonElement respCodeObj = respObj.get("responseCode");
            if (respCodeObj != null && !respCodeObj.getAsString().equals("SUCCESS")) {
                JsonObject respErr = respObj.getAsJsonObject("responseErrorDetails");
                logger.debug("Server Response: " + respErr.toString());
                throw new Exception("Error while launching new scan. Server returned: " + respErr);
            } else {
                JsonArray dataArr = respObj.get("data").getAsJsonArray();
                if (dataArr.isEmpty()) {
                    return "";
                }
                for (int i = 0; i < dataArr.size(); ++i) {
                    JsonObject obj = dataArr.get(i).getAsJsonObject();
                    JsonObject wasObj = obj.get("WasScan").getAsJsonObject();
                    String scan_id = wasObj.get("id").getAsString();
                    scan_ids.add(scan_id);
                }
                return String.join(", ", scan_ids);
            }
        } catch (Exception ex) {
            logger.error("Something went wrong. Reason: " + ex.getMessage());
        }
        return "";
    }
}
