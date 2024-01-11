package com.example.GitHubActionsQWas.service;

import com.example.GitHubActionsQWas.WASAuth.WASAuth;
import com.example.GitHubActionsQWas.WASClient.WASClient;
import com.example.GitHubActionsQWas.util.Helper;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import lombok.Getter;
import lombok.Setter;
import org.apache.tomcat.util.buf.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
public class QualysWASScanBuilder {
    private static final Logger logger = LoggerFactory.getLogger(QualysWASScanBuilder.class);
    private final static int PROXY_PORT = 80;
    private final static int DEFAULT_POLLING_INTERVAL_FOR_VULNS = 5; //5 minutes
    private final static int DEFAULT_TIMEOUT_FOR_VULNS = 60 * 24;
    @Autowired
    private final Environment environment;
    private String apiServer;
    private String portalServer;
    private String qualysUsername;
    private String qualysPasssword;
    private boolean useProxy = false;
    private String proxyServer;
    private int proxyPort = PROXY_PORT;
    private String proxyUsername;
    private String proxyPassword;
    private String webAppId;
    private String scanName;
    private String scanType;
    private String authRecord;
    private String authRecordId;
    private String optionProfile;
    private String optionProfileId;
    private String cancelOptions;
    private String cancelHours;
    private boolean isFailOnSevereVulns = true;
    private boolean severityCheck;
    private int severityLevel;
    private int interval;
    private int severity1Limit;
    private int severity2Limit;
    private int severity3Limit;
    private int severity4Limit;
    private int severity5Limit;
    private boolean isSev1Vulns = false;
    private boolean isSev2Vulns = false;
    private boolean isSev3Vulns = false;
    private boolean isSev4Vulns = false;
    private boolean isSev5Vulns = false;
    private boolean isFailOnQidFound;
    private String qidList;
    private String exclude;
    private boolean isFailOnScanError;
    private String pollingInterval;
    private String vulnsTimeout;
    private boolean waitForResult;
    private WASClient client;

    public QualysWASScanBuilder(Environment environment) {
        this.environment = environment;
        this.apiServer = environment.getProperty("API_SERVER", "");
        this.qualysUsername = environment.getProperty("QUALYS_USERNAME", "");
        this.qualysPasssword = environment.getProperty("QUALYS_PASSWORD", "");
        this.useProxy = environment.getProperty("USE_PROXY", Boolean.class, false);
        this.proxyServer = environment.getProperty("PROXY_SERVER", "");
        this.proxyPort = environment.getProperty("PROXY_PORT", Integer.class, 0);
        this.proxyUsername = environment.getProperty("PROXY_USERNAME", "");
        this.proxyPassword = environment.getProperty("PROXY_PASSWORD", "");
        this.webAppId = environment.getProperty("WEBAPP_ID", "");
        this.scanName = environment.getProperty("SCAN_NAME", "");
        this.scanType = environment.getProperty("SCAN_TYPE", "");
        this.authRecord = environment.getProperty("AUTH_RECORD", "");
        this.authRecordId = environment.getProperty("AUTH_RECORD_ID", "");
        this.optionProfile = environment.getProperty("OPTION_PROFILE", "");
        this.optionProfileId = environment.getProperty("OPTION_PROFILE_ID", "");
        this.cancelOptions = environment.getProperty("CANCEL_OPTION", "");
        this.cancelHours = environment.getProperty("CANCEL_HOURS", "");
        this.severityCheck = environment.getProperty("SEVERITY_CHECK", Boolean.class, false);
        this.severityLevel = environment.getProperty("SEVERITY_LEVEL", Integer.class, 0);
        this.isFailOnQidFound = environment.getProperty("IS_FAIL_ON_QID_FOUND", Boolean.class, false);
        this.qidList = environment.getProperty("QID_LIST", "");
        this.exclude = environment.getProperty("EXCLUDE", "");
        this.isFailOnScanError = environment.getProperty("FAIL_ON_SCAN_ERROR", Boolean.class, false);
        this.waitForResult = environment.getProperty("WAIT_FOR_RESULT", Boolean.class, true);
        this.interval = environment.getProperty("INTERVAL", Integer.class, 5);
        this.severity1Limit = 0;
        this.severity2Limit = 0;
        this.severity3Limit = 0;
        this.severity4Limit = 0;
        this.severity5Limit = 0;

        initWASClient();
        if (severityCheck) {
            assignSeverities(severityLevel);
        }
    }

    private void assignSeverities(int severityLevel) {
        switch (severityLevel) {
            case 1: {
                this.isSev1Vulns = true;
                this.severity1Limit = 1;
            }
            case 2: {
                this.isSev2Vulns = true;
                this.severity2Limit = 1;
            }
            case 3: {
                this.isSev3Vulns = true;
                this.severity3Limit = 1;
            }
            case 4: {
                this.isSev4Vulns = true;
                this.severity4Limit = 1;
            }
            case 5: {
                this.isSev5Vulns = true;
                this.severity5Limit = 1;
            }
        }
    }

    private void initWASClient() {
        WASAuth auth = new WASAuth();
        auth.setWasCredentials(apiServer, qualysUsername, qualysPasssword);

        if (useProxy) {
            auth.setProxyCredentials(proxyServer, proxyPort, proxyUsername, proxyPassword);
        }
        client = new WASClient(auth, System.out);
    }

    /**
     * @return
     */
    public JsonObject getCriteriaAsJsonObject() {
        JsonObject obj = new JsonObject();

        JsonObject failConditionsObj = new JsonObject();
        Gson gson = new Gson();
        if (isFailOnQidFound) {
            if (this.qidList != null) {
                if (!this.qidList.isEmpty()) {
                    List<String> qids = new ArrayList<>(List.of(this.qidList.split(",")));
                    qids.replaceAll(String::trim);
                    JsonElement element = gson.toJsonTree(qids, new TypeToken<List<String>>() {
                    }.getType());
                    failConditionsObj.add("qids", element);
                }
            }
        }

        if (isFailOnSevereVulns) {
            JsonObject severities = new JsonObject();
            if (this.isSev5Vulns) severities.addProperty("5", this.severity5Limit);
            if (this.isSev4Vulns) severities.addProperty("4", this.severity4Limit);
            if (this.isSev3Vulns) severities.addProperty("3", this.severity3Limit);
            if (this.isSev2Vulns) severities.addProperty("2", this.severity2Limit);
            if (this.isSev1Vulns) severities.addProperty("1", this.severity1Limit);

            failConditionsObj.add("severities", severities);

            if (this.exclude != null) {
                if (!this.exclude.isEmpty()) {
                    List<String> excludeQids = new ArrayList<>(List.of(this.exclude.split(",")));
                    excludeQids.replaceAll(String::trim);
                    JsonElement element = gson.toJsonTree(excludeQids, new TypeToken<List<String>>() {
                    }.getType());
                    failConditionsObj.add("excludeQids", element);
                }
            }
        }

        if (isFailOnScanError) {
            failConditionsObj.addProperty("failOnScanError", true);
        }

        obj.add("failConditions", failConditionsObj);
        logger.debug("Criteria: " + obj.toString());
        return obj;
    }

    /**
     *
     */
    public void launchWebApplicationScan() {
        portalServer = apiServer.replace("api", "guard");

        logger.info("Using Qualys API Server: " + apiServer);

        try {
            try {
                logger.info("Testing connection with Qualys API Server...");
                client.testConnection();
                logger.info("Test connection successful.");
            } catch (Exception ex) {
                logger.error("Test connection failed. Reason: " + ex.getMessage());
                Helper.dumpDataIntoFile("Test connection failed. Reason: " + ex.getMessage(), "Qualys_Wasscan_" + this.webAppId + ".txt");
                System.exit(1);
            }

            boolean isFailConditionConfigured = false;
            this.isFailOnSevereVulns = this.isSev1Vulns || this.isSev2Vulns || this.isSev3Vulns || this.isSev4Vulns || this.isSev5Vulns;
            if (isFailOnQidFound || isFailOnSevereVulns || isFailOnScanError) {
                isFailConditionConfigured = true;
            }

            QualysWASScanService service = QualysWASScanService.builder().webAppId(webAppId).scanName(scanName).scanType(scanType).authRecord(authRecord).authRecordId(authRecordId).optionProfile(optionProfile).optionProfileId(optionProfileId).cancelOptions(cancelOptions).cancelHours(cancelHours).isFailConditionsConfigured(isFailConditionConfigured).pollingIntervalForVulns(Helper.setTimeoutInMinutes("pollingInterval", DEFAULT_POLLING_INTERVAL_FOR_VULNS, pollingInterval)).vulnsTimeout(Helper.setTimeoutInMinutes("vulnsTimeout", DEFAULT_TIMEOUT_FOR_VULNS, vulnsTimeout)).criteriaObject(getCriteriaAsJsonObject()).apiServer(apiServer).apiUser(qualysUsername).apiPass(qualysPasssword).useProxy(useProxy).proxyServer(proxyServer).proxyPort(proxyPort).proxyUsername(proxyUsername).proxyPassword(proxyPassword).portalUrl(portalServer).failOnScanError(isFailOnScanError).apiClient(client).build();

            logger.info("Qualys task - Started Launching web app scanning with WAS");
            String scanId = service.launchScan();
            if (scanId != null && !scanId.isEmpty()) {
                String message1 = "Launching scan with 'WAIT_FOR_RESULT:" + waitForResult + "'";
                String message2 = "Scan successfully launched with scan id: " + scanId;
                String message3 = "Please switch to WAS Classic UI and Check for report...";
                String message4 = "To check scan result, please follow the url: " + portalServer + "/portal-front/module/was/#forward=/module/was/&scan-report=" + scanId;
                logger.info(message1);
                logger.info(message2);
                if (this.waitForResult) {
                    logger.info("Qualys task - Fetching scan finished status");
                    String status = getScanFinishedStatus(scanId);
                    logger.info("Scan finished status fetched successfully");
                    boolean buildPassed = true;

                    Gson gson = new Gson();
                    QualysWASScanResultParser resultParser = new QualysWASScanResultParser(gson.toJson(getCriteriaAsJsonObject()), client);
                    logger.info("Qualys task - Fetching scan result");
                    JsonObject result = resultParser.fetchScanResult(scanId);
                    if (result != null) {
                        String fileName = "Qualys_Wasscan_" + scanId + ".json";
                        JsonObject data = result;
                        if (result.has("ServiceResponse") && result.get("ServiceResponse").getAsJsonObject().has("responseCode") && result.get("ServiceResponse").getAsJsonObject().get("responseCode").getAsString().equalsIgnoreCase("SUCCESS")) {
                            data.get("ServiceResponse").getAsJsonObject().getAsJsonArray("data").get(0).getAsJsonObject().get("WasScan").getAsJsonObject().remove("igs").getAsJsonObject();
                            data.get("ServiceResponse").getAsJsonObject().getAsJsonArray("data").get(0).getAsJsonObject().get("WasScan").getAsJsonObject().addProperty("ScanId", scanId);
                            if (!status.equalsIgnoreCase("error") && !status.equalsIgnoreCase("canceled") && !status.equalsIgnoreCase("finished") && isFailOnScanError) {
                                Helper.dumpDataIntoFile(gson.toJson(data), "Qualys_Wasscan_" + scanId + ".txt");
                                System.exit(1);
                            }
                            Helper.dumpDataIntoFile(gson.toJson(data), fileName);
                            if (isFailConditionConfigured) {
                                JsonObject evaluationResult = evaluateFailurePolicy(result);
                                buildPassed = evaluationResult.get("passed").getAsBoolean();
                                if (!buildPassed) {
                                    logger.info(message3);
                                    logger.info(message4);
                                    String failureMessage = evaluationResult.get("failureMessage").getAsString();
                                    logger.error(failureMessage);
                                    Helper.dumpDataIntoFile(failureMessage, "Qualys_Wasscan_" + scanId + ".txt");
                                    System.exit(1);
                                }
                            }
                        } else {
                            String message = "API Error - Could not fetch scan result for scan id: " + scanId;
                            logger.error(message);
                            Helper.dumpDataIntoFile(message, "Qualys_Wasscan_" + scanId + ".json");
                            System.exit(1);
                        }
                        logger.info(message3);
                        logger.info(message4);
                    }
                } else {
                    logger.info(message3);
                    logger.info(message4);
                    String message = message1 + "\n" + message2 + "\n" + message3 + "\n" + message4;
                    String fileName = "Qualys_Wasscan_" + webAppId + ".txt";
                    Helper.dumpDataIntoFile(message, fileName);
                }
            } else {
                String message = "API Error - Could not launch new scan for web app id: " + webAppId;
                logger.error(message);
                Helper.dumpDataIntoFile(message, "Qualys_Wasscan_" + webAppId + ".txt");
                System.exit(1);
            }
        } catch (Exception ex) {
            logger.error("Something went wrong. Reason: " + ex.getMessage(), ex);
        }
    }

    public JsonObject evaluateFailurePolicy(JsonObject result) throws Exception {
        Gson gson = new Gson();
        QualysWASScanResultParser criteria = new QualysWASScanResultParser(gson.toJson(getCriteriaAsJsonObject()), client);
        Boolean passed = criteria.evaluate(result);
        JsonObject obj = new JsonObject();
        obj.add("passed", gson.toJsonTree(passed));
        obj.add("result", criteria.returnObject);
        if (!passed) {
            String failureMessage = getBuildFailureMessages(criteria.getResult());
            obj.addProperty("failureMessage", failureMessage);
        }
        return obj;
    }

    /**
     * @param scanId
     */
    private String getScanFinishedStatus(String scanId) {
        QualysWASScanStatusService statusService = new QualysWASScanStatusService(client);
        String status = statusService.fetchScanStatus(scanId, portalServer, interval);
        logger.info(status);
        return status;
    }

    private String getBuildFailureMessages(JsonObject result) {
        List<String> failureMessages = new ArrayList<String>();
        if (result.has("qids") && result.get("qids") != null && !result.get("qids").isJsonNull()) {
            JsonObject qidsObj = result.get("qids").getAsJsonObject();
            boolean qidsPass = qidsObj.get("result").getAsBoolean();
            if (!qidsPass) {
                String found = qidsObj.get("found").getAsString();
                failureMessages.add("QIDs configured in Failure Conditions were found in the scan result : " + found);
            }
        }

        String sevConfigured = "\nConfigured : \n";
        String sevFound = "\nFound : \n";
        boolean severityFailed = false;
        for (int i = 1; i <= 5; i++) {
            if (result.has("severities") && result.get("severities") != null && !result.get("severities").isJsonNull()) {
                JsonObject sevObj = result.get("severities").getAsJsonObject();
                JsonObject severity = sevObj.get("" + i).getAsJsonObject();
                if (severity.has("configured") && !severity.get("configured").isJsonNull() && severity.get("configured").getAsInt() != -1) {
                    sevFound += "Severity " + i + "; Count: " + (severity.get("found").isJsonNull() ? 0 : severity.get("found").getAsString()) + "\n";
                    sevConfigured += "Severity " + i + ": " + (severity.get("configured").isJsonNull() ? "false" : "true") + "\n";
                    severityFailed = severity.get("result").getAsBoolean();
                    if (!severityFailed) {
                        severityFailed = true;
                    }
                }
            }
        }
        if (severityFailed) {
            failureMessages.add("The vulnerabilities count by severity exceeded one of the configured threshold value : " + sevConfigured + sevFound);
        }

        return StringUtils.join(failureMessages, '\n');
    }

    public boolean isMandatoryParametersSet() {
        return !(this.apiServer == null || this.apiServer.isEmpty()
                || this.qualysUsername == null || this.qualysUsername.isEmpty()
                || this.qualysPasssword == null || this.qualysPasssword.isEmpty()
                || webAppId == null || webAppId.isEmpty()
                || scanName == null || scanName.isEmpty()
                || scanType == null || scanType.isEmpty());
    }

    @Override
    public String toString() {
        return "QualysWASScanBuilder{" +
                "environment=" + environment +
                ", apiServer='" + apiServer + '\'' +
                ", portalServer='" + portalServer + '\'' +
                ", qualysUsername='" + qualysUsername + '\'' +
                ", qualysPasssword='" + qualysPasssword + '\'' +
                ", useProxy=" + useProxy +
                ", proxyServer='" + proxyServer + '\'' +
                ", proxyPort=" + proxyPort +
                ", proxyUsername='" + proxyUsername + '\'' +
                ", proxyPassword='" + proxyPassword + '\'' +
                ", webAppId='" + webAppId + '\'' +
                ", scanName='" + scanName + '\'' +
                ", scanType='" + scanType + '\'' +
                ", authRecord='" + authRecord + '\'' +
                ", authRecordId='" + authRecordId + '\'' +
                ", optionProfile='" + optionProfile + '\'' +
                ", optionProfileId='" + optionProfileId + '\'' +
                ", cancelOptions='" + cancelOptions + '\'' +
                ", cancelHours='" + cancelHours + '\'' +
                ", isFailOnSevereVulns=" + isFailOnSevereVulns +
                ", severityCheck=" + severityCheck +
                ", severityLevel=" + severityLevel +
                ", severity1Limit=" + severity1Limit +
                ", severity2Limit=" + severity2Limit +
                ", severity3Limit=" + severity3Limit +
                ", severity4Limit=" + severity4Limit +
                ", severity5Limit=" + severity5Limit +
                ", isSev1Vulns=" + isSev1Vulns +
                ", isSev2Vulns=" + isSev2Vulns +
                ", isSev3Vulns=" + isSev3Vulns +
                ", isSev4Vulns=" + isSev4Vulns +
                ", isSev5Vulns=" + isSev5Vulns +
                ", isFailOnQidFound=" + isFailOnQidFound +
                ", qidList='" + qidList + '\'' +
                ", exclude='" + exclude + '\'' +
                ", isFailOnScanError=" + isFailOnScanError +
                ", pollingInterval='" + pollingInterval + '\'' +
                ", vulnsTimeout='" + vulnsTimeout + '\'' +
                ", waitForResult=" + waitForResult +
                ", client=" + client +
                '}';
    }
}
