package com.example.GitHubActionsQWas.WASClient;

import com.example.GitHubActionsQWas.WASAuth.WASAuth;
import com.google.gson.*;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.HashMap;

public class WASClient extends WASBaseClient {
    HashMap<String, String> apiMap;
    Logger logger = LoggerFactory.getLogger(WASClient.class);

    public WASClient(WASAuth auth) {
        super(auth, System.out);
        this.populateApiMap();
    }

    public WASClient(WASAuth auth, PrintStream stream) {
        super(auth, stream);
        this.populateApiMap();
    }

    private void populateApiMap() {
        this.apiMap = new HashMap<>();
        this.apiMap.put("getWebAppCount", "/qps/rest/3.0/count/was/webapp");
        this.apiMap.put("getScanResult", "/qps/rest/3.0/download/was/wasscan/");
        this.apiMap.put("getScanStatus", "/qps/rest/3.0/status/was/wasscan/");
        this.apiMap.put("launchScan", "/qps/rest/3.0/launch/was/wasscan");
    }

    public QualysWASResponse getScanResult(String scanId) {
        return this.get(this.apiMap.get("getScanResult") + scanId);
    }

    public QualysWASResponse getScanStatus(String scanId) {
        return this.get(this.apiMap.get("getScanStatus") + scanId);
    }

    public QualysWASResponse getWebAppCount() {
        return this.get(this.apiMap.get("getWebAppCount"));
    }

    public QualysWASResponse launchWASScan(JsonObject requestData) {
        return this.post(this.apiMap.get("launchScan"), requestData);
    }

    public void testConnection() throws Exception {
        try {
            QualysWASResponse response = getWebAppCount();
            if (response.errored) {
                if (response.responseCode > 0) {
                    throw new Exception("Please provide valid API and/or Proxy details." + " Server returned with Response code: " + response.responseCode);
                } else {
                    throw new Exception("Please provide valid API and/or Proxy details." + " Error Message: " + response.errorMessage);
                }
            } else {
                JsonObject responseObject = response.response;
                if (response.responseCode < 200 || response.responseCode > 299) {
                    String err_message = responseObject.has("errorMessage") ? "Error message: " + responseObject.get("errorMessage").getAsString() : "";
                    throw new Exception("HTTP Response code from server: " + response.responseCode + ". " + err_message);
                }
                JsonObject serviceResponseObject = responseObject.get("ServiceResponse").getAsJsonObject();
                String responseCodeString = serviceResponseObject.get("responseCode").getAsString();
                if (!responseCodeString.equalsIgnoreCase("success")) {
                    JsonObject detailsObject = serviceResponseObject.get("responseErrorDetails").getAsJsonObject();
                    String errorMessage = detailsObject.get("errorMessage").getAsString();
                    String errorResolution = detailsObject.get("errorResolution").getAsString();
                    throw new Exception("[" + responseCodeString + "] " + errorMessage + ", " + errorResolution);
                }
                logger.debug("response:" + response.response.toString());
            }
        } catch (NullPointerException ne) {
            ne.printStackTrace();
            throw new Exception("Please provide valid API and/or Proxy details.");
        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception(e.getMessage());
        }
    }

    public String getScanFinishedStatus(String scanId) {
        String status = null;
        try {
            QualysWASResponse statusResponse = getScanStatus(scanId);
            JsonObject result = statusResponse.response;
            JsonElement resultElement = result.get("ServiceResponse");
            JsonObject responseObject = resultElement.getAsJsonObject();
            JsonElement responseCodeElement = responseObject.get("responseCode");
            if (responseCodeElement != null && !responseCodeElement.getAsString().equals("SUCCESS")) {
                JsonObject respErr = responseObject.getAsJsonObject("responseErrorDetails");
                logger.info("Server Response: " + respErr.toString());
                String reason = respErr.get("errorMessage").getAsString();
                throw new Exception(reason);
            } else {
                JsonArray dataArr = responseObject.getAsJsonArray("data");
                JsonObject obj = dataArr.get(0).getAsJsonObject();
                JsonObject scanObj = obj.getAsJsonObject("WasScan");
                String scanStatus = scanObj.get("status").getAsString();

                String error = "Error.";
                if (scanObj.has("summary")) {
                    JsonObject summaryObj = scanObj.getAsJsonObject("summary");
                    error = summaryObj.get("resultsStatus").getAsString();
                }

                if (scanStatus.equalsIgnoreCase("error") || scanStatus.equalsIgnoreCase("canceled") || (scanStatus.equalsIgnoreCase("finished") && !error.equalsIgnoreCase("finished"))) {
                    logger.info(new Timestamp(System.currentTimeMillis()) + " Scan Status: " + scanStatus + ". Reason: " + error);
                    return error;
                } else {
                    logger.info(new Timestamp(System.currentTimeMillis()) + " Scan Status: " + scanStatus);
                }
                return (scanStatus.equalsIgnoreCase("error") || scanStatus.equalsIgnoreCase("canceled") || scanStatus.equalsIgnoreCase("finished")) ? scanStatus : null;
            }

        } catch (Exception ex) {
            logger.error(new Timestamp(System.currentTimeMillis()) + " Error getting scan status: " + ex.getMessage(), ex);
        }
        return status;
    }

    private QualysWASResponse get(String apiPath) {
        QualysWASResponse apiResponse = new QualysWASResponse();
        String apiResponseString = "";
        CloseableHttpClient httpClient = null;

        try {
            URL url = this.getAbsoluteUrl(apiPath);
            this.stream.println("Making Request: " + url.toString());
            httpClient = this.getHttpClient();

            HttpGet getRequest = new HttpGet(url.toString());
            getRequest.addHeader("accept", "application/json");
            getRequest.addHeader("Authorization", "Basic " + this.getBasicAuthHeader());
            CloseableHttpResponse response = httpClient.execute(getRequest);
            apiResponse.responseCode = response.getStatusLine().getStatusCode();
            logger.debug("Server returned with ResponseCode: " + apiResponse.responseCode);

            if (response.getEntity() != null) {
                BufferedReader br = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
                String output;
                while ((output = br.readLine()) != null) {
                    apiResponseString += output;
                }

                JsonParser jsonParser = new JsonParser();
                JsonElement jsonElement = jsonParser.parse(apiResponseString);

                if (!jsonElement.isJsonObject()) {
                    throw new InvalidAPIResponseException();
                }
                apiResponse.response = jsonElement.getAsJsonObject();

            }

        } catch (JsonParseException je) {
            apiResponse.errored = true;
            apiResponse.errorMessage = apiResponseString;
        } catch (Exception e) {
            apiResponse.errored = true;
            apiResponse.errorMessage = e.getMessage();
        }

        return apiResponse;
    }

    private QualysWASResponse post(String apiPath, JsonObject requestData) {
        QualysWASResponse response = new QualysWASResponse();
        String apiResponseString = "";
        CloseableHttpClient httpClient = null;
        try {
            URL url = this.getAbsoluteUrl(apiPath);
            logger.info("Making Request: " + url.toString());
            httpClient = this.getHttpClient();

            HttpPost postRequest = new HttpPost(url.toString());
            postRequest.addHeader("accept", "application/json");
            postRequest.addHeader("Authorization", "Basic " + this.getBasicAuthHeader());
            Gson gson = new Gson();
            if (requestData != null) {
                postRequest.addHeader("Content-Type", "application/json");
                StringEntity entity = new StringEntity(gson.toJson(requestData));
                postRequest.setEntity(entity);
            }

            CloseableHttpResponse httpResponse = httpClient.execute(postRequest);
            response.responseCode = httpResponse.getStatusLine().getStatusCode();
            logger.info("Server returned with ResponseCode: " + response.responseCode);
            if (httpResponse.getEntity() != null) {
                BufferedReader br = new BufferedReader(new InputStreamReader(httpResponse.getEntity().getContent()));
                String output;
                while ((output = br.readLine()) != null) {
                    apiResponseString += output;
                }

                JsonParser jsonParser = new JsonParser();
                JsonElement jsonElement = jsonParser.parse(apiResponseString);

                if (!jsonElement.isJsonObject()) {
                    throw new InvalidAPIResponseException();
                }
                response.response = jsonElement.getAsJsonObject();
            }
        } catch (Exception ex) {
            response.errored = true;
            response.errorMessage = apiResponseString;
        }

        return response;
    }

    public URL getAbsoluteUrl(String path) throws MalformedURLException {
        path = (path.startsWith("/")) ? path : ("/" + path);
        URL url = new URL(this.auth.getServer() + path);
        return url;
    }

    protected String getBasicAuthHeader() {
        String userPass = this.auth.getUsername() + ":" + this.auth.getPassword();
        String encoded = Base64.getEncoder().encodeToString((userPass).getBytes(StandardCharsets.UTF_8));
        return encoded;
    }
}
