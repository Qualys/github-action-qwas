package com.example.GitHubActionsQWas.service;

import com.example.GitHubActionsQWas.WASClient.QualysWASResponse;
import com.example.GitHubActionsQWas.WASClient.WASClient;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class QualysWASScanServiceTest {

    @Test
    public void test_instantiation_with_valid_parameters() {
        WASClient apiClient = mock(WASClient.class);
        QualysWASScanService service = QualysWASScanService.builder().build();
        service.setApiClient(apiClient);
        // Set up test data
        service.setWebAppId("webAppId");
        service.setScanName("scanName");
        service.setScanType("scanType");
        service.setAuthRecord("useDefault");
        service.setOptionProfile("useDefault");
        service.setCancelOptions(false);
        service.setAuthRecordId("authRecordId");
        service.setOptionProfileId("optionProfileId");
        service.setCancelHours("cancelHours");
        service.setPollingIntervalForVulns(1);
        service.setVulnsTimeout(1);
        service.setPortalUrl("portalUrl");
        service.setApiServer("apiServer");
        service.setApiUser("apiUser");
        service.setApiPass("apiPass");
        service.setUseProxy(false);
        service.setProxyServer("proxyServer");
        service.setProxyPort(1);
        service.setProxyUsername("proxyUsername");
        service.setProxyPassword("proxyPassword");
        service.setFailOnScanError(true);
        service.setFailConditionsConfigured(true);
        service.setCriteriaObject(new JsonObject());


        assertNotNull(service.getApiClient());
        assertEquals(service.getWebAppId(), "webAppId");
        assertEquals(service.getScanName(), "scanName");
        assertEquals(service.getScanType(), "scanType");
        assertEquals(service.getAuthRecord(), "useDefault");
        assertEquals(service.getOptionProfile(), "useDefault");
        assertFalse(service.isCancelOptions());
        assertEquals(service.getAuthRecordId(), "authRecordId");
        assertEquals(service.getOptionProfileId(), "optionProfileId");
        assertEquals(service.getCancelHours(), "cancelHours");
        assertEquals(service.getPollingIntervalForVulns(), 1);
        assertEquals(service.getVulnsTimeout(), 1);
        assertEquals(service.getPortalUrl(), "portalUrl");
        assertEquals(service.getApiServer(), "apiServer");
        assertEquals(service.getApiUser(), "apiUser");
        assertEquals(service.getApiPass(), "apiPass");
        assertFalse(service.isUseProxy());
        assertEquals(service.getProxyServer(), "proxyServer");
        assertEquals(service.getProxyPort(), 1);
        assertEquals(service.getProxyUsername(), "proxyUsername");
        assertEquals(service.getProxyPassword(), "proxyPassword");
        assertTrue(service.isFailOnScanError());
        assertTrue(service.isFailConditionsConfigured());
        assertNotNull(service.getCriteriaObject());

    }

    @Test
    public void test_launch_scan_with_valid_parameters_returns_scan_id() {
        // Mock dependencies
        WASClient apiClient = mock(WASClient.class);
        QualysWASScanService service = QualysWASScanService.builder().build();
        service.setApiClient(apiClient);

        // Set up test data
        service.setWebAppId("webAppId");
        service.setScanName("scanName");
        service.setScanType("scanType");
        service.setAuthRecord("useDefault");
        service.setOptionProfile("useDefault");
        service.setCancelOptions(false);
        service.setAuthRecordId("authRecordId");
        service.setOptionProfileId("optionProfileId");
        service.setCancelHours("cancelHours");
        service.setPollingIntervalForVulns(1);
        service.setVulnsTimeout(1);
        service.setPortalUrl("portalUrl");
        service.setApiServer("apiServer");
        service.setApiUser("apiUser");
        service.setApiPass("apiPass");
        service.setUseProxy(false);
        service.setProxyServer("proxyServer");
        service.setProxyPort(1);
        service.setProxyUsername("proxyUsername");
        service.setProxyPassword("proxyPassword");
        service.setFailOnScanError(true);

        // Set up expected response
        JsonObject responseObj = new JsonObject();
        JsonObject serviceResponseObj = new JsonObject();
        serviceResponseObj.addProperty("responseCode", "SUCCESS");
        JsonArray dataArr = new JsonArray();
        JsonObject dataObj = new JsonObject();
        JsonObject wasScanObj = new JsonObject();
        wasScanObj.addProperty("id", "scanId");
        dataObj.add("WasScan", wasScanObj);
        dataArr.add(dataObj);
        serviceResponseObj.add("data", dataArr);
        responseObj.add("ServiceResponse", serviceResponseObj);

        // Set up mock API response
        QualysWASResponse apiResponse = new QualysWASResponse();
        apiResponse.setResponse(responseObj);
        when(apiClient.launchWASScan(any(JsonObject.class))).thenReturn(apiResponse);

        // Invoke the method under test
        String scanId = service.launchScan();

        // Verify the result
        assertEquals("scanId", scanId);
    }
}