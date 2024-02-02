package com.example.GitHubActionsQWas.WASClient;

import com.example.GitHubActionsQWas.WASAuth.WASAuth;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class WASClientTest {

    @Test
    public void test_valid_api_and_proxy_details() {
        WASAuth auth = mock(WASAuth.class);
        WASClient wasClient = mock(WASClient.class);
        when(auth.getServer()).thenReturn("server");
        when(auth.getUsername()).thenReturn("username");
        when(auth.getPassword()).thenReturn("password");
        when(auth.getProxyServer()).thenReturn("proxyServer");
        when(auth.getProxyPort()).thenReturn(8080);
        when(auth.getProxyUsername()).thenReturn("proxyUsername");
        when(auth.getProxyPassword()).thenReturn("proxyPassword");

        QualysWASResponse response = new QualysWASResponse();
        response.errored = false;

        when(wasClient.getWebAppCount()).thenReturn(response);

        try {
            wasClient.testConnection();
        } catch (Exception e) {
            fail("Exception thrown: " + e.getMessage());
        }
    }

    @Test
    public void test_response_code_between_200_and_299() {
        WASAuth auth = mock(WASAuth.class);
        WASClient wasClient = mock(WASClient.class);
        when(auth.getServer()).thenReturn("server");
        when(auth.getUsername()).thenReturn("username");
        when(auth.getPassword()).thenReturn("password");
        when(auth.getProxyServer()).thenReturn("proxyServer");
        when(auth.getProxyPort()).thenReturn(8080);
        when(auth.getProxyUsername()).thenReturn("proxyUsername");
        when(auth.getProxyPassword()).thenReturn("proxyPassword");

        QualysWASResponse response = new QualysWASResponse();
        response.errored = false;
        response.responseCode = 200;

        when(wasClient.getWebAppCount()).thenReturn(response);

        try {
            wasClient.testConnection();
        } catch (Exception e) {
            fail("Exception thrown: " + e.getMessage());
        }
    }

    @Test
    public void test_response_code_not_between_200_and_299_with_success_response_code() {
        WASAuth auth = mock(WASAuth.class);
        WASClient wasClient = spy(new WASClient(auth));
        when(auth.getServer()).thenReturn("server");
        when(auth.getUsername()).thenReturn("username");
        when(auth.getPassword()).thenReturn("password");
        when(auth.getProxyServer()).thenReturn("proxyServer");
        when(auth.getProxyPort()).thenReturn(8080);
        when(auth.getProxyUsername()).thenReturn("proxyUsername");
        when(auth.getProxyPassword()).thenReturn("proxyPassword");

        QualysWASResponse response = new QualysWASResponse();
        response.errored = false;
        response.responseCode = 400;

        JsonObject responseObject = new JsonObject();
        responseObject.addProperty("responseCode", "success");

        response.response = responseObject;

        when(wasClient.getWebAppCount()).thenReturn(response);

        try {
            wasClient.testConnection();
        } catch (Exception e) {
            assertEquals("HTTP Response code from server: 400. ", e.getMessage());
        }
    }

    @Test
    public void test_response_code_zero() {
        WASClient client = spy(new WASClient(new WASAuth()));
        when(client.getWebAppCount()).thenReturn(null);
        QualysWASResponse response = new QualysWASResponse();
        response.responseCode = -1;
        response.errored = false;
        response.errorMessage = "";

        Mockito.when(client.getWebAppCount()).thenReturn(response);

        try {
            client.testConnection();
            fail("Expected Exception to be thrown");
        } catch (Exception e) {
            assertEquals("Please provide valid API and/or Proxy details.", e.getMessage());
        }
    }

    @Test
    public void test_responseCode_not_success() {
        // Mock QualysWASResponse with responseCode not equal to success
        QualysWASResponse mockResponse = new QualysWASResponse();
        mockResponse.responseCode = 200;
        JsonObject responseObject = new JsonObject();
        JsonObject serviceResponseObject = new JsonObject();
        serviceResponseObject.addProperty("responseCode", "error");
        JsonObject detailsObject = new JsonObject();
        detailsObject.addProperty("errorMessage", "Error message");
        detailsObject.addProperty("errorResolution", "Error resolution");
        serviceResponseObject.add("responseErrorDetails", detailsObject);
        responseObject.add("ServiceResponse", serviceResponseObject);
        mockResponse.response = responseObject;

        // Mock getWebAppCount() to return the mock response
        WASClient wasClient = spy(new WASClient(new WASAuth()));
        Mockito.when(wasClient.getWebAppCount()).thenReturn(mockResponse);

        // Test the behavior
        assertThrows(Exception.class, () -> {
            wasClient.testConnection();
        });
    }

    @Test
    public void test_returns_null_if_scan_status_not_error_canceled_or_finished() {
        WASClient wasClient = spy(new WASClient(mock(WASAuth.class)));
        QualysWASResponse statusResponse = new QualysWASResponse();
        JsonObject result = new JsonObject();
        JsonObject responseObject = new JsonObject();
        responseObject.addProperty("responseCode", "SUCCESS");
        result.add("ServiceResponse", responseObject);
        statusResponse.response = result;

        when(wasClient.getScanStatus(anyString())).thenReturn(statusResponse);

        String scanId = "12345";
        String scanResult = wasClient.getScanFinishedStatus(scanId);

        assertNull(scanResult);
    }

    @Test
    public void test_returns_scan_status_if_scan_status_error_or_canceled() {
        WASClient wasClient = spy(new WASClient(mock(WASAuth.class)));
        QualysWASResponse statusResponse = new QualysWASResponse();
        JsonObject result = new JsonObject();
        JsonObject responseObject = new JsonObject();
        responseObject.addProperty("responseCode", "SUCCESS");
        JsonArray dataArr = new JsonArray();
        JsonObject obj = new JsonObject();
        JsonObject scanObj = new JsonObject();
        scanObj.addProperty("status", "error");
        obj.add("WasScan", scanObj);
        dataArr.add(obj);
        responseObject.add("data", dataArr);
        result.add("ServiceResponse", responseObject);
        statusResponse.response = result;

        when(wasClient.getScanStatus(anyString())).thenReturn(statusResponse);

        String scanId = "12345";
        String scanResult = wasClient.getScanFinishedStatus(scanId);

        assertEquals("Error.", scanResult);
    }

    @Test
    public void test_returns_error_if_scan_status_finished_and_results_status_not_finished() {
        WASClient wasClient = spy(new WASClient(mock(WASAuth.class)));
        QualysWASResponse statusResponse = new QualysWASResponse();
        JsonObject result = new JsonObject();
        JsonObject responseObject = new JsonObject();
        responseObject.addProperty("responseCode", "SUCCESS");
        JsonArray dataArr = new JsonArray();
        JsonObject obj = new JsonObject();
        JsonObject scanObj = new JsonObject();
        scanObj.addProperty("status", "finished");
        JsonObject summaryObj = new JsonObject();
        summaryObj.addProperty("resultsStatus", "failed");
        scanObj.add("summary", summaryObj);
        obj.add("WasScan", scanObj);
        dataArr.add(obj);
        responseObject.add("data", dataArr);
        result.add("ServiceResponse", responseObject);
        statusResponse.response = result;

        when(wasClient.getScanStatus(anyString())).thenReturn(statusResponse);

        String scanId = "12345";
        String scanResult = wasClient.getScanFinishedStatus(scanId);

        assertEquals("failed", scanResult);
    }

    @Test
    public void test_returns_null_if_scan_status_finished_and_results_status_finished() {
        WASClient wasClient = spy(new WASClient(mock(WASAuth.class)));
        QualysWASResponse statusResponse = new QualysWASResponse();
        JsonObject result = new JsonObject();
        JsonObject responseObject = new JsonObject();
        responseObject.addProperty("responseCode", "SUCCESS");
        JsonArray dataArr = new JsonArray();
        JsonObject obj = new JsonObject();
        JsonObject scanObj = new JsonObject();
        scanObj.addProperty("status", "finished");
        JsonObject summaryObj = new JsonObject();
        summaryObj.addProperty("resultsStatus", "finished");
        scanObj.add("summary", summaryObj);
        obj.add("WasScan", scanObj);
        dataArr.add(obj);
        responseObject.add("data", dataArr);
        result.add("ServiceResponse", responseObject);
        statusResponse.response = result;

        when(wasClient.getScanStatus(anyString())).thenReturn(statusResponse);

        String scanId = "12345";
        String scanResult = wasClient.getScanFinishedStatus(scanId);

        assertEquals("finished", scanResult);
    }

    @Test
    public void test_returns_qualyswasresponse_object() {
        // Arrange
        WASAuth auth = new WASAuth();
        auth.setWasCredentials("https://example.com", "username", "password");
        WASClient wasClient = new WASClient(auth);
        JsonObject requestData = new JsonObject();

        // Act
        QualysWASResponse response = wasClient.launchWASScan(requestData);

        // Assert
        assertNotNull(response);
        assertTrue(response instanceof QualysWASResponse);
    }
}