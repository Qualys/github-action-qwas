package com.example.GitHubActionsQWas.service;

import com.example.GitHubActionsQWas.WASClient.QualysWASResponse;
import com.example.GitHubActionsQWas.WASClient.WASClient;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.io.FileReader;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class QualysWASScanResultParserTest {

    @Test
    public void test_instantiation_with_json_criteria_and_wasclient_object() {
        String criteriaJson = "{\"failConditions\":{\"severities\":{\"1\":5,\"2\":10,\"3\":15,\"4\":20,\"5\":25},\"excludeQids\":[\"5-10\"]}}";
        WASClient mockClient = mock(WASClient.class);

        assertDoesNotThrow(() -> new QualysWASScanResultParser(criteriaJson, mockClient));
    }

    @Test
    public void test_instantiation_with_empty_json_criteria_and_wasclient_object() {
        String criteriaJson = "{\"failConditions\":{}}";
        WASClient mockClient = mock(WASClient.class);

        assertDoesNotThrow(() -> new QualysWASScanResultParser(criteriaJson, mockClient));
    }

    @Test
    public void test_returns_json_object_with_valid_scan_id() throws Exception {
        // Create a mock WASClient
        WASClient clientMock = mock(WASClient.class);

        // Create a mock QualysWASResponse
        QualysWASResponse responseMock = mock(QualysWASResponse.class);

        // Create a JsonObject for the scan result
        JsonObject scanResult = new JsonObject();
        // Add necessary properties to the scan result

        // Set up the mock objects
        when(clientMock.getScanResult(anyString())).thenReturn(responseMock);
        when(responseMock.getResponse()).thenReturn(scanResult);

        // Create an instance of QualysWASScanResultParser
        QualysWASScanResultParser parser = new QualysWASScanResultParser("{\"failConditions\":{}}", clientMock);

        // Call the fetchScanResult method with a valid scanId
        JsonObject result = parser.fetchScanResult("validScanId");

        // Assert that the returned JsonObject is the same as the scan result
        assertEquals(scanResult, result);
    }

    @Test
    public void test_returns_json_object() throws Exception {
        QualysWASScanResultParser parser = new QualysWASScanResultParser("{\"failConditions\":{}}", null);
        JsonObject expectedResult = parser.returnObject;

        JsonObject result = parser.getResult();

        assertEquals(expectedResult, result);
    }

    @Test
    public void test_correctly_evaluates_severity() throws Exception {
        // Arrange
        JsonObject statsData = new JsonObject();
        statsData.addProperty("nbVulnsLevel1", 3);
        statsData.addProperty("nbVulnsLevel2", 5);
        statsData.addProperty("nbVulnsLevel3", 2);
        statsData.addProperty("nbVulnsLevel4", 0);
        statsData.addProperty("nbVulnsLevel5", 0);

        QualysWASScanResultParser parser = new QualysWASScanResultParser("{\"failConditions\":{}}", null);

        // Act
        boolean result = parser.evaluateSev(statsData);

        // Assert
        assertTrue(result);
    }

    @Test
    public void test_success_with_vulnerabilities() throws Exception {
        JsonObject response = new JsonObject();
        JsonObject serviceResponseObj = new JsonObject();
        serviceResponseObj.addProperty("responseCode", "success");
        JsonArray dataArr = new JsonArray();
        JsonObject scanObj = new JsonObject();
        JsonObject vulns = new JsonObject();
        JsonObject wasScan = new JsonObject();
        JsonObject statsData = new JsonObject();
        JsonObject globalStats = new JsonObject();
        vulns.addProperty("count", 1);
        JsonArray vulnsList = new JsonArray();

        try (FileReader reader = new FileReader("src/test/java/test_data/test_vulnerabilityArray_mockData.json")) {
            JsonObject vuln = new JsonParser().parse(reader).getAsJsonObject();
            vulnsList.add(vuln.getAsJsonArray("list").get(0));
        }

        vulns.add("list", vulnsList);
        scanObj.add("vulns", vulns);
        statsData.add("global", globalStats);
        scanObj.add("stats", statsData);
        wasScan.add("WasScan", scanObj);
        dataArr.add(wasScan);
        serviceResponseObj.add("data", dataArr);
        response.add("ServiceResponse", serviceResponseObj);

        QualysWASScanResultParser parser = spy(new QualysWASScanResultParser("{\"failConditions\":{\"severities\":{\"1\":5,\"2\":10,\"3\":15,\"4\":20,\"5\":25},\"excludeQids\":[\"5-150263\"]}}", null));
        doReturn(true).when(parser).evaluateSev(any(JsonObject.class));

        Boolean result = parser.evaluate(response);
        assertTrue(result);
    }
}