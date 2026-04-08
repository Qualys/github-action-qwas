package com.example.GitHubActionsQWas.service;

import com.example.GitHubActionsQWas.WASClient.QualysWASResponse;
import com.example.GitHubActionsQWas.WASClient.WASClient;
import com.google.gson.JsonObject;
import org.junit.Test;
import org.mockito.Mockito;

import static com.github.stefanbirkner.systemlambda.SystemLambda.catchSystemExit;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class QualysWASScanStatusServiceTest {
    private static final int TIMEOUT = (60 * 5) + 50;

    // The fetchScanStatus method returns the scan status when the scan is finished.
    @Test
    public void test_fetchScanStatus_returnsScanStatusWhenScanIsFinished() {
        // Arrange
        String scanId = "123";
        String portalUrl = "https://example.com";
        String scanType = "vulnerability";
        boolean severityCheck = true;
        int interval = 1;
        String expectedStatus = "finished";

        WASClient mockClient = Mockito.mock(WASClient.class);
        Mockito.when(mockClient.getScanFinishedStatus(scanId)).thenReturn(expectedStatus);

        QualysWASScanStatusService service = new QualysWASScanStatusService(mockClient);

        // Act
        String actualStatus = service.fetchScanStatus(scanId, scanType, severityCheck, portalUrl, interval, TIMEOUT);

        // Assert
        assertEquals(expectedStatus, actualStatus);
    }

    // The fetchScanStatus method waits for the specified interval before making the next attempt to get the scan result.
    @Test
    public void test_fetchScanStatus_waitsForIntervalBeforeNextAttempt() {
        // Arrange
        String scanId = "123";
        String portalUrl = "https://example.com";
        int interval = 1;

        WASClient mockClient = Mockito.mock(WASClient.class);
        Mockito.when(mockClient.getScanFinishedStatus(scanId)).thenReturn(null, "finished");

        QualysWASScanStatusService service = new QualysWASScanStatusService(mockClient);

        // Act
        long startTime = System.currentTimeMillis();
        service.fetchScanStatus(scanId, "vulnerability", true, portalUrl, interval, TIMEOUT);
        long endTime = System.currentTimeMillis();

        // Assert
        long elapsedTime = endTime - startTime;
        assertTrue(elapsedTime >= interval * 6 * 100);
    }

    // The fetchScanStatus method waits for the scan to finish before returning the scan status.
    @Test
    public void test_fetchScanStatus_waitsForScanToFinishBeforeReturningStatus() {
        // Arrange
        String scanId = "123";
        String portalUrl = "https://example.com";
        int interval = 1;
        String expectedStatus = "finished";

        WASClient mockClient = Mockito.mock(WASClient.class);
        Mockito.when(mockClient.getScanFinishedStatus(scanId)).thenReturn(null, expectedStatus);

        QualysWASScanStatusService service = new QualysWASScanStatusService(mockClient);

        // Act
        String actualStatus = service.fetchScanStatus(scanId, "vulnerability", true, portalUrl, interval, TIMEOUT);

        // Assert
        assertEquals(expectedStatus, actualStatus);
    }

    // The fetchScanStatus method returns the scan status when the scan is finished within the timeout period.
    @Test
    public void test_fetchScanStatus_returnsScanStatusWithinTimeoutPeriod() {
        // Arrange
        String scanId = "123";
        String portalUrl = "https://example.com";
        int interval = 1;
        String expectedStatus = "finished";

        WASClient mockClient = Mockito.mock(WASClient.class);
        Mockito.when(mockClient.getScanFinishedStatus(scanId)).thenReturn(null, expectedStatus);

        QualysWASScanStatusService service = new QualysWASScanStatusService(mockClient);

        // Act
        String actualStatus = service.fetchScanStatus(scanId, "vulnerability", true, portalUrl, interval, TIMEOUT);

        // Assert
        assertEquals(expectedStatus, actualStatus);
    }

    // The fetchScanStatus method waits for the specified interval before making the next attempt to get the scan result when the scan is not finished.
    @Test
    public void test_fetchScanStatus_waitInterval() {
        // Create a mock WASClient
        WASClient clientMock = Mockito.mock(WASClient.class);

        // Create a QualysWASScanStatusService instance with the mock client
        QualysWASScanStatusService service = new QualysWASScanStatusService(clientMock);

        // Set up the mock behavior for getScanFinishedStatus
        Mockito.when(clientMock.getScanFinishedStatus(Mockito.anyString())).thenReturn(null, "finished");

        // Set up the timeout and interval values
        int timeout = 5; // in minutes
        int interval = 1; // in minutes

        // Call the fetchScanStatus method
        String scanId = "12345";
        String portalUrl = "https://example.com";
        String status = service.fetchScanStatus(scanId, "vulnerability", true, portalUrl, interval, timeout);

        // Verify that getScanFinishedStatus was called twice with the correct scanId
        Mockito.verify(clientMock, Mockito.times(2)).getScanFinishedStatus(scanId);

        // Verify that the status is "finished"
        assertEquals("finished", status);
    }

    // The fetchScanStatus method dumps the error message to a file and exits the program if the timeout period is reached.
    @Test
    public void test_fetchScanStatus_timeout() throws Exception {
        // Create a mock WASClient
        WASClient mockClient = Mockito.mock(WASClient.class);

        // Create a QualysWASScanStatusService instance with the mock objects
        QualysWASScanStatusService service = new QualysWASScanStatusService(mockClient);

        // Set the timeout and interval values
        int timeout = 1;
        int interval = 2;

        // Set the scanId and portalUrl values
        String scanId = "12345";
        String portalUrl = "https://example.com";

        Mockito.when(mockClient.getScanFinishedStatus(scanId)).thenReturn(null);

        int statusCode = catchSystemExit(() -> service.fetchScanStatus(scanId,"vulnerability", true, portalUrl, interval, timeout));

        // Verify that the getScanFinishedStatus method was called multiple times with the correct scanId
        Mockito.verify(mockClient, Mockito.atLeast(timeout)).getScanFinishedStatus(scanId);

        // Assert that the status is null
        assertEquals(1, statusCode);
    }

    // The fetchScanStatus method logs an error message when the scan result is not a JSON object.
    @Test
    public void test_fetchScanStatus_logsErrorMessageWhenScanResultIsNotJSONObject() {
        // Create a mock WASClient
        WASClient mockClient = Mockito.mock(WASClient.class);
        
        // Create a QualysWASScanStatusService instance with the mock client and logger
        QualysWASScanStatusService service = new QualysWASScanStatusService(mockClient);

        // Set up the mock client to return a non-JSON response
        QualysWASResponse mockResponse = new QualysWASResponse();
        mockResponse.response = new JsonObject();
        Mockito.when(mockClient.getScanFinishedStatus(Mockito.anyString())).thenReturn("");

        // Call the fetchScanStatus method
        String scanId = "12345";
        String portalUrl = "https://example.com";
        int interval = 1;
        String status = service.fetchScanStatus(scanId,"vulnerability", true, portalUrl, interval, TIMEOUT);

        // Verify that the status is null
        assertEquals("", status);
    }


    // The fetchScanStatus method waits for the specified interval before making the next attempt to get the scan result when the scan status is not available.
    @Test
    public void test_fetchScanStatus_waitsForInterval() {
        // Create a mock WASClient
        WASClient clientMock = Mockito.mock(WASClient.class);

        // Create a QualysWASScanStatusService instance with the mock client
        QualysWASScanStatusService service = new QualysWASScanStatusService(clientMock);

        // Set up the mock behavior for getScanFinishedStatus
        Mockito.when(clientMock.getScanFinishedStatus(Mockito.anyString())).thenReturn(null, "finished");

        // Call the fetchScanStatus method with a scanId, portalUrl, and interval
        String scanId = "12345";
        String portalUrl = "https://example.com";
        int interval = 1;
        String status = service.fetchScanStatus(scanId,"vulnerability", true, portalUrl, interval, TIMEOUT);

        // Verify that getScanFinishedStatus was called twice with the correct scanId
        Mockito.verify(clientMock, Mockito.times(2)).getScanFinishedStatus(scanId);

        // Verify that the returned status is "finished"
        assertEquals("finished", status);
    }

    // The fetchScanStatus method logs an error message when the scan status is not available within the timeout period.
    @Test
    public void test_fetchScanStatus_logsErrorMessageWhenScanStatusNotAvailableWithinTimeoutPeriod() throws Exception {
        // Create a mock WASClient
        WASClient mockClient = Mockito.mock(WASClient.class);

        // Create a QualysWASScanStatusService instance with the mock client
        QualysWASScanStatusService service = new QualysWASScanStatusService(mockClient);

        // Set up the mock client to return null for scan status
        Mockito.when(mockClient.getScanFinishedStatus(Mockito.anyString())).thenReturn(null);

        // Set up the timeout and interval values
        int timeout = 1; // minutes
        int interval = 2; // minute

        // Call the fetchScanStatus method
        String scanId = "12345";
        String portalUrl = "https://example.com";

        int statusCode = catchSystemExit(() -> service.fetchScanStatus(scanId,"vulnerability", true, portalUrl, interval, timeout));

        // Verify that the mock client's getScanFinishedStatus method was called
        Mockito.verify(mockClient, Mockito.atLeastOnce()).getScanFinishedStatus(scanId);

        assertEquals(1, statusCode);
    }
}