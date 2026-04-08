package com.example.GitHubActionsQWas.service;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.env.Environment;

import java.io.FileReader;

import static com.github.stefanbirkner.systemlambda.SystemLambda.catchSystemExit;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class QualysWASScanBuilderTest {
    private QualysWASScanBuilder builder;
    private Environment environment = mock(Environment.class);

    @Before
    public void setup() {
        when(environment.getProperty("API_SERVER", "")).thenReturn("https://example.com");
        when(environment.getProperty("QUALYS_USERNAME", "")).thenReturn("qualusUsername");
        when(environment.getProperty("QUALYS_PASSWORD", "")).thenReturn("qualysPassword");
        when(environment.getProperty("USE_PROXY", Boolean.class, false)).thenReturn(false);
        when(environment.getProperty("PROXY_SERVER", "")).thenReturn("proxyServer");
        when(environment.getProperty("PROXY_PORT", Integer.class, 0)).thenReturn(8080);
        when(environment.getProperty("PROXY_USERNAME", "")).thenReturn("proxyUsername");
        when(environment.getProperty("PROXY_PASSWORD", "")).thenReturn("proxyPassword");
        when(environment.getProperty("WEBAPP_ID", "")).thenReturn("1069358967");
        when(environment.getProperty("SCAN_NAME", "")).thenReturn("New WAS Vulnerability Scan launched from API");
        when(environment.getProperty("SCAN_TYPE", "")).thenReturn("VULNERABILITY");
        when(environment.getProperty("AUTH_RECORD", "none")).thenReturn("none");
        when(environment.getProperty("AUTH_RECORD_ID", "")).thenReturn("authRecordId");
        when(environment.getProperty("OPTION_PROFILE", "useDefault")).thenReturn("useDefault");
        when(environment.getProperty("OPTION_PROFILE_ID", "")).thenReturn("optionProfileId");
        when(environment.getProperty("CANCEL_OPTION", Boolean.class, false)).thenReturn(true);
        when(environment.getProperty("CANCEL_HOURS", "")).thenReturn("12");
        when(environment.getProperty("SEVERITY_CHECK", Boolean.class, false)).thenReturn(true);
        when(environment.getProperty("SEVERITY_LEVEL", Integer.class, 0)).thenReturn(4);
        when(environment.getProperty("IS_FAIL_ON_QID_FOUND", Boolean.class, false)).thenReturn(false);
        when(environment.getProperty("QID_LIST", "")).thenReturn("qidList");
        when(environment.getProperty("EXCLUDE", "")).thenReturn("");
        when(environment.getProperty("FAIL_ON_SCAN_ERROR", Boolean.class, false)).thenReturn(false);
        when(environment.getProperty("WAIT_FOR_RESULT", Boolean.class, true)).thenReturn(true);
        when(environment.getProperty("INTERVAL", Integer.class, 5)).thenReturn(5);
        when(environment.getProperty("TIMEOUT", Integer.class, (60 * 5) + 50)).thenReturn(350);

        builder = spy(new QualysWASScanBuilder(environment));
    }

    // Constructor assigns values to all parameters based on environment properties
    @Test
    public void test_constructor_assigns_values() throws Exception {
        assertEquals("https://example.com", builder.getApiServer());
        assertEquals("qualusUsername", builder.getQualysUsername());
        assertEquals("qualysPassword", builder.getQualysPasssword());
        assertFalse(builder.isUseProxy());
        assertEquals("proxyServer", builder.getProxyServer());
        assertEquals(8080, builder.getProxyPort());
        assertEquals("proxyUsername", builder.getProxyUsername());
        assertEquals("proxyPassword", builder.getProxyPassword());
        assertEquals("1069358967", builder.getWebAppId());
        assertEquals("New WAS Vulnerability Scan launched from API", builder.getScanName());
        assertEquals("VULNERABILITY", builder.getScanType());
        assertEquals("none", builder.getAuthRecord());
        assertEquals("authRecordId", builder.getAuthRecordId());
        assertEquals("useDefault", builder.getOptionProfile());
        assertEquals("optionProfileId", builder.getOptionProfileId());
        assertTrue(builder.isCancelOptions());
        assertEquals("12", builder.getCancelHours());
        assertTrue(builder.isFailOnSevereVulns());
        assertTrue(builder.isSeverityCheck());
        assertEquals(4, builder.getSeverityLevel());
        assertEquals(5, builder.getInterval());
        assertEquals(350, builder.getTimeout());
        assertFalse(builder.isSev1Vulns());
        assertFalse(builder.isSev2Vulns());
        assertFalse(builder.isSev3Vulns());
        assertTrue(builder.isSev4Vulns());
        assertTrue(builder.isSev5Vulns());
        assertEquals("", builder.getExclude());
        assertFalse(builder.isFailOnScanError());
        assertNull("", builder.getPollingInterval());
        assertNull("", builder.getVulnsTimeout());
        assertTrue(builder.isWaitForResult());
        assertNotNull(builder.getClient());
        assertEquals(0, builder.getSeverity1Limit());
        assertEquals(0, builder.getSeverity2Limit());
        assertEquals(0, builder.getSeverity3Limit());
        assertEquals(1, builder.getSeverity4Limit());
        assertEquals(1, builder.getSeverity5Limit());
        assertNotNull(builder.getEnvironment());
    }

    @Test
    public void test_validateParameters() throws Exception {
        builder.validateParameters();

        builder.setAuthRecord("authRecord");
        int statusCode = catchSystemExit(builder::validateParameters);
        assertEquals(1, statusCode);

        builder.setAuthRecord("none");
        builder.setOptionProfile("optionProfile");
        statusCode = catchSystemExit(builder::validateParameters);
        assertEquals(1, statusCode);
    }

    @Test
    public void test_assignSeverities() throws Exception {
        builder.setSeverityLevel(1);
        builder.assignSeverities();

        assertTrue(builder.isSev1Vulns());
        assertTrue(builder.isSev2Vulns());
        assertTrue(builder.isSev3Vulns());
        assertTrue(builder.isSev4Vulns());
        assertTrue(builder.isSev5Vulns());

        builder.setSeverityLevel(6);
        int statusCode = catchSystemExit(builder::assignSeverities);
        assertEquals(1, statusCode);
    }

    @Test
    public void test_returns_non_null_json_object_with_fail_conditions_field() {
        JsonObject criteria = builder.getCriteriaAsJsonObject();
        assertNotNull(criteria);
        assertTrue(criteria.has("failConditions"));
    }

    @Test
    public void test_adds_severities_field_when_is_fail_on_severe_vulns_is_true() {
        QualysWASScanBuilder builder = new QualysWASScanBuilder(environment);
        builder.setFailOnSevereVulns(true);
        builder.setSev1Vulns(true);
        builder.setSeverity1Limit(10);
        builder.setSev2Vulns(true);
        builder.setSeverity2Limit(20);
        JsonObject criteria = builder.getCriteriaAsJsonObject();
        assertTrue(criteria.has("failConditions"));
        JsonObject failConditions = criteria.getAsJsonObject("failConditions");
        assertTrue(failConditions.has("severities"));
        JsonObject severities = failConditions.getAsJsonObject("severities");
        assertTrue(severities.has("1"));
        assertEquals(10, severities.get("1").getAsInt());
        assertTrue(severities.has("2"));
        assertEquals(20, severities.get("2").getAsInt());
    }

    @Test
    public void test_adds_exclude_qids_field_when_exclude_is_not_null_or_empty() {
        builder.setExclude("4,5,6");
        JsonObject criteria = builder.getCriteriaAsJsonObject();
        assertTrue(criteria.has("failConditions"));
        JsonObject failConditions = criteria.getAsJsonObject("failConditions");
        assertTrue(failConditions.has("excludeQids"));
        JsonArray excludeQids = failConditions.getAsJsonArray("excludeQids");
        assertEquals(3, excludeQids.size());
    }

    @Test
    public void test_adds_fail_on_scan_error_field_when_is_fail_on_scan_error_is_true() {
        builder.setFailOnScanError(true);
        JsonObject criteria = builder.getCriteriaAsJsonObject();
        assertTrue(criteria.has("failConditions"));
        JsonObject failConditions = criteria.getAsJsonObject("failConditions");
        assertTrue(failConditions.has("failOnScanError"));
        assertTrue(failConditions.get("failOnScanError").getAsBoolean());
    }

    @Test
    public void test_all_mandatory_parameters_set() {
        QualysWASScanBuilder builder = new QualysWASScanBuilder(environment);
        builder.setApiServer("apiServer");
        builder.setQualysUsername("qualysUsername");
        builder.setQualysPasssword("qualysPassword");
        builder.setWebAppId("webAppId");
        builder.setScanName("scanName");
        builder.setScanType("scanType");

        boolean result = builder.isMandatoryParametersSet();

        assertTrue(result);
    }

    @Test
    public void test_testConnection_with_invalid_credentials() throws Exception {
        builder.setQualysUsername("invalidUsername");
        builder.setQualysPasssword("invalidPassword");
        builder.initWASClient();

        int statusCode = catchSystemExit(builder::testConnection);

        assertEquals(1, statusCode);
    }

    @Test
    public void test_launch_scan_successfully_fail_condition_configured_and_build_failed() throws Exception {
        builder.setWaitForResult(true);
        builder.setSeverityCheck(true);
        builder.assignSeverities();

        doReturn("FINISHED").when(builder).getScanFinishedStatus(anyString());

        try (FileReader reader = new FileReader("src/test/java/test_data/test_scanResult_mockData_1.json")) {
            JsonObject returnData = new JsonParser().parse(reader).getAsJsonObject();
            doReturn(returnData).when(builder).fetchScanResult(any(QualysWASScanResultParser.class), anyString());
        }

        try (FileReader reader = new FileReader("src/test/java/test_data/test_failurePolicyEvaluationResult_buildFailed_mockData.json")) {
            JsonObject returnData = new JsonParser().parse(reader).getAsJsonObject();
            doReturn(returnData).when(builder).evaluateFailurePolicy(any(JsonObject.class));
        }

        doReturn("12345678").when(builder).launchWasScan(any(QualysWASScanService.class));
        doReturn(true).when(builder).testConnection();

        // Assert statements
        int statusCode = catchSystemExit(builder::launchWebApplicationScan);

        assertEquals(1, statusCode);
    }

    @Test
    public void test_launch_scan_successfully_fetch_result_failure() throws Exception {
        builder.setWaitForResult(true);
        QualysWASScanService mockService = mock(QualysWASScanService.class);

        doReturn("FINISHED").when(builder).getScanFinishedStatus(anyString());

        try (FileReader reader = new FileReader("src/test/java/test_data/test_scanResult_mockData_2.json")) {
            JsonObject returnData = new JsonParser().parse(reader).getAsJsonObject();
            doReturn(returnData).when(builder).fetchScanResult(any(QualysWASScanResultParser.class), anyString());
        }

        doReturn("12345678").when(builder).launchWasScan(any(QualysWASScanService.class));
        doReturn(true).when(builder).testConnection();

        // Assert statements
        int statusCode = catchSystemExit(builder::launchWebApplicationScan);

        assertEquals(1, statusCode);
    }

    @Test
    public void test_evaluateFailurePolicy() throws Exception {
        builder.setSeverityCheck(true);
        builder.setSeverityLevel(1);
        builder.assignSeverities();

        try (FileReader reader = new FileReader("src/test/java/test_data/test_scanResult_mockData_1.json")) {
            JsonObject returnData = new JsonParser().parse(reader).getAsJsonObject();
            JsonObject result = builder.evaluateFailurePolicy(returnData);
            assertNotNull(result);
        }
    }

    @Test
    public void test_getScanFinishedStatus() {
        doReturn("FINISHED").when(builder).getScanFinishedStatus(anyString());
        String status = builder.getScanFinishedStatus("38931000");
        assertNotNull(status);
    }

    @Test
    public void test_isMandatoryParametersSet() {
        doReturn(true).when(builder).isMandatoryParametersSet();
        boolean result = builder.isMandatoryParametersSet();
        assertTrue(result);
    }

    @Test
    public void test_returns_json_object_with_valid_scan_id() {
        // Arrange
        QualysWASScanResultParser resultParser = mock(QualysWASScanResultParser.class);
        String scanId = "valid_scan_id";
        JsonObject expectedJson = new JsonObject();
        when(resultParser.fetchScanResult(scanId)).thenReturn(expectedJson);

        // Act
        JsonObject actualJson = builder.fetchScanResult(resultParser, scanId);

        // Assert
        assertEquals(expectedJson, actualJson);
    }
}