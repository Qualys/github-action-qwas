package com.example.GitHubActionsQWas.constants;

/**
 * @author jyadav@qualys.com
 */
public class Constants {

    public static final String CREATE_REPORT_REQUEST_BODY = "{\"ServiceRequest\":{\"data\":{\"Report\":{\"name\":\"ScanReport_CreateScanId\",\"description\":\"Report\",\"format\":\"fileType\",\"type\":\"WAS_SCAN_REPORT\",\"config\":{\"scanReport\":{\"target\":{\"scans\":{\"WasScan\":{\"id\":\"CreateScanId\"}}}}}}}}}";
    public static final String TEXT_TO_REPLACE_SCAN_ID = "CreateScanId";
    public static final String TEXT_TO_REPLACE_FILE_FORMAT = "fileType";
    public static final String SERVICE_RESPONSE = "ServiceResponse";
    public static final String RESPONSE_CODE = "responseCode";
    public static final String SUCCESS = "SUCCESS";
    public static final String DATA = "data";
    public static final String REPORT = "Report";
    public static final String ID = "id";
    public static final String STATUS = "status";
    public static final String COMPLETE = "COMPLETE";
    public static final String UNKNOWN = "UNKNOWN";
    public static final String PDF_FORMAT = "PDF";

}
