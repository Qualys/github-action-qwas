package com.example.GitHubActions.service;

import com.example.GitHubActions.WASClient.WASClient;
import org.junit.Before;
import org.junit.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@SpringBootTest
public class QualysWASScanStatusServiceTest {
    private QualysWASScanStatusService statusService;

    private WASClient client;

    @Before
    public void setup() {
        client = mock(WASClient.class);
        statusService = new QualysWASScanStatusService(client);
    }

    @Test
    public void testFetchScanStatus() {
//        when(statusService.fetchScanStatus(any())).thenReturn("FINISHED");
        when(client.getScanFinishedStatus(any())).thenReturn("FINISHED");
        String actualStatus = client.getScanFinishedStatus("38620594");
        verify(client, times(1)).getScanFinishedStatus("38620594");
        assertEquals(actualStatus, "FINISHED");
    }
}