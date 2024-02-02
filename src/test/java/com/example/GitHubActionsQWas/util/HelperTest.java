package com.example.GitHubActionsQWas.util;

import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

import static org.junit.Assert.*;

public class HelperTest {
    // setTimeoutInMinutes method returns calculated timeout in minutes when timeout is in regex form
    @Test
    public void test_calculate_timeout_in_minutes_when_timeout_is_in_regex_form() {
        int defaultTimeoutInMins = 60;
        String timeout = "2*60*60";

        int result = Helper.setTimeoutInMinutes("vulnsTimeout", defaultTimeoutInMins, timeout);

        assertEquals(7200, result);
    }

    // setTimeoutInMinutes method returns default timeout when timeout is null or empty
    @Test
    public void test_setTimeoutInMinutes_default_timeout_when_timeout_is_null_or_empty() {
        int defaultTimeoutInMins = 10;
        String timeout = null;

        int result = Helper.setTimeoutInMinutes("timeout", defaultTimeoutInMins, timeout);

        assertEquals(defaultTimeoutInMins, result);
    }

    // dumpDataIntoFile method creates directory and writes data to file successfully
    @Test
    public void test_dumpDataIntoFile_creates_directory_and_writes_data_to_file_successfully() {
        // Arrange
        String data = "Test data";
        String fileName = "test.txt";
        String expectedFilePath = "outputs/test.txt";

        // Act
        Helper.dumpDataIntoFile(data, fileName);

        // Assert
        File file = new File(expectedFilePath);
        assertTrue(file.exists());
        assertTrue(file.isFile());
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String fileData = reader.readLine();
            assertEquals(data, fileData);
        } catch (IOException e) {
            fail("Exception occurred while reading the file: " + e.getMessage());
        }
    }

    // setTimeoutInMinutes method returns default timeout when timeout is not a valid number
    @Test
    public void test_setTimeoutInMinutes_invalid_timeout_1() {
        int defaultTimeout = 60;
        String timeout = "invalid";

        int result = Helper.setTimeoutInMinutes("timeout", defaultTimeout, timeout);

        assertEquals(defaultTimeout, result);
    }

    // setTimeoutInMinutes method logs error and returns default timeout when timeout is not in regex form and cannot be parsed
    @Test
    public void test_setTimeoutInMinutes_invalid_timeout_2() {
        // Arrange
        int defaultTimeoutInMins = 60;
        String timeout = "invalid_timeout";
        int expectedTimeout = defaultTimeoutInMins;

        // Act
        int actualTimeout = Helper.setTimeoutInMinutes("vulnsTimeout", defaultTimeoutInMins, timeout);

        // Assert
        assertEquals(expectedTimeout, actualTimeout);
    }
}