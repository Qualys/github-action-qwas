package com.example.GitHubActionsQWas.model;

import com.example.GitHubActionsQWas.WASClient.QualysAPIResponse;
import com.example.GitHubActionsQWas.WASClient.QualysWASResponse;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;

public class TestModel {

    @Test
    public void projectSetUp()
            throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        invokeMethods(QualysAPIResponse.class);
        invokeMethods(QualysWASResponse.class);
    }
    private <T> void invokeMethods(Class<T> tClass)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        Class c = Class.forName(tClass.getName());
        Object t = c.newInstance();

        Method[] allMethods = c.getDeclaredMethods();
        for (Method m : allMethods) {
            try {
                m.invoke(t, null);
            } catch (Exception e) {//
            }
        }
    }
}
