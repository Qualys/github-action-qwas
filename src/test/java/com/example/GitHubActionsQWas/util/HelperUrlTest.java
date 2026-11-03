package com.example.GitHubActionsQWas.util;

import org.junit.jupiter.api.Test;

import static com.example.GitHubActionsQWas.util.Helper.deriveGatewayUrl;
import static com.example.GitHubActionsQWas.util.Helper.derivePortalUrl;
import static com.example.GitHubActionsQWas.util.Helper.normalizeUrl;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Verifies API server -> gateway/portal URL derivation against the official
 * Qualys platform list: https://www.qualys.com/platform-identification/
 */
class HelperUrlTest {

    @Test
    void gateway_urls_for_all_shared_platforms() {
        // US1 and EU1 are special: API host has no qgN segment but gateway does
        assertEquals("https://gateway.qg1.apps.qualys.com", deriveGatewayUrl("https://qualysapi.qualys.com"));
        assertEquals("https://gateway.qg1.apps.qualys.eu", deriveGatewayUrl("https://qualysapi.qualys.eu"));
        // GOV1: no qgN segment on either side
        assertEquals("https://gateway.gov1.qualys.us", deriveGatewayUrl("https://qualysapi.gov1.qualys.us"));
        // Standard qgN platforms
        assertEquals("https://gateway.qg2.apps.qualys.com", deriveGatewayUrl("https://qualysapi.qg2.apps.qualys.com"));
        assertEquals("https://gateway.qg3.apps.qualys.com", deriveGatewayUrl("https://qualysapi.qg3.apps.qualys.com"));
        assertEquals("https://gateway.qg4.apps.qualys.com", deriveGatewayUrl("https://qualysapi.qg4.apps.qualys.com"));
        assertEquals("https://gateway.qg2.apps.qualys.eu", deriveGatewayUrl("https://qualysapi.qg2.apps.qualys.eu"));
        assertEquals("https://gateway.qg3.apps.qualys.it", deriveGatewayUrl("https://qualysapi.qg3.apps.qualys.it"));
        assertEquals("https://gateway.qg1.apps.qualys.in", deriveGatewayUrl("https://qualysapi.qg1.apps.qualys.in"));
        assertEquals("https://gateway.qg1.apps.qualys.ca", deriveGatewayUrl("https://qualysapi.qg1.apps.qualys.ca"));
        assertEquals("https://gateway.qg1.apps.qualys.ae", deriveGatewayUrl("https://qualysapi.qg1.apps.qualys.ae"));
        assertEquals("https://gateway.qg1.apps.qualys.co.uk", deriveGatewayUrl("https://qualysapi.qg1.apps.qualys.co.uk"));
        assertEquals("https://gateway.qg1.apps.qualys.com.au", deriveGatewayUrl("https://qualysapi.qg1.apps.qualys.com.au"));
        assertEquals("https://gateway.qg1.apps.qualysksa.com", deriveGatewayUrl("https://qualysapi.qg1.apps.qualysksa.com"));
    }

    @Test
    void gateway_url_for_private_platforms_uses_qualysgateway_prefix() {
        // Private Cloud Platforms: https://qualysapi.<customer_base_url> -> https://qualysgateway.<customer_base_url>
        assertEquals("https://qualysgateway.customer.example.com", deriveGatewayUrl("https://qualysapi.customer.example.com"));
        assertEquals("https://qualysgateway.intranet.acme.local", deriveGatewayUrl("https://qualysapi.intranet.acme.local"));
    }

    @Test
    void portal_urls_derived_from_api_server() {
        assertEquals("https://qualysguard.qualys.com", derivePortalUrl("https://qualysapi.qualys.com"));
        assertEquals("https://qualysguard.qualys.eu", derivePortalUrl("https://qualysapi.qualys.eu"));
        assertEquals("https://qualysguard.gov1.qualys.us", derivePortalUrl("https://qualysapi.gov1.qualys.us"));
        assertEquals("https://qualysguard.qg2.apps.qualys.com", derivePortalUrl("https://qualysapi.qg2.apps.qualys.com"));
        assertEquals("https://qualysguard.qg1.apps.qualysksa.com", derivePortalUrl("https://qualysapi.qg1.apps.qualysksa.com"));
        assertEquals("https://qualysguard.customer.example.com", derivePortalUrl("https://qualysapi.customer.example.com"));
    }

    @Test
    void normalize_url_strips_trailing_slashes_and_whitespace() {
        assertEquals("https://qualysapi.qualys.com", normalizeUrl(" https://qualysapi.qualys.com/ "));
        assertEquals("https://qualysapi.qualys.com", normalizeUrl("https://qualysapi.qualys.com//"));
        assertEquals("https://qualysapi.qualys.com", normalizeUrl("https://qualysapi.qualys.com"));
    }
}
