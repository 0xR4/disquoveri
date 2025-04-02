package com.disquoveri;

import com.disquoveri.model.Subdomain;
import com.disquoveri.modules.DNSDumpster;
import com.disquoveri.modules.SecurityTrails;
import com.disquoveri.modules.SubdomainEnumerator;
import com.disquoveri.modules.WHOISXML;
import java.util.Map;

public class DisquoveriTest {
    // These would typically come from a config file
    private static final String DNSDUMPSTER_API = "https://api.dnsdumpster.com/domain/";
    private static final String DNSDUMPSTER_API_KEY = "c751ba3828f835be80d9f3ca9a332c8642a547c92299814d7fe17a6be3d4b938";
    private static final String SECURITYTRAILS_API = "http://api.securitytrails.com/v1/";
    private static final String SECURITYTRAILS_API_KEY = "k8KZg3ikKZBpAqGDxScHY6zi1gbSf6B-";
    private static final String WHOISXML_API = "https://subdomains.whoisxmlapi.com/api/v1";
    private static final String WHOISXML_API_KEY = "at_rFdt9jRRdfPWyNXAFKVVgzoT0g2K6";

    public static void main(String[] args) {
        // Initialize services
        DNSDumpster dnsDumpster = new DNSDumpster(DNSDUMPSTER_API, DNSDUMPSTER_API_KEY);
        SecurityTrails securityTrails = new SecurityTrails(SECURITYTRAILS_API, SECURITYTRAILS_API_KEY);
        WHOISXML whoisXml = new WHOISXML(WHOISXML_API, WHOISXML_API_KEY);

        // Pass null for callbacks when testing outside of Burp
        SubdomainEnumerator enumerator = new SubdomainEnumerator(null, dnsDumpster, securityTrails, whoisXml);

        // Test domain
        String testDomain = "my.gov.az";
        System.out.println("Testing domain: " + testDomain);

        // Enumerate subdomains
        Map<String, Subdomain> results = enumerator.enumerate(testDomain);

        // Print results
        System.out.println("\nFound subdomains:");
        for (Map.Entry<String, Subdomain> entry : results.entrySet()) {
            Subdomain subdomain = entry.getValue();
            System.out.println("\nSubdomain: " + subdomain.getName());
            
            Map<String, Object> dict = subdomain.toDict();
            @SuppressWarnings("unchecked")
            Map<String, Map<String, Object>> ipInfo = (Map<String, Map<String, Object>>) dict.get("ips");
            
            if (ipInfo != null && !ipInfo.isEmpty()) {
                System.out.println("IPs:");
                for (Map.Entry<String, Map<String, Object>> ip : ipInfo.entrySet()) {
                    System.out.println("  IP: " + ip.getKey());
                    Map<String, Object> details = ip.getValue();
                    System.out.println("    ASN Name: " + details.get("asn_name"));
                    System.out.println("    ASN Range: " + details.get("asn_range"));
                    System.out.println("    From Resource: " + details.get("from_resource"));
                }
            }
        }
    }
} 