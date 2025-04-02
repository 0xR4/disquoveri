package com.disquoveri.modules;

import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SecurityTrails {
    private static final Logger logger = LoggerFactory.getLogger(SecurityTrails.class);
    private final String apiUrl;
    private final String apiKey;
    private final Map<String, List<String>> exampleSubs;
    
    public SecurityTrails(String apiUrl, String apiKey) {
        this.apiUrl = apiUrl;
        this.apiKey = apiKey;
        this.exampleSubs = createExampleData();
    }
    
    private Map<String, List<String>> createExampleData() {
        Map<String, List<String>> data = new HashMap<>();
        List<String> subdomains = Arrays.asList(
            "asanloginmobilepreprod", "www.feedback", "test", "www.asanlogintest",
            "esignasanloginprod", "ssoauth", "admin", "www.asanlogin", "adminasanlogin",
            "notification", "asanlogin", "apiasanloginpreprod", "apiasanlogindev",
            "www.asanlogindev", "adminasanlogintest", "asanlogintest", "feedback",
            "services", "backendadmin", "cdn"
        );
        data.put("subdomains", subdomains);
        return data;
    }
    
    public Map<String, List<String>> getRecords(String domain) {
        try {
            // For now, return example data as in Python version
            return exampleSubs;
        } catch (Exception e) {
            logger.error("Error fetching SecurityTrails data: ", e);
            return null;
        }
    }
} 