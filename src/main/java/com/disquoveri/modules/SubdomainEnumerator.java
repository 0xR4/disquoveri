package com.disquoveri.modules;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import com.disquoveri.model.Subdomain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.concurrent.*;
import java.nio.charset.StandardCharsets;

public class SubdomainEnumerator {
    private static final Logger logger = LoggerFactory.getLogger(SubdomainEnumerator.class);
    private static final int MAX_TIMEOUT = 5; // seconds
    private static final int THREAD_POOL_SIZE = 50;

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private final DNSDumpster dnsdumpster;
    private final SecurityTrails securitytrails;
    private final WHOISXML whoisxmlapi;
    private final Map<String, Subdomain> subdomains;
    private final ExecutorService executorService;

    public SubdomainEnumerator(IBurpExtenderCallbacks callbacks, DNSDumpster dnsdumpster, SecurityTrails securitytrails, WHOISXML whoisxmlapi) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.dnsdumpster = dnsdumpster;
        this.securitytrails = securitytrails;
        this.whoisxmlapi = whoisxmlapi;
        this.subdomains = new HashMap<>();
        this.executorService = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
    }

    public Map<String, Subdomain> enumerate(String domain) {
        enumerateDnsDumpster(domain);
        enumerateSecurityTrails(domain);
        // Commented out as in original
        // enumerateWhoisXmlApi(domain);
        
        // Verify alive subdomains after enumeration
        verifyAliveSubdomains();
        
        // Cleanup
        cleanup();
        
        return subdomains;
    }

    private void cleanup() {
        // Shutdown the executor service
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(60, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    private void verifyAliveSubdomains() {
        logger.info("Starting alive verification for {} subdomains", subdomains.size());
        
        List<Future<VerificationResult>> futures = new ArrayList<>();
        
        for (Map.Entry<String, Subdomain> entry : subdomains.entrySet()) {
            futures.add(executorService.submit(() -> {
                String hostname = entry.getKey();
                Set<String> ipAddresses = resolveHostname(hostname);
                
                logger.debug("Found {} IPs for {}: {}", ipAddresses.size(), hostname, ipAddresses);
                
                Map<String, Boolean> ipStatuses = new HashMap<>();
                int activeCount = 0;

                for (String ip : ipAddresses) {
                    // Try HTTPS first
                    boolean isAlive = checkServiceWithHostHeader("https", ip, hostname);
                    if (!isAlive) {
                        // Try HTTP if HTTPS fails
                        isAlive = checkServiceWithHostHeader("http", ip, hostname);
                    }
                    ipStatuses.put(ip, isAlive);
                    if (isAlive) activeCount++;
                }

                return new VerificationResult(hostname, ipStatuses, activeCount > 1);
            }));
        }
        
        for (Future<VerificationResult> future : futures) {
            try {
                VerificationResult result = future.get(MAX_TIMEOUT * 2, TimeUnit.SECONDS);
                if (result != null) {
                    Subdomain subdomain = subdomains.get(result.getHostname());
                    if (subdomain != null) {
                        // Update each IP's status
                        for (Map.Entry<String, Boolean> ipStatus : result.getIpStatuses().entrySet()) {
                            subdomain.addIpInfo(
                                ipStatus.getKey(),
                                null,  // ASN name
                                null,  // ASN range
                                "ALIVE_CHECK",
                                null,
                                ipStatus.getValue()
                            );
                        }
                        subdomain.setHasMultipleActiveIPs(result.hasMultipleActiveIPs());
                    }
                }
            } catch (TimeoutException e) {
                logger.debug("Verification timed out");
            } catch (Exception e) {
                logger.error("Error during verification", e);
            }
        }
    }

    private boolean checkServiceWithHostHeader(String protocol, String ip, String hostname) {
        try {
            int port = protocol.equalsIgnoreCase("https") ? 443 : 80;
            
            logger.debug("Attempting {} connection to {}:{} with host header: {}", 
                protocol, ip, port, hostname);
            
            // Create Burp's HTTP service with specific IP
            IHttpService service = helpers.buildHttpService(ip, port, protocol.equalsIgnoreCase("https"));
            
            // Build request with Host header set to the subdomain
            List<String> headers = new ArrayList<>();
            headers.add("GET / HTTP/1.1");
            headers.add("Host: " + hostname);
            headers.add("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            headers.add("Accept: */*");
            headers.add("Connection: close");

            byte[] request = helpers.buildHttpMessage(headers, null);
            logger.debug("Built request ({} bytes): \n{}", 
                request.length, 
                new String(request, StandardCharsets.UTF_8));
            
            // Set timeout for the request
            // Note: This is handled by Burp's makeHttpRequest
            
            // Send request using Burp's HTTP stack
            logger.debug("Sending request to {}:{}", ip, port);
            IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(service, request);
            
            if (requestResponse == null) {
                logger.debug("Request failed - null response from makeHttpRequest");
                return false;
            }
            
            byte[] response = requestResponse.getResponse();
            if (response != null) {
                logger.debug("Received response ({} bytes) from {}:{}", 
                    response.length, ip, port);
                
                Subdomain subdomain = subdomains.get(hostname);
                if (subdomain != null) {
                    logger.debug("Storing request/response for {}:{}", hostname, ip);
                    subdomain.addRequestResponse(ip, request, response);
                    return true;
                } else {
                    logger.debug("No subdomain object found for {}", hostname);
                }
            } else {
                logger.debug("No response received from {}:{}", ip, port);
            }
            
            return false;
        } catch (Exception e) {
            logger.debug("Error checking {} on IP {}: {}", hostname, ip, e.getMessage(), e);
            return false;
        }
    }

    private void verifySubdomain(String hostname) {
        logger.debug("Verifying subdomain: {}", hostname);
        Subdomain subdomain = subdomains.get(hostname);
        if (subdomain == null) {
            logger.debug("No subdomain object found for {}", hostname);
            return;
        }

        Map<String, Object> dict = subdomain.toDict();
        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> ipInfo = (Map<String, Map<String, Object>>) dict.get("ips");
        
        if (ipInfo == null || ipInfo.isEmpty()) {
            logger.debug("No IPs found for {}", hostname);
            return;
        }

        int activeIPs = 0;
        for (Map.Entry<String, Map<String, Object>> entry : ipInfo.entrySet()) {
            String ip = entry.getKey();
            Map<String, Object> details = entry.getValue();
            
            logger.debug("Checking IP {} for {}", ip, hostname);
            
            // Try HTTPS first
            boolean httpsAlive = checkServiceWithHostHeader("https", ip, hostname);
            logger.debug("HTTPS check for {}:{} result: {}", hostname, ip, httpsAlive);
            
            // Try HTTP if HTTPS failed
            boolean httpAlive = false;
            if (!httpsAlive) {
                logger.debug("HTTPS failed for {}:{}, trying HTTP", hostname, ip);
                httpAlive = checkServiceWithHostHeader("http", ip, hostname);
                logger.debug("HTTP check for {}:{} result: {}", hostname, ip, httpAlive);
            }

            boolean isAlive = httpsAlive || httpAlive;
            if (isAlive) {
                activeIPs++;
                logger.debug("IP {} is alive for {} (HTTPS: {}, HTTP: {})", 
                    ip, hostname, httpsAlive, httpAlive);
                
                // Update the IP info with alive status
                details.put("is_alive", true);
            } else {
                logger.debug("IP {} is not responding for {}", ip, hostname);
                details.put("is_alive", false);
            }
        }

        subdomain.setHasMultipleActiveIPs(activeIPs > 1);
        logger.debug("Found {} active IPs for {}", activeIPs, hostname);
    }

    private void enumerateDnsDumpster(String domain) {
        Map<String, List<Map<String, Object>>> data = dnsdumpster.getRecords(domain);
        if (data == null) {
            return;
        }

        List<Map<String, Object>> records = data.get("a");
        if (records != null) {
            for (Map<String, Object> record : records) {
                String subdomainName = (String) record.get("host");
                if (!subdomains.containsKey(subdomainName)) {
                    subdomains.put(subdomainName, new Subdomain(subdomainName));
                }

                @SuppressWarnings("unchecked")
                List<Map<String, Object>> ips = (List<Map<String, Object>>) record.get("ips");
                for (Map<String, Object> ipInfo : ips) {
                    subdomains.get(subdomainName).addIpInfo(
                        (String) ipInfo.get("ip"),
                        (String) ipInfo.get("asn_name"),
                        (String) ipInfo.get("asn_range"),
                        "DD",
                        null,
                        true
                    );
                }
            }
        }
    }

    private void enumerateSecurityTrails(String domain) {
        Map<String, List<String>> data = securitytrails.getRecords(domain);
        if (data == null) {
            return;
        }

        List<String> subdomainList = data.get("subdomains");
        if (subdomainList != null) {
            for (String sub : subdomainList) {
                String fullDomain = sub + "." + domain;
                if (!subdomains.containsKey(fullDomain)) {
                    subdomains.put(fullDomain, new Subdomain(fullDomain));
                }
            }
        }
    }

    private Set<String> resolveHostname(String hostname) {
        Set<String> ipAddresses = new HashSet<>();
        try {
            InetAddress[] addresses = InetAddress.getAllByName(hostname);
            for (InetAddress addr : addresses) {
                ipAddresses.add(addr.getHostAddress());
            }
        } catch (UnknownHostException e) {
            logger.debug("Could not resolve hostname: {}", hostname);
        }
        return ipAddresses;
    }

    public static class VerificationResult {
        private final String hostname;
        private final Map<String, Boolean> ipStatuses;
        private final boolean hasMultipleActiveIPs;

        public VerificationResult(String hostname, Map<String, Boolean> ipStatuses, boolean hasMultipleActiveIPs) {
            this.hostname = hostname;
            this.ipStatuses = ipStatuses;
            this.hasMultipleActiveIPs = hasMultipleActiveIPs;
        }

        public String getHostname() {
            return hostname;
        }

        public Map<String, Boolean> getIpStatuses() {
            return ipStatuses;
        }

        public boolean hasMultipleActiveIPs() {
            return hasMultipleActiveIPs;
        }
    }
}