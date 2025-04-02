package com.disquoveri.model;

import java.util.HashMap;
import java.util.Map;
import burp.IHttpService;

public class Subdomain {
    private String name;
    private Map<String, Map<String, Object>> ips; // List of IP addresses
    private boolean hasMultipleActiveIPs;
    private Map<String, RequestResponse> requestResponses = new HashMap<>();

    public Subdomain(String name) {
        this.name = name;
        this.ips = new HashMap<>();
        this.hasMultipleActiveIPs = false;
    }

    public void addIpInfo(String ip, String asnName, String asnRange, String fromResource, String lastSeenDate, boolean isAlive) {
        if (ip != null && !ips.containsKey(ip)) {
            Map<String, Object> ipInfo = new HashMap<>();
            ipInfo.put("asn_name", asnName);
            ipInfo.put("asn_range", asnRange);
            ipInfo.put("from_resource", fromResource);
            ipInfo.put("last_seen_date", lastSeenDate);
            ipInfo.put("is_alive", isAlive);
            ips.put(ip, ipInfo);
        }
    }

    public String getName() {
        return name;
    }

    public Map<String, Object> toDict() {
        Map<String, Object> result = new HashMap<>();
        result.put("name", this.name);
        Map<String, Map<String, Object>> ipMap = new HashMap<>();
        for (String ip : ips.keySet()) {
            ipMap.put(ip, ips.get(ip));
        }
        result.put("ips", ipMap);
        return result;
    }

    public boolean hasIpAddresses() {
        return !ips.isEmpty();
    }

    public void setHasMultipleActiveIPs(boolean hasMultipleActiveIPs) {
        this.hasMultipleActiveIPs = hasMultipleActiveIPs;
    }

    public boolean hasMultipleActiveIPs() {
        return hasMultipleActiveIPs;
    }

    public void updateIpAliveStatus(String ip, boolean isAlive) {
        if (ips.containsKey(ip)) {
            ips.get(ip).put("is_alive", isAlive);
        }
    }

    public void addRequestResponse(String ip, byte[] request, byte[] response) {
        // Create a unique key combining hostname and IP
        String key = name + ":" + ip;
        if (request != null || response != null) {
            requestResponses.put(key, new RequestResponse(request, response));
            System.out.println("Stored request/response for " + key);
        }
    }

    public RequestResponse getRequestResponse(String ip) {
        // Use the combined key to retrieve request/response
        String key = name + ":" + ip;
        RequestResponse resp = requestResponses.get(key);
        if (resp != null) {
            System.out.println("Found request/response for " + key);
        } else {
            System.out.println("No request/response found for " + key);
        }
        return resp;
    }

    @Override
    public String toString() {
        return name;
    }

    public static class RequestResponse {
        private final byte[] request;
        private final byte[] response;

        public RequestResponse(byte[] request, byte[] response) {
            this.request = request;
            this.response = response;
        }

        public byte[] getRequest() { return request; }
        public byte[] getResponse() { return response; }
    }
}