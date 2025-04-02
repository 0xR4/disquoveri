package com.disquoveri;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.ITab;
import burp.IExtensionHelpers;
import burp.IHttpService;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import com.disquoveri.model.Subdomain;
import com.disquoveri.modules.DNSDumpster;
import com.disquoveri.modules.SecurityTrails;
import com.disquoveri.modules.SubdomainEnumerator;
import com.disquoveri.modules.WHOISXML;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.DefaultTreeCellRenderer;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPanel;
    private JSplitPane splitPane;
    private JTree resultsTree;
    private DefaultTreeModel treeModel;
    private JTextField domainTextField;
    private JLabel statusLabel;
    private RequestResponsePanel requestResponsePanel;

    // API configurations
    private static final String DNSDUMPSTER_API = "https://api.dnsdumpster.com/domain/";
    private static final String DNSDUMPSTER_API_KEY = "c751ba3828f835be80d9f3ca9a332c8642a547c92299814d7fe17a6be3d4b938";
    private static final String SECURITYTRAILS_API = "http://api.securitytrails.com/v1/";
    private static final String SECURITYTRAILS_API_KEY = "k8KZg3ikKZBpAqGDxScHY6zi1gbSf6B-";
    private static final String WHOISXML_API = "https://subdomains.whoisxmlapi.com/api/v1";
    private static final String WHOISXML_API_KEY = "at_rFdt9jRRdfPWyNXAFKVVgzoT0g2K6";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        // Register as a context menu factory
        callbacks.registerContextMenuFactory(this);
        
        callbacks.setExtensionName("Disquoveri Subdomain Scanner");

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                // Main split pane
                splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                
                // Left panel with tree
                JPanel leftPanel = new JPanel(new BorderLayout());
                
                // Input panel
                JPanel inputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
                domainTextField = new JTextField(20);
                JButton scanButton = new JButton("Scan");
                scanButton.addActionListener(e -> performScan());
                
                inputPanel.add(new JLabel("Domain:"));
                inputPanel.add(domainTextField);
                inputPanel.add(scanButton);
                
                // Add status label
                statusLabel = new JLabel(" ");
                inputPanel.add(statusLabel);
                
                // Results tree
                DefaultMutableTreeNode root = new DefaultMutableTreeNode("Subdomains");
                treeModel = new DefaultTreeModel(root);
                resultsTree = new JTree(treeModel);
                resultsTree.setCellRenderer(new CustomTreeCellRenderer());
                
                // Add mouse listener for tree
                resultsTree.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        DefaultMutableTreeNode node = (DefaultMutableTreeNode)
                            resultsTree.getLastSelectedPathComponent();
                        
                        if (node != null) {
                            Object userObject = node.getUserObject();
                            callbacks.printOutput("Selected node type: " + userObject.getClass().getName());
                            
                            if (userObject instanceof ResponseInfo) {
                                ResponseInfo responseInfo = (ResponseInfo) userObject;
                                requestResponsePanel.updateRequestResponse(
                                    responseInfo.getRequest(),
                                    responseInfo.getResponse(),
                                    responseInfo.getHostname(),
                                    responseInfo.getIpAddress()
                                );
                            }
                        }
                    }
                });
                
                JScrollPane treeScrollPane = new JScrollPane(resultsTree);
                
                leftPanel.add(inputPanel, BorderLayout.NORTH);
                leftPanel.add(treeScrollPane, BorderLayout.CENTER);
                
                // Right panel with request/response
                requestResponsePanel = new RequestResponsePanel(callbacks);
                
                // Add panels to split pane
                splitPane.setLeftComponent(leftPanel);
                splitPane.setRightComponent(requestResponsePanel);
                splitPane.setDividerLocation(400);
                
                // Add to main panel
                mainPanel = new JPanel(new BorderLayout());
                mainPanel.add(splitPane, BorderLayout.CENTER);
                
                callbacks.customizeUiComponent(mainPanel);
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    private void performScan() {
        String domain = domainTextField.getText().trim();
        if (domain.isEmpty()) {
            return;
        }

        statusLabel.setText("Scanning...");

        // Initialize API clients
        DNSDumpster dnsDumpster = new DNSDumpster(DNSDUMPSTER_API, DNSDUMPSTER_API_KEY);
        SecurityTrails securityTrails = new SecurityTrails(SECURITYTRAILS_API, SECURITYTRAILS_API_KEY);
        WHOISXML whoisXml = new WHOISXML(WHOISXML_API, WHOISXML_API_KEY);

        // Create enumerator with callbacks
        SubdomainEnumerator enumerator = new SubdomainEnumerator(callbacks, dnsDumpster, securityTrails, whoisXml);

        // Clear previous results
        DefaultMutableTreeNode root = (DefaultMutableTreeNode) treeModel.getRoot();
        root.removeAllChildren();
        treeModel.reload();
        requestResponsePanel.updateRequestResponse(null, null, null, null);

        // Run scan in background thread
        new Thread(() -> {
            try {
                // Enumerate subdomains
                Map<String, Subdomain> results = enumerator.enumerate(domain);

                // Update UI in EDT
                SwingUtilities.invokeLater(() -> {
                    updateResultsTree(results);
                    requestResponsePanel.updateRequestResponse(null, null, null, null);
                });

            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    requestResponsePanel.updateRequestResponse(null, null, null, null);
                });
            }
        }).start();
    }

    private class CustomTreeCellRenderer extends DefaultTreeCellRenderer {
        @Override
        public Component getTreeCellRendererComponent(JTree tree, Object value,
                boolean selected, boolean expanded, boolean leaf, int row, boolean hasFocus) {
            
            Component c = super.getTreeCellRendererComponent(tree, value, selected,
                    expanded, leaf, row, hasFocus);

            DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
            Object userObject = node.getUserObject();

            // Reset color to default
            setForeground(UIManager.getColor("Tree.textForeground"));

            if (node.getParent() == tree.getModel().getRoot()) {
                // This is a subdomain node
                Subdomain subdomain = (Subdomain) userObject;
                if (subdomain.hasMultipleActiveIPs()) {
                    setForeground(Color.RED);
                    setToolTipText("Multiple active IPs detected!");
                }
            }

            return c;
        }
    }

    private void updateResultsTree(Map<String, Subdomain> results) {
        DefaultMutableTreeNode root = (DefaultMutableTreeNode) treeModel.getRoot();
        root.removeAllChildren();

        for (Map.Entry<String, Subdomain> entry : results.entrySet()) {
            Subdomain subdomain = entry.getValue();
            DefaultMutableTreeNode subdomainNode = new DefaultMutableTreeNode(subdomain);

            Map<String, Object> dict = subdomain.toDict();
            @SuppressWarnings("unchecked")
            Map<String, Map<String, Object>> ipInfo = (Map<String, Map<String, Object>>) dict.get("ips");

            if (ipInfo != null && !ipInfo.isEmpty()) {
                for (Map.Entry<String, Map<String, Object>> ip : ipInfo.entrySet()) {
                    String ipAddress = ip.getKey();
                    
                    // Create ResponseInfo for this IP
                    Subdomain.RequestResponse reqResp = subdomain.getRequestResponse(ipAddress);
                    ResponseInfo responseInfo = new ResponseInfo(
                        "IP: " + ipAddress,
                        reqResp != null ? reqResp.getRequest() : null,
                        reqResp != null ? reqResp.getResponse() : null,
                        subdomain.getName(),
                        ipAddress
                    );
                    
                    // Create IP node with ResponseInfo
                    DefaultMutableTreeNode ipNode = new DefaultMutableTreeNode(responseInfo);
                    
                    // Add IP details
                    Map<String, Object> details = ip.getValue();
                    if (details.get("asn_name") != null) {
                        ipNode.add(new DefaultMutableTreeNode("ASN Name: " + details.get("asn_name")));
                    }
                    if (details.get("asn_range") != null) {
                        ipNode.add(new DefaultMutableTreeNode("ASN Range: " + details.get("asn_range")));
                    }
                    if (details.get("from_resource") != null) {
                        ipNode.add(new DefaultMutableTreeNode("Source: " + details.get("from_resource")));
                    }
                    
                    subdomainNode.add(ipNode);
                }
            }

            root.add(subdomainNode);
        }

        treeModel.reload();
    }

    @Override
    public String getTabCaption() {
        return "Disquoveri";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) 
            resultsTree.getLastSelectedPathComponent();
            
        if (node != null && node.getUserObject() instanceof ResponseInfo) {
            JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
            ResponseInfo responseInfo = (ResponseInfo) node.getUserObject();
            
            // Get the parent node (IP node) to extract IP and hostname
            DefaultMutableTreeNode ipNode = (DefaultMutableTreeNode) node.getParent();
            DefaultMutableTreeNode subdomainNode = (DefaultMutableTreeNode) ipNode.getParent();
            
            String ipAddress = ipNode.toString().replace("IP: ", "");
            String hostname = subdomainNode.toString();
            
            sendToRepeater.addActionListener(e -> {
                try {
                    // Determine if it's HTTPS based on response
                    boolean isHttps = isHttpsResponse(responseInfo.getResponse());
                    int port = isHttps ? 443 : 80;
                    
                    // Send to Repeater
                    callbacks.sendToRepeater(
                        ipAddress,              // host
                        port,                   // port
                        isHttps,               // useHttps
                        responseInfo.getRequest(), // request
                        hostname               // tab name
                    );
                    
                    callbacks.printOutput("Sent to Repeater: " + hostname + " (" + ipAddress + ")");
                } catch (Exception ex) {
                    callbacks.printError("Error sending to Repeater: " + ex.getMessage());
                }
            });
            
            return Arrays.asList(sendToRepeater);
        }
        
        return null;
    }

    private boolean isHttpsResponse(byte[] response) {
        if (response == null) return false;
        try {
            // Look for HTTPS indicators in the response
            String resp = new String(response, "UTF-8").toLowerCase();
            return resp.contains("https://") || 
                   resp.contains("301 moved") || 
                   resp.contains("302 found") ||
                   resp.contains("strict-transport-security");
        } catch (Exception e) {
            return false;
        }
    }

    // Helper class to store response information
    private static class ResponseInfo {
        private final String displayName;
        private final byte[] request;
        private final byte[] response;
        private final String hostname;
        private final String ipAddress;

        public ResponseInfo(String displayName, byte[] request, byte[] response, String hostname, String ipAddress) {
            this.displayName = displayName;
            this.request = request;
            this.response = response;
            this.hostname = hostname;
            this.ipAddress = ipAddress;
        }

        public byte[] getRequest() { return request; }
        public byte[] getResponse() { return response; }
        public String getHostname() { return hostname; }
        public String getIpAddress() { return ipAddress; }

        @Override
        public String toString() {
            return displayName;
        }
    }
}