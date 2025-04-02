package com.disquoveri;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditor;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IMessageEditorController;
import burp.IHttpService;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.List;
import java.util.Arrays;

public class RequestResponsePanel extends JPanel implements IMessageEditorController {
    private final IMessageEditor requestViewer;
    private final IMessageEditor responseViewer;
    private final IBurpExtenderCallbacks callbacks;
    private byte[] currentRequest;
    private byte[] currentResponse;
    private String currentHostname;
    private String currentIP;

    public RequestResponsePanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        setLayout(new GridLayout(2, 1));

        // Request viewer
        requestViewer = callbacks.createMessageEditor(this, false);
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.add(new JLabel(" Request:"), BorderLayout.NORTH);
        requestPanel.add(requestViewer.getComponent(), BorderLayout.CENTER);

        // Response viewer
        responseViewer = callbacks.createMessageEditor(this, false);
        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.add(new JLabel(" Response:"), BorderLayout.NORTH);
        responsePanel.add(responseViewer.getComponent(), BorderLayout.CENTER);

        // Add panels
        add(requestPanel);
        add(responsePanel);

        // Register context menu
        callbacks.registerContextMenuFactory(new IContextMenuFactory() {
            @Override
            public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
                JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
                sendToRepeater.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_R, 
                    Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()));
                
                sendToRepeater.addActionListener(e -> sendToRepeater());
                
                return Arrays.asList(sendToRepeater);
            }
        });

        // Add keyboard shortcut
        registerKeyboardShortcut();
    }

    private void registerKeyboardShortcut() {
        // Register Ctrl+R shortcut
        KeyStroke ctrlR = KeyStroke.getKeyStroke(KeyEvent.VK_R, 
            Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx());
            
        getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(ctrlR, "sendToRepeater");
        getActionMap().put("sendToRepeater", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendToRepeater();
            }
        });
    }

    private void sendToRepeater() {
        if (currentRequest != null && currentHostname != null && currentIP != null) {
            try {
                // Determine if it's HTTPS based on response
                boolean isHttps = isHttpsResponse(currentResponse);
                int port = isHttps ? 443 : 80;
                
                // Send to Repeater
                callbacks.sendToRepeater(
                    currentIP,         // host
                    port,             // port
                    isHttps,          // useHttps
                    currentRequest,    // request
                    currentHostname    // tab name
                );
                
                callbacks.printOutput("Sent to Repeater: " + currentHostname + " (" + currentIP + ")");
            } catch (Exception ex) {
                callbacks.printError("Error sending to Repeater: " + ex.getMessage());
            }
        }
    }

    private boolean isHttpsResponse(byte[] response) {
        if (response == null) return false;
        try {
            String resp = new String(response, "UTF-8").toLowerCase();
            return resp.contains("https://") || 
                   resp.contains("301 moved") || 
                   resp.contains("302 found") ||
                   resp.contains("strict-transport-security");
        } catch (Exception e) {
            return false;
        }
    }

    public void updateRequestResponse(byte[] request, byte[] response, String hostname, String ip) {
        this.currentRequest = request;
        this.currentResponse = response;
        this.currentHostname = hostname;
        this.currentIP = ip;
        
        requestViewer.setMessage(request != null ? request : new byte[0], true);
        responseViewer.setMessage(response != null ? response : new byte[0], false);
    }

    @Override
    public IHttpService getHttpService() {
        return null;
    }

    @Override
    public byte[] getRequest() {
        return currentRequest;
    }

    @Override
    public byte[] getResponse() {
        return currentResponse;
    }
} 