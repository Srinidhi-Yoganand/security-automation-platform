package com.example.vulnerable;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

/**
 * Intentionally vulnerable application for security testing
 * Contains multiple vulnerability types for comprehensive testing
 */
public class VulnerableApp {
    
    private Connection dbConnection;
    
    // SQL Injection Vulnerability
    public String getUserData(String userId) {
        try {
            Statement stmt = dbConnection.createStatement();
            // VULNERABLE: Direct string concatenation in SQL query
            String query = "SELECT * FROM users WHERE id = '" + userId + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                return rs.getString("username");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    // XSS Vulnerability
    public String displayUserInput(HttpServletRequest request) {
        String userInput = request.getParameter("comment");
        // VULNERABLE: No HTML encoding
        return "<div>User said: " + userInput + "</div>";
    }
    
    // Path Traversal Vulnerability
    public String readFile(String filename) {
        try {
            // VULNERABLE: No path validation
            String filePath = "/var/www/files/" + filename;
            java.nio.file.Files.readString(java.nio.file.Paths.get(filePath));
            return filePath;
        } catch (Exception e) {
            return "Error reading file";
        }
    }
    
    // Command Injection Vulnerability
    public String pingServer(String host) {
        try {
            // VULNERABLE: Direct command execution with user input
            Process process = Runtime.getRuntime().exec("ping -c 1 " + host);
            java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(process.getInputStream())
            );
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return output.toString();
        } catch (Exception e) {
            return "Error executing ping";
        }
    }
    
    // Insecure Deserialization
    public Object deserializeData(byte[] data) {
        try {
            // VULNERABLE: Unsafe deserialization
            java.io.ObjectInputStream ois = new java.io.ObjectInputStream(
                new java.io.ByteArrayInputStream(data)
            );
            return ois.readObject();
        } catch (Exception e) {
            return null;
        }
    }
    
    // Weak Cryptography
    public String encryptPassword(String password) {
        try {
            // VULNERABLE: Using MD5 for password hashing
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            return java.util.Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            return null;
        }
    }
    
    // IDOR (Insecure Direct Object Reference)
    public String getDocument(int documentId) {
        // VULNERABLE: No authorization check
        try {
            Statement stmt = dbConnection.createStatement();
            String query = "SELECT content FROM documents WHERE id = " + documentId;
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                return rs.getString("content");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    // XXE (XML External Entity) Vulnerability
    public void parseXml(String xmlInput) {
        try {
            // VULNERABLE: XXE attack possible
            javax.xml.parsers.DocumentBuilderFactory factory = 
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
            javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
            java.io.ByteArrayInputStream input = new java.io.ByteArrayInputStream(
                xmlInput.getBytes()
            );
            builder.parse(input);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Hard-coded Credentials
    public boolean authenticate(String username, String password) {
        // VULNERABLE: Hard-coded credentials
        String adminUser = "admin";
        String adminPass = "password123";
        
        return username.equals(adminUser) && password.equals(adminPass);
    }
    
    // Insufficient Logging
    public void processPayment(double amount, String cardNumber) {
        // VULNERABLE: Logging sensitive data
        System.out.println("Processing payment: $" + amount + " with card " + cardNumber);
    }
}
