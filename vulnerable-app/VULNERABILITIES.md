# Phase 1.1: Vulnerable Spring Boot Application - Testing Guide

## Overview
This document describes the three intentional vulnerabilities implemented in the Spring Boot application and how to test them.

## Running the Application

```bash
cd vulnerable-app
mvn spring-boot:run
```

The application will start on `http://localhost:8080`

## Test Users

| Username | Password   | Role  |
|----------|------------|-------|
| alice    | alice123   | USER  |
| bob      | bob123     | USER  |
| admin    | admin123   | ADMIN |

## Vulnerability 1: SQL Injection (Simple)

**Location:** `UserController.java` - `/api/users/search` endpoint

**Description:** Direct string concatenation in SQL query

**Test:**
```bash
# Normal search
curl -u alice:alice123 "http://localhost:8080/api/users/search?username=alice"

# SQL Injection attack
curl -u alice:alice123 "http://localhost:8080/api/users/search?username=alice'%20OR%20'1'='1"
```

**Expected Behavior:**
- Normal search returns users matching "alice"
- SQLi attack returns ALL users due to the injected `OR '1'='1` condition

**Detection:**
- **SAST (Semgrep):** Should detect string concatenation in SQL
- **DAST (ZAP):** Should detect SQLi via active scanning
- **CodeQL:** Should trace data flow from `@RequestParam` to JDBC execute

## Vulnerability 2: Simple IDOR (Insecure Direct Object Reference)

**Location:** `UserController.java` - `/api/users/{userId}` endpoint  
**Security:** `AuthorizationService.isMe()` method

**Description:** The `@PreAuthorize("@authorizationService.isMe(#userId)")` annotation promises to verify that the user can only access their own data. However, the `isMe()` implementation only checks if the user is authenticated, NOT if the userId matches the current user.

**Test:**
```bash
# Alice accessing her own data (ID=1) - should work
curl -u alice:alice123 http://localhost:8080/api/users/1

# Alice accessing Bob's data (ID=2) - SHOULD FAIL but DOESN'T
curl -u alice:alice123 http://localhost:8080/api/users/2
```

**Expected Behavior:**
- Alice should ONLY be able to access user ID 1 (herself)
- Due to the bug, Alice CAN access user ID 2 (Bob's data)

**Detection:**
- **SAST:** Harder to detect - requires understanding that `isMe()` doesn't use the parameter
- **DAST:** Can detect by authenticating as different users and testing cross-access
- **CodeQL:** Should show that the `userId` parameter is never compared to the authenticated user

## Vulnerability 3: Complex IDOR / Logic Flaw (Multi-Step)

**Location:** `OrderController.java` - `/api/companies/{companyId}/orders/{orderId}` endpoint  
**Security:** `AuthorizationService.isOrderOwner()` method

**Description:** This is a more sophisticated authorization bypass:
1. The endpoint path suggests orders are scoped to companies: `/api/companies/{companyId}/orders/{orderId}`
2. The `@PreAuthorize` checks if the user owns the order
3. **THE BUG:** It doesn't validate that the order belongs to the specified company

**Attack Scenario:**
```
- Alice owns Company 1 and Order 1 (Company 1 → Order 1)
- Bob owns Company 2 and Order 2 (Company 2 → Order 2)
- Alice can access: /api/companies/1/orders/1 ✓ (legitimate)
- Alice can ALSO access: /api/companies/2/orders/1 ✗ (BUG!)
```

**Test:**
```bash
# Setup: Get order IDs first
curl -u alice:alice123 http://localhost:8080/api/companies/1/orders
curl -u bob:bob123 http://localhost:8080/api/companies/2/orders

# Alice accessing her order through her company (legitimate)
curl -u alice:alice123 http://localhost:8080/api/companies/1/orders/1

# Alice accessing her order through Bob's company (SHOULD FAIL but DOESN'T)
curl -u alice:alice123 http://localhost:8080/api/companies/2/orders/1

# Test shipping address update vulnerability
curl -u alice:alice123 -X PUT \
  -H "Content-Type: application/json" \
  -d "999 Hacker Street" \
  http://localhost:8080/api/companies/2/orders/1/shipping
```

**Expected Behavior:**
- Alice should NOT be able to access `/api/companies/2/orders/1` because Order 1 doesn't belong to Company 2
- Due to the bug, the check only validates Alice owns Order 1, not the company context

**Root Cause in Code:**
```java
// AuthorizationService.java
public boolean isOrderOwner(Long orderId) {
    // ...
    return order.getUser().getUsername().equals(username);
    // BUG: Missing validation: 
    // order.getCompany().getId().equals(companyIdFromRequest)
}
```

**Detection:**
- **SAST:** Very difficult - requires understanding the relationship between URL structure and authorization logic
- **DAST:** Requires behavioral testing with multiple users and understanding the data model
- **CodeQL + Semantic Analysis:** Need to:
  1. Extract the URL pattern: `/companies/{companyId}/orders/{orderId}`
  2. Analyze `@PreAuthorize` annotation
  3. Trace that `companyId` parameter is never used in authorization
  4. Understand that Order entity has a relationship to Company

## Summary

| Vulnerability | Type | Detection Difficulty | Tools That Should Find It |
|---------------|------|----------------------|---------------------------|
| SQL Injection | CWE-89 | Easy | Semgrep, ZAP, CodeQL |
| Simple IDOR | CWE-639 | Medium | DAST (with behavioral tests), CodeQL |
| Complex IDOR | CWE-639 + CWE-285 | Hard | Semantic analysis, CodeQL + policy extraction |

## Next Steps

These vulnerabilities will be used to test the correlation engine's ability to:
1. Find simple vulnerabilities with traditional tools
2. Correlate SAST + DAST findings
3. Detect complex logic flaws by comparing security policies with implementation
