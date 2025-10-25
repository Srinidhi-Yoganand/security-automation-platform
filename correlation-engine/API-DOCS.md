# Phase 2 API Endpoints

## Overview
The Security Behavior Analysis API provides endpoints to query vulnerability lifecycle data, risk scores, patterns, and metrics.

## Base URL
```
http://localhost:8000
```

## Endpoints

### 1. List Vulnerabilities
**GET** `/api/v1/vulnerabilities`

Get a list of vulnerabilities with optional filtering.

**Query Parameters:**
- `state` (optional): Filter by state (`new`, `existing`, `fixed`, `regressed`, `ignored`)
- `severity` (optional): Filter by severity (`critical`, `high`, `medium`, `low`)
- `limit` (optional, default: 50): Maximum number of results

**Example Request:**
```bash
curl http://localhost:8000/api/v1/vulnerabilities?state=existing&severity=high
```

**Example Response:**
```json
{
  "count": 2,
  "vulnerabilities": [
    {
      "id": 1,
      "type": "SQL Injection",
      "severity": "high",
      "state": "existing",
      "file_path": "src/main/java/com/security/controller/UserController.java",
      "line_number": 45,
      "confidence": 0.9,
      "risk_score": 8.5,
      "age_days": 15,
      "first_seen": "2024-01-01T10:00:00",
      "last_seen": "2024-01-15T10:00:00"
    }
  ]
}
```

---

### 2. Get Vulnerability History
**GET** `/api/v1/vulnerabilities/{vuln_id}/history`

Get the complete lifecycle history of a specific vulnerability.

**Path Parameters:**
- `vuln_id`: The vulnerability ID

**Example Request:**
```bash
curl http://localhost:8000/api/v1/vulnerabilities/1/history
```

**Example Response:**
```json
{
  "vulnerability": {
    "id": 1,
    "fingerprint": "f624f42b98f1fc9b...",
    "type": "SQL Injection",
    "file_path": "src/main/java/...",
    "line_number": 45
  },
  "state_transitions": [
    {
      "from_state": null,
      "to_state": "new",
      "transition_date": "2024-01-01T10:00:00",
      "scan_id": 1
    },
    {
      "from_state": "new",
      "to_state": "existing",
      "transition_date": "2024-01-05T10:00:00",
      "scan_id": 2
    }
  ],
  "total_transitions": 2
}
```

---

### 3. Get Metrics Overview
**GET** `/api/v1/metrics/overview`

Get overall security metrics for the repository.

**Example Request:**
```bash
curl http://localhost:8000/api/v1/metrics/overview
```

**Example Response:**
```json
{
  "total_scans": 10,
  "total_vulnerabilities": 25,
  "by_state": {
    "new": 3,
    "existing": 12,
    "fixed": 8,
    "regressed": 2
  },
  "by_severity": {
    "critical": 2,
    "high": 5,
    "medium": 10,
    "low": 8
  },
  "mean_time_to_fix_days": 7.5,
  "average_risk_score": 5.8
}
```

---

### 4. Get Security Patterns
**GET** `/api/v1/patterns`

Get identified security patterns over time.

**Example Request:**
```bash
curl http://localhost:8000/api/v1/patterns
```

**Example Response:**
```json
{
  "patterns": [
    {
      "pattern_id": "sql-injection-controller",
      "name": "SQL Injection in Controllers",
      "occurrences": [
        {
          "scan_id": 1,
          "timestamp": "2024-01-01T10:00:00",
          "count": 3
        }
      ]
    }
  ]
}
```

---

### 5. Analyze Patterns
**POST** `/api/v1/patterns/analyze`

Run pattern analysis on current vulnerabilities.

**Example Request:**
```bash
curl -X POST http://localhost:8000/api/v1/patterns/analyze
```

**Example Response:**
```json
{
  "patterns_found": [
    {
      "pattern_id": "sql-injection-controller",
      "name": "SQL Injection in Controllers",
      "description": "SQL injection vulnerabilities in controller classes",
      "category": "vulnerability-pattern",
      "count": 3,
      "severity": "high",
      "remediation": "Use parameterized queries...",
      "affected_files": [
        "src/main/java/com/security/controller/UserController.java"
      ]
    }
  ],
  "hotspots": [
    {
      "type": "file",
      "path": "src/main/java/com/security/controller/UserController.java",
      "vulnerability_count": 4,
      "total_risk_score": 25.5,
      "vulnerabilities": [...]
    }
  ],
  "clusters": [
    {
      "pattern": "IDOR (multiple occurrences)",
      "size": 2,
      "vulnerabilities": [...]
    }
  ],
  "recommendations": [
    "Address SQL Injection in Controllers pattern (3 occurrences)",
    "Review hotspot file: UserController.java (4 vulnerabilities)"
  ]
}
```

---

### 6. Get Risk-Ranked Vulnerabilities
**GET** `/api/v1/risk-scores`

Get vulnerabilities ranked by risk score (highest first).

**Query Parameters:**
- `limit` (optional, default: 20): Maximum number of results

**Example Request:**
```bash
curl http://localhost:8000/api/v1/risk-scores?limit=10
```

**Example Response:**
```json
{
  "count": 10,
  "vulnerabilities": [
    {
      "id": 1,
      "type": "SQL Injection",
      "severity": "high",
      "risk_score": 8.5,
      "risk_category": "Critical",
      "file_path": "src/main/java/com/security/controller/UserController.java",
      "line_number": 45,
      "age_days": 15,
      "state": "existing"
    }
  ]
}
```

---

## Risk Categories

Risk scores range from 0.0 to 10.0 and are categorized as:

- **Critical**: 8.5 - 10.0 (Immediate attention required)
- **High**: 7.0 - 8.5 (Should be addressed soon)
- **Medium**: 4.0 - 7.0 (Address in normal workflow)
- **Low**: 0.0 - 4.0 (Monitor but lower priority)

## Vulnerability States

- `new`: Newly discovered in the latest scan
- `existing`: Persisted from previous scans
- `fixed`: No longer detected (was present before)
- `regressed`: Reappeared after being fixed
- `ignored`: Manually marked to ignore

## Testing the API

### 1. Start the server:
```bash
cd correlation-engine
python run_server.py
```

The server will start at `http://localhost:8000`

### 2. View API documentation:
Open your browser to `http://localhost:8000/docs` for interactive Swagger UI documentation.

### 3. Example curl commands:

```bash
# Get all vulnerabilities
curl http://localhost:8000/api/v1/vulnerabilities

# Get only high severity existing vulnerabilities
curl "http://localhost:8000/api/v1/vulnerabilities?state=existing&severity=high"

# Get metrics overview
curl http://localhost:8000/api/v1/metrics/overview

# Run pattern analysis
curl -X POST http://localhost:8000/api/v1/patterns/analyze

# Get top 5 highest risk vulnerabilities
curl "http://localhost:8000/api/v1/risk-scores?limit=5"

# Get history of vulnerability #1
curl http://localhost:8000/api/v1/vulnerabilities/1/history
```

## Integration with Phase 1

The Phase 2 API builds on Phase 1 by:
1. Storing correlation results in the database
2. Tracking vulnerabilities over time
3. Calculating risk scores based on multiple factors
4. Identifying patterns in security findings

To integrate:
1. Run Phase 1 correlation: `POST /api/v1/correlate`
2. Store results using Phase 2 lifecycle tracker
3. Query insights using Phase 2 endpoints
