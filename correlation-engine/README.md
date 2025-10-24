# Correlation Engine

An intelligent security findings correlation engine that ingests results from SAST, DAST, and CodeQL tools to identify and confirm vulnerabilities.

## Features

### Phase 1: Basic Intelligence
- Ingest and parse SARIF (Semgrep), JSON (ZAP), and CodeQL CSV results
- Correlate findings using data flow analysis
- Generate unified vulnerability reports

### Phase 2: Security Behavior Analysis (Coming Soon)
- Extract security policies from code annotations
- Behavioral DAST testing
- Specification vs. implementation gap analysis

### Phase 3: Advanced Patch Generation (Coming Soon)
- Context-aware vulnerability analysis
- LLM-powered patch generation
- Automated validation and PR creation

## Architecture

```
correlation-engine/
├── app/
│   ├── main.py              # FastAPI application & CLI entry point
│   ├── api/                 # REST API endpoints
│   ├── core/                # Core correlation logic
│   │   ├── parsers/         # SARIF, JSON, CSV parsers
│   │   ├── correlator.py    # Main correlation engine
│   │   └── dataflow.py      # Data flow analysis
│   ├── models/              # Pydantic data models
│   ├── services/            # Business logic services
│   └── utils/               # Helper utilities
├── tests/                   # Test suite
├── config/                  # Configuration files
└── data/                    # Sample data for testing
```

## Installation

```bash
cd correlation-engine
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

### As a Web Service

```bash
uvicorn app.main:app --reload
```

The API will be available at `http://localhost:8000`

### As a CLI Tool

```bash
# Correlate scan results
python -m app.main correlate \
  --semgrep ../scan-results/semgrep.sarif \
  --codeql ../scan-results/codeql/ \
  --zap ../scan-results/zap.json \
  --output correlation-report.json

# Generate dashboard
python -m app.main dashboard \
  --input correlation-report.json \
  --output security-dashboard.html
```

## API Endpoints

### POST /api/v1/correlate
Correlate findings from multiple security scanners

**Request:**
```json
{
  "semgrep_sarif": "base64_encoded_sarif",
  "codeql_data": "base64_encoded_csv",
  "zap_json": "base64_encoded_json"
}
```

**Response:**
```json
{
  "correlation_id": "uuid",
  "total_findings": 15,
  "correlated_findings": 8,
  "confirmed_vulnerabilities": 5,
  "findings": [...]
}
```

### GET /api/v1/findings/{correlation_id}
Retrieve correlation results

### POST /api/v1/findings/{finding_id}/patch
Generate a patch for a specific finding (Phase 3)

## Development

```bash
# Run tests
pytest

# Format code
black app/

# Type checking
mypy app/

# Linting
flake8 app/
```

## Configuration

Create a `.env` file:

```env
# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
DEBUG=false

# Database
DATABASE_URL=postgresql://user:pass@localhost/correlation_db

# LLM API Keys (for Phase 3)
OPENAI_API_KEY=your_key_here
```

## Phase 1: Correlation Logic

The engine performs multi-stage correlation:

1. **Parse Results**: Ingest SARIF, JSON, and CSV formats
2. **Normalize**: Convert to unified finding format
3. **Match**: Find overlapping findings by location
4. **Data Flow Analysis**: Use CodeQL data flow to confirm vulnerabilities
5. **Severity Scoring**: Calculate confidence scores based on correlation
6. **Report**: Generate actionable findings

### Example Correlation

```
DAST Finding: SQL Injection at /api/users/search?username=test
SAST Finding: String concatenation in SQL at UserController.java:35
CodeQL: Data flow from @RequestParam username to jdbcTemplate.query()
→ CONFIRMED: High confidence SQL Injection vulnerability
```

## License

MIT
