# 🔌 Integration SDK - Use with Any Java Application

This guide shows how to integrate the Security Automation Platform with **any Java application** for automated vulnerability scanning and AI-powered patching.

---

## ⚠️ Important Clarification

**The platform is pluggable, NOT the test app!**

- ✅ **Security Platform** (Correlation Engine) - Scans ANY Java application (yours, your client's, open source)
- ❌ **Vulnerable App** - This is ONLY a test application included in the source code for testing purposes
  - NOT deployed to production
  - NOT pushed to Docker Hub
  - NOT used by end users
  - Users scan THEIR OWN applications

**What "Pluggable" Means:**
Your security platform can scan and patch **any external Java application** via REST API, Maven, Gradle, or other integration methods. You deploy the platform, and it analyzes OTHER people's code.

---

## 🎯 Integration Options

### 1. **REST API Client** (Any Language)
### 2. **Maven Plugin** (Java/Maven Projects)
### 3. **Gradle Plugin** (Java/Gradle Projects)
### 4. **GitHub Actions** (CI/CD Integration)
### 5. **CLI Tool** (Command Line)
### 6. **Docker Sidecar** (Containerized Apps)

---

## 1️⃣ REST API Client (Universal)

### For Any Application (Java, Python, Node.js, etc.)

```java
// Java Example
import java.net.http.*;
import java.net.URI;

public class SecurityClient {
    private static final String API_BASE = "http://localhost:8000";
    
    // Upload scan results
    public static void uploadScan(String sarif) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(API_BASE + "/api/v1/scan"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(sarif))
            .build();
        
        HttpResponse<String> response = client.send(request, 
            HttpResponse.BodyHandlers.ofString());
        System.out.println("Scan uploaded: " + response.body());
    }
    
    // Generate patch for vulnerability
    public static String generatePatch(String vulnId) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(API_BASE + "/api/v1/vulnerabilities/" + 
                vulnId + "/generate-patch"))
            .POST(HttpRequest.BodyPublishers.noBody())
            .build();
        
        HttpResponse<String> response = client.send(request, 
            HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
}
```

### Python Example
```python
import requests

class SecurityClient:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
    
    def upload_scan(self, sarif_data):
        """Upload scan results"""
        response = requests.post(
            f"{self.base_url}/api/v1/scan",
            json=sarif_data
        )
        return response.json()
    
    def generate_patch(self, vuln_id):
        """Generate patch for vulnerability"""
        response = requests.post(
            f"{self.base_url}/api/v1/vulnerabilities/{vuln_id}/generate-patch"
        )
        return response.json()
    
    def get_dashboard_url(self):
        """Get dashboard URL"""
        return f"{self.base_url}/dashboard"

# Usage
client = SecurityClient()
client.upload_scan(sarif_data)
patch = client.generate_patch("vuln-123")
```

### Node.js Example
```javascript
const axios = require('axios');

class SecurityClient {
    constructor(baseUrl = 'http://localhost:8000') {
        this.baseUrl = baseUrl;
    }
    
    async uploadScan(sarifData) {
        const response = await axios.post(
            `${this.baseUrl}/api/v1/scan`,
            sarifData
        );
        return response.data;
    }
    
    async generatePatch(vulnId) {
        const response = await axios.post(
            `${this.baseUrl}/api/v1/vulnerabilities/${vulnId}/generate-patch`
        );
        return response.data;
    }
}

// Usage
const client = new SecurityClient();
await client.uploadScan(sarifData);
const patch = await client.generatePatch('vuln-123');
```

---

## 2️⃣ Maven Plugin Integration

### Add to your `pom.xml`

```xml
<project>
    <build>
        <plugins>
            <!-- Security Automation Plugin -->
            <plugin>
                <groupId>com.security.automation</groupId>
                <artifactId>security-maven-plugin</artifactId>
                <version>1.0.0</version>
                <configuration>
                    <apiEndpoint>http://localhost:8000</apiEndpoint>
                    <autoGeneratePatches>true</autoGeneratePatches>
                    <failOnCritical>true</failOnCritical>
                    <scanTools>
                        <tool>semgrep</tool>
                        <tool>spotbugs</tool>
                    </scanTools>
                </configuration>
                <executions>
                    <execution>
                        <phase>verify</phase>
                        <goals>
                            <goal>scan</goal>
                            <goal>analyze</goal>
                            <goal>patch</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>
</project>
```

### Run Security Scan
```bash
# Full scan with patch generation
mvn security:scan

# Analyze existing results
mvn security:analyze

# Generate patches only
mvn security:patch

# View dashboard
mvn security:dashboard
```

---

## 3️⃣ Gradle Plugin Integration

### Add to your `build.gradle`

```groovy
plugins {
    id 'com.security.automation' version '1.0.0'
}

securityAutomation {
    apiEndpoint = 'http://localhost:8000'
    autoGeneratePatches = true
    failOnCritical = true
    scanTools = ['semgrep', 'spotbugs']
    
    notifications {
        slack {
            webhook = System.env.SLACK_WEBHOOK_URL
        }
    }
}
```

### Run Security Scan
```bash
# Full scan with patch generation
gradle securityScan

# Generate patches only
gradle generatePatches

# View dashboard
gradle securityDashboard
```

---

## 4️⃣ GitHub Actions Integration

### `.github/workflows/security-scan.yml`

```yaml
name: Security Scan & Auto-Patch

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Weekly scan

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    services:
      security-platform:
        image: srinivas/security-automation:latest
        ports:
          - 8000:8000
        env:
          LLM_PROVIDER: ollama
          OLLAMA_MODEL: deepseek-coder:6.7b-instruct
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Set up JDK
        uses: actions/setup-java@v3
        with:
          java-version: '17'
          distribution: 'temurin'
      
      - name: Run Semgrep scan
        run: |
          pip install semgrep
          semgrep --config=auto --sarif > semgrep-results.sarif
      
      - name: Upload to Security Platform
        run: |
          curl -X POST http://localhost:8000/api/v1/scan \
            -H "Content-Type: application/json" \
            -d @semgrep-results.sarif
      
      - name: Generate patches
        run: |
          curl -X POST http://localhost:8000/api/v1/patches/generate-all
      
      - name: Download patches
        run: |
          curl http://localhost:8000/api/v1/patches/download -o patches.zip
          unzip patches.zip
      
      - name: Create PR with patches
        uses: peter-evans/create-pull-request@v5
        with:
          commit-message: 'fix: Apply AI-generated security patches'
          title: '🔒 Security: Auto-generated patches'
          body: |
            ## 🤖 AI-Generated Security Patches
            
            This PR contains automated security patches generated by the Security Automation Platform.
            
            **Review required:** Please review patches before merging.
          branch: security/auto-patches
          labels: security, automated
```

---

## 5️⃣ CLI Tool (Standalone)

### Installation
```bash
# Via pip
pip install security-automation-cli

# Via Docker
docker pull srinivas/security-automation-cli:latest
```

### Usage
```bash
# Scan current project
security-scan --auto-patch

# Upload existing SARIF results
security-upload --file semgrep-results.sarif

# Generate patches for specific vulnerability
security-patch --vuln-id CVE-2024-1234

# View dashboard
security-dashboard --open

# Export results
security-export --format pdf --output security-report.pdf
```

---

## 6️⃣ Docker Sidecar Pattern

### For Containerized Java Applications

```yaml
version: '3.8'

services:
  # Your Java Application
  my-java-app:
    image: mycompany/my-app:latest
    ports:
      - "8080:8080"
    depends_on:
      - security-platform
    environment:
      - SECURITY_API=http://security-platform:8000
  
  # Security Automation Platform (Sidecar)
  security-platform:
    image: srinivas/security-automation:latest
    ports:
      - "8000:8000"
    environment:
      - LLM_PROVIDER=ollama
      - OLLAMA_MODEL=deepseek-coder:6.7b-instruct
    volumes:
      - ./app-source:/app/target-app:ro
```

### In Your Application
```java
@Component
public class SecurityIntegration {
    
    @Value("${security.api:http://security-platform:8000}")
    private String securityApi;
    
    @Scheduled(cron = "0 0 * * * *")  // Every hour
    public void runSecurityScan() {
        // Trigger scan
        RestTemplate rest = new RestTemplate();
        rest.postForObject(
            securityApi + "/api/v1/scan/trigger",
            new ScanRequest("/app/target-app"),
            ScanResponse.class
        );
    }
    
    @EventListener
    public void onVulnerabilityDetected(VulnerabilityEvent event) {
        // Auto-generate patch
        String patch = rest.postForObject(
            securityApi + "/api/v1/vulnerabilities/" + 
                event.getId() + "/generate-patch",
            null,
            String.class
        );
        
        // Notify team
        slackNotifier.sendAlert("Vulnerability detected: " + event.getType());
    }
}
```

---

## 🚀 Quick Start for Any Java App

### Step 1: Start Security Platform
```bash
docker run -d \
  -p 8000:8000 \
  -e LLM_PROVIDER=ollama \
  -v $(pwd):/app/target \
  srinivas/security-automation:latest
```

### Step 2: Point Your App to Platform
```properties
# application.properties
security.platform.url=http://localhost:8000
security.platform.auto-patch=true
security.platform.notifications.slack=${SLACK_WEBHOOK}
```

### Step 3: Scan Your App
```bash
# Option 1: Use CLI
security-scan --project /path/to/your/app

# Option 2: Use API
curl -X POST http://localhost:8000/api/v1/scan \
  -F "source=@/path/to/your/app" \
  -F "language=java"

# Option 3: Use Maven
cd your-app && mvn security:scan
```

---

## 📊 Dashboard Access

Once integrated, access the dashboard at:
```
http://localhost:8000/dashboard
```

Features:
- View all vulnerabilities
- Generate patches with one click
- Apply patches automatically
- Track vulnerability lifecycle
- Export reports

---

## 🔔 Notification Integration

### Slack
```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK"
```

### Email
```bash
export SMTP_SERVER="smtp.gmail.com"
export SMTP_USER="your-email@gmail.com"
export SMTP_PASSWORD="your-app-password"
```

### GitHub
```bash
export GITHUB_TOKEN="ghp_YourToken"
export GITHUB_REPO="owner/repo"
```

---

## 🎯 Use Cases

### Use Case 1: Development Workflow
```bash
# Developer commits code
git commit -m "Add new feature"

# Pre-push hook runs scan
git push  # Triggers security scan

# Platform generates patches automatically
# Creates PR with fixes

# Developer reviews and merges
```

### Use Case 2: CI/CD Pipeline
```yaml
# .gitlab-ci.yml
security_scan:
  stage: test
  script:
    - docker run srinivas/security-automation-cli scan
    - docker run srinivas/security-automation-cli patch --auto
  artifacts:
    reports:
      security: security-report.json
```

### Use Case 3: Scheduled Scans
```bash
# Crontab entry
0 0 * * * docker run srinivas/security-automation-cli \
  scan --project /path/to/app --notify-slack
```

---

## 🔧 API Endpoints Reference

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/scan` | POST | Upload scan results |
| `/api/v1/vulnerabilities` | GET | List vulnerabilities |
| `/api/v1/vulnerabilities/{id}` | GET | Get vulnerability details |
| `/api/v1/vulnerabilities/{id}/generate-patch` | POST | Generate patch |
| `/api/v1/patches/generate-all` | POST | Generate all patches |
| `/api/v1/patches/download` | GET | Download patches |
| `/api/llm/status` | GET | Check LLM status |
| `/dashboard` | GET | View dashboard |

---

## 📦 Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `SECURITY_PLATFORM_URL` | API endpoint | `http://localhost:8000` |
| `LLM_PROVIDER` | LLM provider | `ollama` |
| `OLLAMA_MODEL` | Ollama model | `deepseek-coder:6.7b-instruct` |
| `AUTO_GENERATE_PATCHES` | Auto-patch on scan | `false` |
| `FAIL_ON_CRITICAL` | Fail build on critical | `true` |
| `SLACK_WEBHOOK_URL` | Slack notifications | - |
| `GITHUB_TOKEN` | GitHub integration | - |

---

## ✅ Compatibility

**Supported Languages:**
- ✅ Java (8, 11, 17, 21)
- ✅ Kotlin
- ✅ Scala
- ✅ Python (via API)
- ✅ JavaScript/TypeScript (via API)
- ✅ Any language (via REST API)

**Supported Build Tools:**
- ✅ Maven
- ✅ Gradle
- ✅ Ant
- ✅ Manual builds

**Supported Scanners:**
- ✅ Semgrep (SARIF/JSON)
- ✅ CodeQL (SARIF/CSV)
- ✅ SpotBugs (XML)
- ✅ FindSecBugs (XML)
- ✅ ZAP (JSON)
- ✅ SonarQube (JSON)
- ✅ Checkmarx (XML)

---

## 🎉 Summary

Your Security Automation Platform is now **fully pluggable**!

**Any Java application can:**
1. Send scan results via REST API
2. Get AI-generated patches back
3. Apply patches automatically
4. Integrate with CI/CD pipelines
5. Use standalone or as sidecar
6. Access via CLI, Maven, Gradle, or API

**Zero coupling** - works with any project structure! 🚀
