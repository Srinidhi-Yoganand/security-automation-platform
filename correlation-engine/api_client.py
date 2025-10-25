"""
Universal API client for integrating Security Automation Platform
with ANY Java application.

This module provides a simple interface for:
1. Uploading scan results
2. Generating patches
3. Retrieving vulnerability information
4. Managing security lifecycle
"""

import requests
import json
from typing import Dict, List, Optional, Any
from pathlib import Path
import subprocess
import tempfile


class SecurityAutomationClient:
    """
    Client for interacting with Security Automation Platform API.
    
    Can be used from ANY Java application to:
    - Upload security scan results
    - Generate AI-powered patches
    - Track vulnerability lifecycle
    - Get security metrics
    """
    
    def __init__(self, base_url: str = "http://localhost:8000", api_key: Optional[str] = None):
        """
        Initialize client.
        
        Args:
            base_url: API endpoint (default: http://localhost:8000)
            api_key: Optional API key for authentication
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        
        if api_key:
            self.session.headers['Authorization'] = f'Bearer {api_key}'
    
    def health_check(self) -> Dict[str, Any]:
        """Check if API is healthy"""
        response = self.session.get(f"{self.base_url}/health")
        response.raise_for_status()
        return response.json()
    
    def llm_status(self) -> Dict[str, Any]:
        """Check LLM provider status"""
        response = self.session.get(f"{self.base_url}/api/llm/status")
        response.raise_for_status()
        return response.json()
    
    # === SCANNING ===
    
    def scan_project(self, project_path: str, tools: List[str] = None) -> Dict[str, Any]:
        """
        Scan a Java project and upload results.
        
        Args:
            project_path: Path to Java project root
            tools: List of scanning tools to use (default: ['semgrep'])
        
        Returns:
            Scan results with vulnerability count
        """
        if tools is None:
            tools = ['semgrep']
        
        results = {}
        
        for tool in tools:
            if tool == 'semgrep':
                sarif = self._run_semgrep(project_path)
                results['semgrep'] = self.upload_sarif(sarif)
        
        return results
    
    def upload_sarif(self, sarif_data: str) -> Dict[str, Any]:
        """
        Upload SARIF format scan results.
        
        Args:
            sarif_data: SARIF JSON string or dict
        
        Returns:
            Upload response with vulnerability IDs
        """
        if isinstance(sarif_data, str):
            sarif_data = json.loads(sarif_data)
        
        response = self.session.post(
            f"{self.base_url}/api/v1/scan",
            json=sarif_data
        )
        response.raise_for_status()
        return response.json()
    
    def upload_scan_file(self, file_path: str, format: str = 'sarif') -> Dict[str, Any]:
        """
        Upload scan results from file.
        
        Args:
            file_path: Path to scan results file
            format: File format (sarif, json, xml)
        
        Returns:
            Upload response
        """
        with open(file_path, 'r') as f:
            data = f.read()
        
        if format == 'sarif':
            return self.upload_sarif(data)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    # === VULNERABILITIES ===
    
    def list_vulnerabilities(self, 
                           severity: Optional[str] = None,
                           state: Optional[str] = None,
                           limit: int = 100) -> List[Dict[str, Any]]:
        """
        List vulnerabilities with optional filters.
        
        Args:
            severity: Filter by severity (critical, high, medium, low)
            state: Filter by state (open, investigating, fixing, fixed)
            limit: Maximum results to return
        
        Returns:
            List of vulnerabilities
        """
        params = {'limit': limit}
        if severity:
            params['severity'] = severity
        if state:
            params['state'] = state
        
        response = self.session.get(
            f"{self.base_url}/api/v1/vulnerabilities",
            params=params
        )
        response.raise_for_status()
        return response.json()
    
    def get_vulnerability(self, vuln_id: int) -> Dict[str, Any]:
        """Get details for specific vulnerability"""
        response = self.session.get(
            f"{self.base_url}/api/v1/vulnerabilities/{vuln_id}"
        )
        response.raise_for_status()
        return response.json()
    
    # === PATCH GENERATION ===
    
    def generate_patch(self, vuln_id: int, auto_apply: bool = False) -> Dict[str, Any]:
        """
        Generate AI-powered patch for vulnerability.
        
        Args:
            vuln_id: Vulnerability ID
            auto_apply: Automatically apply patch (default: False)
        
        Returns:
            Patch data with original and fixed code
        """
        response = self.session.post(
            f"{self.base_url}/api/v1/vulnerabilities/{vuln_id}/generate-patch",
            json={"auto_apply": auto_apply}
        )
        response.raise_for_status()
        return response.json()
    
    def generate_all_patches(self, severity_threshold: str = 'medium') -> Dict[str, Any]:
        """
        Generate patches for all open vulnerabilities above severity threshold.
        
        Args:
            severity_threshold: Minimum severity (critical, high, medium, low)
        
        Returns:
            Batch patch generation results
        """
        response = self.session.post(
            f"{self.base_url}/api/v1/patches/generate-all",
            json={"severity_threshold": severity_threshold}
        )
        response.raise_for_status()
        return response.json()
    
    def apply_patch(self, vuln_id: int, patch_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply a generated patch to source code.
        
        Args:
            vuln_id: Vulnerability ID
            patch_data: Patch data from generate_patch()
        
        Returns:
            Application result
        """
        response = self.session.post(
            f"{self.base_url}/api/v1/vulnerabilities/{vuln_id}/apply-patch",
            json=patch_data
        )
        response.raise_for_status()
        return response.json()
    
    # === METRICS & REPORTING ===
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get overall security metrics"""
        response = self.session.get(f"{self.base_url}/api/v1/metrics/overview")
        response.raise_for_status()
        return response.json()
    
    def get_dashboard_url(self) -> str:
        """Get dashboard URL"""
        return f"{self.base_url}/dashboard"
    
    def export_report(self, format: str = 'json') -> Any:
        """
        Export security report.
        
        Args:
            format: Report format (json, pdf, html)
        
        Returns:
            Report data
        """
        response = self.session.get(
            f"{self.base_url}/api/v1/report",
            params={'format': format}
        )
        response.raise_for_status()
        
        if format == 'json':
            return response.json()
        else:
            return response.content
    
    # === LIFECYCLE MANAGEMENT ===
    
    def update_vulnerability_state(self, vuln_id: int, state: str, notes: str = "") -> Dict[str, Any]:
        """
        Update vulnerability state.
        
        Args:
            vuln_id: Vulnerability ID
            state: New state (open, investigating, fixing, fixed, false_positive)
            notes: Optional notes
        
        Returns:
            Updated vulnerability
        """
        response = self.session.patch(
            f"{self.base_url}/api/v1/vulnerabilities/{vuln_id}",
            json={"state": state, "notes": notes}
        )
        response.raise_for_status()
        return response.json()
    
    def get_vulnerability_history(self, vuln_id: int) -> List[Dict[str, Any]]:
        """Get complete history of vulnerability state changes"""
        response = self.session.get(
            f"{self.base_url}/api/v1/vulnerabilities/{vuln_id}/history"
        )
        response.raise_for_status()
        return response.json()
    
    # === HELPER METHODS ===
    
    def _run_semgrep(self, project_path: str) -> str:
        """Run Semgrep scan on project"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
            output_file = f.name
        
        try:
            subprocess.run(
                ['semgrep', '--config=auto', '--sarif', '--output', output_file, project_path],
                check=True,
                capture_output=True
            )
            
            with open(output_file, 'r') as f:
                return f.read()
        finally:
            Path(output_file).unlink(missing_ok=True)


# === CONVENIENCE FUNCTIONS ===

def scan_and_patch(project_path: str, 
                   api_url: str = "http://localhost:8000",
                   auto_apply: bool = False) -> Dict[str, Any]:
    """
    Convenience function: Scan project and generate patches in one call.
    
    Args:
        project_path: Path to Java project
        api_url: Security platform API URL
        auto_apply: Auto-apply generated patches
    
    Returns:
        Results with vulnerabilities and patches
    """
    client = SecurityAutomationClient(api_url)
    
    # Check health
    health = client.health_check()
    print(f"✅ API Status: {health['status']}")
    
    # Scan project
    print(f"🔍 Scanning project: {project_path}")
    scan_results = client.scan_project(project_path)
    
    # Get vulnerabilities
    vulns = client.list_vulnerabilities(state='open')
    print(f"📊 Found {len(vulns)} vulnerabilities")
    
    # Generate patches
    patches = []
    for vuln in vulns:
        print(f"🤖 Generating patch for: {vuln['type']}")
        patch = client.generate_patch(vuln['id'], auto_apply=auto_apply)
        patches.append(patch)
    
    return {
        'scan_results': scan_results,
        'vulnerabilities': vulns,
        'patches': patches,
        'dashboard_url': client.get_dashboard_url()
    }


def quick_scan(project_path: str) -> str:
    """
    Quick scan returning dashboard URL.
    
    Args:
        project_path: Path to Java project
    
    Returns:
        Dashboard URL to view results
    """
    results = scan_and_patch(project_path, auto_apply=False)
    return results['dashboard_url']


# === JAVA INTEGRATION EXAMPLE ===

"""
Java Example Usage:

import requests;
import com.fasterxml.jackson.databind.ObjectMapper;

public class SecurityIntegration {
    private static final String API_URL = "http://localhost:8000";
    
    public void scanAndPatch() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        
        // 1. Upload scan results
        String sarif = Files.readString(Path.of("semgrep-results.sarif"));
        HttpResponse<String> response = HttpClient.newHttpClient().send(
            HttpRequest.newBuilder()
                .uri(URI.create(API_URL + "/api/v1/scan"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(sarif))
                .build(),
            HttpResponse.BodyHandlers.ofString()
        );
        
        // 2. Get vulnerabilities
        response = HttpClient.newHttpClient().send(
            HttpRequest.newBuilder()
                .uri(URI.create(API_URL + "/api/v1/vulnerabilities"))
                .GET()
                .build(),
            HttpResponse.BodyHandlers.ofString()
        );
        List<Vulnerability> vulns = mapper.readValue(
            response.body(), 
            new TypeReference<List<Vulnerability>>(){}
        );
        
        // 3. Generate patches
        for (Vulnerability vuln : vulns) {
            response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder()
                    .uri(URI.create(API_URL + "/api/v1/vulnerabilities/" + 
                        vuln.getId() + "/generate-patch"))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build(),
                HttpResponse.BodyHandlers.ofString()
            );
            
            Patch patch = mapper.readValue(response.body(), Patch.class);
            System.out.println("Generated patch: " + patch.getExplanation());
        }
    }
}
"""
