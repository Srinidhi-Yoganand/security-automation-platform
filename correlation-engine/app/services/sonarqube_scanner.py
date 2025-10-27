"""
SonarQube Scanner Integration

Integrates SonarQube for code quality and security analysis.
Provides multi-SAST ensemble voting with CodeQL.
"""
import logging
import subprocess
import time
from typing import Dict, List, Optional
from pathlib import Path
import requests

logger = logging.getLogger(__name__)


class SonarQubeScanner:
    """
    SonarQube integration for SAST analysis and code quality
    """
    
    def __init__(self, sonar_host: str = "http://localhost:9000", sonar_token: Optional[str] = None):
        """
        Initialize SonarQube Scanner
        
        Args:
            sonar_host: SonarQube server URL
            sonar_token: Authentication token
        """
        self.sonar_host = sonar_host
        self.sonar_token = sonar_token or "squ_default_token"
        self.scanner_path = "/opt/sonar-scanner/bin/sonar-scanner"
        
    def wait_for_sonar_ready(self, timeout: int = 60) -> bool:
        """Wait for SonarQube to be ready"""
        logger.info(f"⏳ Waiting for SonarQube at {self.sonar_host}")
        
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                response = requests.get(f"{self.sonar_host}/api/system/status", timeout=5)
                if response.status_code == 200:
                    status = response.json().get("status")
                    if status == "UP":
                        logger.info("✅ SonarQube is ready!")
                        return True
            except:
                pass
            
            time.sleep(3)
        
        logger.error("❌ SonarQube not ready within timeout")
        return False
    
    def scan_project(
        self,
        project_path: str,
        project_key: str,
        project_name: Optional[str] = None,
        language: str = "java"
    ) -> Dict:
        """
        Scan project with SonarQube
        
        Args:
            project_path: Path to source code
            project_key: Unique project identifier
            project_name: Display name
            language: Programming language
            
        Returns:
            Scan results
        """
        logger.info(f"🔍 Scanning project with SonarQube: {project_key}")
        
        if not Path(project_path).exists():
            return {
                "success": False,
                "error": f"Project path not found: {project_path}"
            }
        
        # Wait for SonarQube to be ready
        if not self.wait_for_sonar_ready():
            return {
                "success": False,
                "error": "SonarQube not available"
            }
        
        project_name = project_name or project_key
        
        # Build scanner command
        cmd = [
            self.scanner_path,
            f"-Dsonar.projectKey={project_key}",
            f"-Dsonar.projectName={project_name}",
            f"-Dsonar.sources={project_path}",
            f"-Dsonar.host.url={self.sonar_host}",
            f"-Dsonar.login={self.sonar_token}",
            f"-Dsonar.language={language}",
            "-Dsonar.sourceEncoding=UTF-8"
        ]
        
        try:
            # Run scanner
            result = subprocess.run(
                cmd,
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if result.returncode == 0:
                logger.info("✅ SonarQube scan completed successfully")
                
                # Wait for analysis to complete
                time.sleep(5)
                
                # Get findings
                findings = self.get_findings(project_key)
                
                return {
                    "success": True,
                    "project_key": project_key,
                    "findings_count": len(findings),
                    "findings": findings
                }
            else:
                logger.error(f"❌ Scan failed: {result.stderr}")
                return {
                    "success": False,
                    "error": result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Scan timeout (>10 minutes)"
            }
        except Exception as e:
            logger.error(f"❌ Scan failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_findings(self, project_key: str) -> List[Dict]:
        """
        Get security findings from SonarQube
        
        Returns list of vulnerabilities and security hotspots
        """
        logger.info(f"📄 Retrieving SonarQube findings for {project_key}")
        
        findings = []
        
        # Get issues (vulnerabilities, bugs, code smells)
        issues = self._get_issues(project_key)
        findings.extend(issues)
        
        # Get security hotspots
        hotspots = self._get_hotspots(project_key)
        findings.extend(hotspots)
        
        logger.info(f"✅ Retrieved {len(findings)} SonarQube findings")
        
        return findings
    
    def _get_issues(self, project_key: str) -> List[Dict]:
        """Get issues from SonarQube"""
        
        url = f"{self.sonar_host}/api/issues/search"
        params = {
            "componentKeys": project_key,
            "types": "VULNERABILITY,SECURITY_HOTSPOT",
            "ps": 500  # Page size
        }
        
        try:
            response = requests.get(
                url,
                params=params,
                auth=(self.sonar_token, ""),
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                issues = data.get("issues", [])
                
                findings = []
                for issue in issues:
                    finding = {
                        "tool": "SonarQube",
                        "rule_id": issue.get("rule", ""),
                        "severity": self._map_severity(issue.get("severity", "MAJOR")),
                        "title": issue.get("message", ""),
                        "description": self._get_rule_description(issue.get("rule", "")),
                        "file_path": issue.get("component", "").split(":")[-1],
                        "line_number": issue.get("line", 0),
                        "message": issue.get("message", ""),
                        "confidence": self._map_confidence(issue.get("severity", "MAJOR")),
                        "type": issue.get("type", ""),
                        "metadata": {
                            "issue_key": issue.get("key"),
                            "creation_date": issue.get("creationDate"),
                            "tags": issue.get("tags", [])
                        }
                    }
                    findings.append(finding)
                
                return findings
            else:
                logger.warning(f"Failed to get issues: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to retrieve issues: {e}")
            return []
    
    def _get_hotspots(self, project_key: str) -> List[Dict]:
        """Get security hotspots"""
        
        url = f"{self.sonar_host}/api/hotspots/search"
        params = {
            "projectKey": project_key,
            "ps": 500
        }
        
        try:
            response = requests.get(
                url,
                params=params,
                auth=(self.sonar_token, ""),
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                hotspots = data.get("hotspots", [])
                
                findings = []
                for hotspot in hotspots:
                    finding = {
                        "tool": "SonarQube-Hotspot",
                        "rule_id": hotspot.get("ruleKey", ""),
                        "severity": "warning",
                        "title": hotspot.get("message", ""),
                        "description": "Security hotspot requiring review",
                        "file_path": hotspot.get("component", "").split(":")[-1],
                        "line_number": hotspot.get("line", 0),
                        "message": hotspot.get("message", ""),
                        "confidence": "medium",
                        "type": "SECURITY_HOTSPOT",
                        "metadata": {
                            "hotspot_key": hotspot.get("key"),
                            "status": hotspot.get("status"),
                            "category": hotspot.get("securityCategory")
                        }
                    }
                    findings.append(finding)
                
                return findings
            else:
                return []
                
        except Exception as e:
            logger.error(f"Failed to retrieve hotspots: {e}")
            return []
    
    def _get_rule_description(self, rule_key: str) -> str:
        """Get rule description from SonarQube"""
        
        url = f"{self.sonar_host}/api/rules/show"
        params = {"key": rule_key}
        
        try:
            response = requests.get(
                url,
                params=params,
                auth=(self.sonar_token, ""),
                timeout=10
            )
            
            if response.status_code == 200:
                rule = response.json().get("rule", {})
                return rule.get("htmlDesc", rule.get("mdDesc", "No description"))
            else:
                return "No description available"
                
        except:
            return "No description available"
    
    def _map_severity(self, sonar_severity: str) -> str:
        """Map SonarQube severity to standard levels"""
        mapping = {
            "BLOCKER": "error",
            "CRITICAL": "error",
            "MAJOR": "warning",
            "MINOR": "note",
            "INFO": "note"
        }
        return mapping.get(sonar_severity, "warning")
    
    def _map_confidence(self, severity: str) -> str:
        """Map severity to confidence level"""
        mapping = {
            "BLOCKER": "high",
            "CRITICAL": "high",
            "MAJOR": "medium",
            "MINOR": "low",
            "INFO": "low"
        }
        return mapping.get(severity, "medium")
    
    def get_quality_gate_status(self, project_key: str) -> Dict:
        """Get quality gate status for project"""
        
        url = f"{self.sonar_host}/api/qualitygates/project_status"
        params = {"projectKey": project_key}
        
        try:
            response = requests.get(
                url,
                params=params,
                auth=(self.sonar_token, ""),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                project_status = data.get("projectStatus", {})
                
                return {
                    "status": project_status.get("status"),
                    "conditions": project_status.get("conditions", []),
                    "passed": project_status.get("status") == "OK"
                }
            else:
                return {"status": "UNKNOWN", "passed": False}
                
        except Exception as e:
            logger.error(f"Failed to get quality gate: {e}")
            return {"status": "ERROR", "passed": False, "error": str(e)}
    
    def get_metrics(self, project_key: str) -> Dict:
        """Get project metrics"""
        
        url = f"{self.sonar_host}/api/measures/component"
        params = {
            "component": project_key,
            "metricKeys": "vulnerabilities,security_hotspots,bugs,code_smells,coverage,duplicated_lines_density"
        }
        
        try:
            response = requests.get(
                url,
                params=params,
                auth=(self.sonar_token, ""),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                component = data.get("component", {})
                measures = component.get("measures", [])
                
                metrics = {}
                for measure in measures:
                    metrics[measure["metric"]] = measure.get("value", "0")
                
                return {
                    "success": True,
                    "metrics": metrics
                }
            else:
                return {"success": False, "metrics": {}}
                
        except Exception as e:
            logger.error(f"Failed to get metrics: {e}")
            return {"success": False, "error": str(e), "metrics": {}}


# Quick test
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    scanner = SonarQubeScanner()
    
    # Test connection
    if scanner.wait_for_sonar_ready():
        print("✅ SonarQube is ready")
    else:
        print("❌ SonarQube not available")
