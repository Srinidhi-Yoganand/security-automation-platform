"""
IAST (Interactive Application Security Testing) Scanner

Combines SAST and DAST by instrumenting applications to monitor runtime behavior.
Provides precise vulnerability detection with low false positive rates.

Supports:
- Contrast Security Community Edition
- OpenRASP (Runtime Application Self-Protection)
- Custom Java instrumentation
"""
import logging
import subprocess
import time
from typing import Dict, List, Optional
from pathlib import Path
import requests

logger = logging.getLogger(__name__)


class IASTScanner:
    """
    Interactive Application Security Testing scanner
    
    Instruments applications to detect vulnerabilities during execution.
    Tracks dataflow and control flow at runtime for precise detection.
    """
    
    def __init__(self, agent_type: str = "contrast", agent_path: Optional[str] = None):
        """
        Initialize IAST Scanner
        
        Args:
            agent_type: Type of IAST agent ('contrast', 'openrasp', 'custom')
            agent_path: Path to IAST agent JAR file
        """
        self.agent_type = agent_type
        self.agent_path = agent_path or self._get_default_agent_path()
        self.monitored_apps = {}
        
    def _get_default_agent_path(self) -> str:
        """Get default agent path based on type"""
        paths = {
            "contrast": "/opt/contrast/contrast-agent.jar",
            "openrasp": "/opt/openrasp/rasp.jar",
            "custom": "/opt/iast/agent.jar"
        }
        return paths.get(self.agent_type, paths["contrast"])
    
    def instrument_application(
        self,
        app_path: str,
        app_name: str,
        port: int = 8080
    ) -> Dict:
        """
        Instrument Java application with IAST agent
        
        Args:
            app_path: Path to application JAR or WAR
            app_name: Application name for tracking
            port: Port to run application on
            
        Returns:
            Dict with instrumentation status and app info
        """
        logger.info(f"🔧 Instrumenting application: {app_name}")
        
        if not Path(app_path).exists():
            return {
                "success": False,
                "error": f"Application not found: {app_path}"
            }
        
        # Build instrumentation command
        java_opts = self._build_java_opts()
        
        cmd = [
            "java",
            java_opts,
            "-jar", app_path,
            f"--server.port={port}"
        ]
        
        try:
            # Start instrumented application
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for application to start
            time.sleep(10)
            
            # Verify application is running
            if not self._is_app_running(port):
                return {
                    "success": False,
                    "error": "Application failed to start"
                }
            
            # Store process info
            self.monitored_apps[app_name] = {
                "process": process,
                "port": port,
                "app_path": app_path
            }
            
            logger.info(f"✅ Application instrumented successfully: {app_name}")
            
            return {
                "success": True,
                "app_name": app_name,
                "port": port,
                "message": "Application instrumented and running",
                "agent_type": self.agent_type
            }
            
        except Exception as e:
            logger.error(f"❌ Instrumentation failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _build_java_opts(self) -> str:
        """Build Java options for IAST agent"""
        
        if self.agent_type == "contrast":
            return f"-javaagent:{self.agent_path}"
        elif self.agent_type == "openrasp":
            return f"-javaagent:{self.agent_path} -Drasp.config=/etc/openrasp/rasp.yml"
        else:
            # Custom lightweight agent
            return f"-javaagent:{self.agent_path}"
    
    def _is_app_running(self, port: int) -> bool:
        """Check if application is running"""
        try:
            response = requests.get(f"http://localhost:{port}/actuator/health", timeout=5)
            return response.status_code == 200
        except:
            try:
                response = requests.get(f"http://localhost:{port}", timeout=5)
                return response.status_code < 500
            except:
                return False
    
    def run_functional_tests(
        self,
        app_name: str,
        test_scenarios: List[Dict]
    ) -> Dict:
        """
        Run functional tests to trigger IAST detection
        
        Args:
            app_name: Monitored application name
            test_scenarios: List of test scenarios to execute
            
        Returns:
            Test execution results
        """
        logger.info(f"🧪 Running functional tests on {app_name}")
        
        if app_name not in self.monitored_apps:
            return {
                "success": False,
                "error": f"Application not monitored: {app_name}"
            }
        
        app_info = self.monitored_apps[app_name]
        base_url = f"http://localhost:{app_info['port']}"
        
        results = []
        
        for scenario in test_scenarios:
            try:
                # Execute test scenario
                method = scenario.get("method", "GET")
                endpoint = scenario.get("endpoint", "/")
                params = scenario.get("params", {})
                data = scenario.get("data", {})
                
                url = f"{base_url}{endpoint}"
                
                if method == "GET":
                    response = requests.get(url, params=params, timeout=10)
                elif method == "POST":
                    response = requests.post(url, data=data, timeout=10)
                elif method == "PUT":
                    response = requests.put(url, data=data, timeout=10)
                else:
                    response = requests.request(method, url, timeout=10)
                
                results.append({
                    "scenario": scenario.get("name", "Unknown"),
                    "status": response.status_code,
                    "success": response.status_code < 400
                })
                
            except Exception as e:
                logger.warning(f"Test scenario failed: {e}")
                results.append({
                    "scenario": scenario.get("name", "Unknown"),
                    "success": False,
                    "error": str(e)
                })
        
        logger.info(f"✅ Completed {len(results)} test scenarios")
        
        return {
            "success": True,
            "total_scenarios": len(test_scenarios),
            "executed": len(results),
            "results": results
        }
    
    def get_findings(self, app_name: str) -> List[Dict]:
        """
        Retrieve IAST findings for application
        
        Returns vulnerabilities detected during runtime monitoring
        """
        logger.info(f"📄 Retrieving IAST findings for {app_name}")
        
        if self.agent_type == "contrast":
            return self._get_contrast_findings(app_name)
        elif self.agent_type == "openrasp":
            return self._get_openrasp_findings(app_name)
        else:
            return self._get_custom_findings(app_name)
    
    def _get_contrast_findings(self, app_name: str) -> List[Dict]:
        """Get findings from Contrast Security"""
        
        # Contrast API endpoint (if using Contrast Community)
        api_url = "http://localhost:19080/api/ng/traces"
        
        try:
            response = requests.get(
                api_url,
                headers={"Authorization": "Bearer YOUR_API_KEY"},
                timeout=10
            )
            
            if response.status_code == 200:
                traces = response.json().get("traces", [])
                
                findings = []
                for trace in traces:
                    finding = {
                        "tool": "IAST-Contrast",
                        "rule_id": trace.get("rule_id", ""),
                        "severity": self._map_severity(trace.get("severity", "medium")),
                        "title": trace.get("title", ""),
                        "description": trace.get("description", ""),
                        "file_path": trace.get("file", ""),
                        "line_number": trace.get("line", 0),
                        "method_name": trace.get("method", ""),
                        "confidence": "high",  # IAST has high confidence
                        "execution_path": trace.get("execution_path", []),
                        "http_request": trace.get("http_request", {}),
                        "metadata": {
                            "trace_id": trace.get("trace_id"),
                            "app_name": app_name,
                            "detection_time": trace.get("timestamp")
                        }
                    }
                    findings.append(finding)
                
                logger.info(f"✅ Retrieved {len(findings)} IAST findings")
                return findings
            else:
                logger.warning("No findings from Contrast API")
                return []
                
        except Exception as e:
            logger.error(f"Failed to get Contrast findings: {e}")
            return []
    
    def _get_openrasp_findings(self, app_name: str) -> List[Dict]:
        """Get findings from OpenRASP"""
        
        # OpenRASP logs location
        log_file = "/var/log/openrasp/attack.log"
        
        findings = []
        
        try:
            if Path(log_file).exists():
                with open(log_file, 'r') as f:
                    for line in f:
                        if app_name in line:
                            # Parse OpenRASP log format
                            # Simplified - implement actual parsing
                            finding = {
                                "tool": "IAST-OpenRASP",
                                "severity": "warning",
                                "title": "Runtime Security Event",
                                "description": line.strip(),
                                "confidence": "high"
                            }
                            findings.append(finding)
                
                logger.info(f"✅ Retrieved {len(findings)} OpenRASP findings")
        except Exception as e:
            logger.error(f"Failed to read OpenRASP logs: {e}")
        
        return findings
    
    def _get_custom_findings(self, app_name: str) -> List[Dict]:
        """Get findings from custom IAST implementation"""
        
        # Custom IAST stores findings in memory or file
        findings_file = f"/tmp/iast-{app_name}-findings.json"
        
        try:
            if Path(findings_file).exists():
                import json
                with open(findings_file, 'r') as f:
                    findings = json.load(f)
                
                logger.info(f"✅ Retrieved {len(findings)} custom IAST findings")
                return findings
        except Exception as e:
            logger.error(f"Failed to read custom findings: {e}")
        
        return []
    
    def _map_severity(self, severity: str) -> str:
        """Map IAST severity to standard levels"""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "note": "note"
        }
        return mapping.get(severity.lower(), "warning")
    
    def stop_monitoring(self, app_name: str):
        """Stop monitoring application"""
        
        if app_name in self.monitored_apps:
            app_info = self.monitored_apps[app_name]
            process = app_info["process"]
            
            try:
                process.terminate()
                process.wait(timeout=10)
                logger.info(f"✅ Stopped monitoring: {app_name}")
            except:
                process.kill()
                logger.warning(f"⚠️  Force killed: {app_name}")
            
            del self.monitored_apps[app_name]
    
    def generate_test_scenarios(self, vulnerability_types: List[str]) -> List[Dict]:
        """
        Generate test scenarios to trigger specific vulnerabilities
        
        Used to verify IAST can detect known vulnerability types
        """
        scenarios = []
        
        if "sql_injection" in vulnerability_types:
            scenarios.extend([
                {
                    "name": "SQL Injection - Authentication Bypass",
                    "method": "POST",
                    "endpoint": "/login",
                    "data": {"username": "admin' OR '1'='1' --", "password": "anything"}
                },
                {
                    "name": "SQL Injection - UNION Attack",
                    "method": "GET",
                    "endpoint": "/user",
                    "params": {"id": "1' UNION SELECT username, password FROM users--"}
                }
            ])
        
        if "xss" in vulnerability_types:
            scenarios.append({
                "name": "XSS - Reflected",
                "method": "GET",
                "endpoint": "/search",
                "params": {"q": "<script>alert('XSS')</script>"}
            })
        
        if "idor" in vulnerability_types:
            scenarios.extend([
                {
                    "name": "IDOR - Access Other User",
                    "method": "GET",
                    "endpoint": "/api/user/profile",
                    "params": {"user_id": "999"}
                },
                {
                    "name": "IDOR - Enumerate Resources",
                    "method": "GET",
                    "endpoint": "/api/document",
                    "params": {"id": "456"}
                }
            ])
        
        return scenarios


# Quick test
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    scanner = IASTScanner(agent_type="contrast")
    
    # Example: Instrument application
    result = scanner.instrument_application(
        app_path="/path/to/app.jar",
        app_name="vulnerable-app",
        port=8080
    )
    
    print(f"\n📊 Instrumentation Result:")
    print(f"Success: {result.get('success')}")
    print(f"Message: {result.get('message', result.get('error'))}")
