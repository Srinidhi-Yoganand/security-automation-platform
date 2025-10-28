"""
DAST (Dynamic Application Security Testing) Scanner
Integrates OWASP ZAP for runtime vulnerability detection
"""
import logging
import time
from typing import Dict, List, Optional
import requests
from zapv2 import ZAPv2

logger = logging.getLogger(__name__)


class DASTScanner:
    """OWASP ZAP Dynamic Scanner for runtime vulnerability detection"""
    
    def __init__(self, zap_host: str = "localhost", zap_port: int = 8090, api_key: Optional[str] = None):
        """
        Initialize DAST Scanner with ZAP proxy
        
        Args:
            zap_host: ZAP proxy host
            zap_port: ZAP proxy port
            api_key: ZAP API key (optional but recommended)
        """
        self.zap_host = zap_host
        self.zap_port = zap_port
        self.api_key = api_key or ""
        self.zap = ZAPv2(proxies={'http': f'http://{zap_host}:{zap_port}', 
                                   'https': f'http://{zap_host}:{zap_port}'})
        
    def wait_for_zap_start(self, timeout: int = 60) -> bool:
        """Wait for ZAP to be ready"""
        logger.info(f"⏳ Waiting for ZAP to start on {self.zap_host}:{self.zap_port}")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                response = requests.get(f"http://{self.zap_host}:{self.zap_port}", timeout=2)
                if response.status_code == 200:
                    logger.info("✅ ZAP is ready!")
                    return True
            except:
                time.sleep(2)
        
        logger.error("❌ ZAP failed to start within timeout")
        return False
    
    def spider_scan(self, target_url: str) -> Dict:
        """
        Perform spider scan to discover URLs
        
        Args:
            target_url: Target application URL
            
        Returns:
            Dict with spider scan results
        """
        logger.info(f"🕷️ Starting spider scan on {target_url}")
        
        try:
            # Start spider scan
            scan_id = self.zap.spider.scan(target_url)
            
            # Wait for spider to complete
            while int(self.zap.spider.status(scan_id)) < 100:
                logger.info(f"Spider progress: {self.zap.spider.status(scan_id)}%")
                time.sleep(2)
            
            # Get discovered URLs
            urls = self.zap.spider.results(scan_id)
            
            logger.info(f"✅ Spider completed! Found {len(urls)} URLs")
            
            return {
                "scan_id": scan_id,
                "urls_found": len(urls),
                "urls": urls[:50]  # Limit to first 50 for summary
            }
            
        except Exception as e:
            logger.error(f"❌ Spider scan failed: {e}")
            return {"error": str(e)}
    
    def active_scan(self, target_url: str, scan_policy: Optional[str] = None) -> Dict:
        """
        Perform active security scan
        
        Args:
            target_url: Target application URL
            scan_policy: Optional custom scan policy
            
        Returns:
            Dict with active scan results
        """
        logger.info(f"🔍 Starting active scan on {target_url}")
        
        try:
            # First, access the URL through ZAP proxy to ensure it's in the sites tree
            logger.info(f"📍 Accessing {target_url} to register with ZAP...")
            try:
                self.zap.urlopen(target_url)
                time.sleep(2)  # Give ZAP time to process
            except Exception as e:
                logger.warning(f"⚠️  Could not access URL directly: {e}")
            
            # Configure scan policy if provided
            if scan_policy:
                self.zap.ascan.set_option_scan_policy(scan_policy)
            
            # Start active scan
            logger.info(f"🚀 Launching active scan...")
            scan_id = self.zap.ascan.scan(target_url)
            
            # Check if scan_id is valid
            if not scan_id or scan_id == 'does_not_exist':
                logger.error(f"❌ Invalid scan ID: {scan_id}")
                return {"error": f"Failed to start scan - invalid scan ID: {scan_id}"}
            
            logger.info(f"✅ Active scan started with ID: {scan_id}")
            
            # Wait for scan to complete
            max_wait = 300  # 5 minutes max
            start_time = time.time()
            while time.time() - start_time < max_wait:
                try:
                    status = self.zap.ascan.status(scan_id)
                    progress = int(status) if status.isdigit() else 0
                    
                    if progress >= 100:
                        logger.info("✅ Active scan completed!")
                        break
                        
                    logger.info(f"Active scan progress: {progress}%")
                    time.sleep(5)
                except Exception as e:
                    logger.warning(f"⚠️  Error checking scan status: {e}")
                    break
            
            return {
                "scan_id": scan_id,
                "status": "completed"
            }
            
        except Exception as e:
            logger.error(f"❌ Active scan failed: {e}")
            return {"error": str(e)}
    
    def get_alerts(self, base_url: Optional[str] = None) -> List[Dict]:
        """
        Get all security alerts found by ZAP
        
        Args:
            base_url: Optional filter by base URL
            
        Returns:
            List of vulnerability findings
        """
        logger.info("📄 Retrieving ZAP alerts...")
        
        try:
            alerts = self.zap.core.alerts(baseurl=base_url) if base_url else self.zap.core.alerts()
            
            # Transform to standardized format
            findings = []
            for alert in alerts:
                finding = {
                    "tool": "ZAP",
                    "rule_id": alert.get('pluginId', ''),
                    "severity": self._map_severity(alert.get('risk', 'Low')),
                    "title": alert.get('alert', ''),
                    "description": alert.get('description', ''),
                    "file_path": alert.get('url', ''),
                    "line_number": 0,  # DAST doesn't have line numbers
                    "message": alert.get('solution', ''),
                    "cwe_id": alert.get('cweid', ''),
                    "confidence": alert.get('confidence', 'Medium'),
                    "attack": alert.get('attack', ''),
                    "evidence": alert.get('evidence', ''),
                    "references": alert.get('reference', ''),
                    "metadata": {
                        "method": alert.get('method', 'GET'),
                        "param": alert.get('param', ''),
                        "solution": alert.get('solution', ''),
                        "other_info": alert.get('other', '')
                    }
                }
                findings.append(finding)
            
            logger.info(f"✅ Found {len(findings)} DAST alerts")
            return findings
            
        except Exception as e:
            logger.error(f"❌ Failed to get alerts: {e}")
            return []
    
    def full_scan(self, target_url: str) -> Dict:
        """
        Perform complete DAST scan: spider + active scan
        
        Args:
            target_url: Target application URL
            
        Returns:
            Dict with complete scan results
        """
        logger.info(f"🚀 Starting full DAST scan on {target_url}")
        
        # Wait for ZAP to be ready
        if not self.wait_for_zap_start():
            return {"error": "ZAP not available"}
        
        # Step 1: Spider scan
        spider_results = self.spider_scan(target_url)
        if "error" in spider_results:
            return spider_results
        
        # Step 2: Active scan
        active_results = self.active_scan(target_url)
        if "error" in active_results:
            return active_results
        
        # Step 3: Get all findings
        findings = self.get_alerts(target_url)
        
        # Generate summary
        summary = self._generate_summary(findings)
        
        return {
            "target_url": target_url,
            "spider_results": spider_results,
            "active_scan_results": active_results,
            "findings": findings,
            "summary": summary,
            "total_findings": len(findings)
        }
    
    def _map_severity(self, risk: str) -> str:
        """Map ZAP risk levels to standard severity"""
        mapping = {
            "High": "error",
            "Medium": "warning",
            "Low": "note",
            "Informational": "note"
        }
        return mapping.get(risk, "note")
    
    def _generate_summary(self, findings: List[Dict]) -> Dict:
        """Generate summary statistics"""
        summary = {
            "total": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "by_type": {}
        }
        
        for finding in findings:
            severity = finding.get('severity', 'note')
            if severity == 'error':
                if finding.get('metadata', {}).get('risk') == 'High':
                    summary['high'] += 1
                else:
                    summary['medium'] += 1
            elif severity == 'warning':
                summary['medium'] += 1
            else:
                summary['low'] += 1
            
            # Count by vulnerability type
            title = finding.get('title', 'Unknown')
            summary['by_type'][title] = summary['by_type'].get(title, 0) + 1
        
        return summary
    
    def shutdown_zap(self):
        """Shutdown ZAP daemon"""
        try:
            self.zap.core.shutdown()
            logger.info("✅ ZAP shut down successfully")
        except Exception as e:
            logger.warning(f"⚠️ Failed to shutdown ZAP: {e}")


# Quick test function
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    scanner = DASTScanner()
    results = scanner.full_scan("http://testphp.vulnweb.com")
    
    print(f"\n📊 Scan Results:")
    print(f"Total findings: {results.get('total_findings', 0)}")
    print(f"Summary: {results.get('summary', {})}")
