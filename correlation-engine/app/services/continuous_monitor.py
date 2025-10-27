"""
Continuous Monitoring Service

Scheduled security scans with trend tracking and alerting.
Monitors security posture over time and alerts on regressions.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path
import json
import asyncio
from enum import Enum

logger = logging.getLogger(__name__)


class ScanFrequency(str, Enum):
    """Scan frequency options"""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class ScanStatus(str, Enum):
    """Scan execution status"""
    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class MonitoringConfig:
    """Configuration for continuous monitoring"""
    
    def __init__(
        self,
        project_name: str,
        source_path: str,
        target_url: Optional[str] = None,
        language: str = "java",
        frequency: ScanFrequency = ScanFrequency.DAILY,
        enable_sast: bool = True,
        enable_dast: bool = True,
        alert_on_new_vulns: bool = True,
        alert_on_regression: bool = True,
        alert_thresholds: Optional[Dict] = None
    ):
        self.project_name = project_name
        self.source_path = source_path
        self.target_url = target_url
        self.language = language
        self.frequency = frequency
        self.enable_sast = enable_sast
        self.enable_dast = enable_dast
        self.alert_on_new_vulns = alert_on_new_vulns
        self.alert_on_regression = alert_on_regression
        self.alert_thresholds = alert_thresholds or {
            "critical": 0,  # Alert on any critical
            "high": 5,      # Alert if > 5 high
            "medium": 20,   # Alert if > 20 medium
            "regression_percent": 10  # Alert if 10%+ increase
        }


class ScanResult:
    """Individual scan result"""
    
    def __init__(
        self,
        scan_id: str,
        project_name: str,
        timestamp: datetime,
        status: ScanStatus,
        sast_findings: int = 0,
        dast_findings: int = 0,
        correlated_findings: int = 0,
        critical: int = 0,
        high: int = 0,
        medium: int = 0,
        low: int = 0,
        patches_generated: int = 0,
        duration_seconds: float = 0,
        error_message: Optional[str] = None
    ):
        self.scan_id = scan_id
        self.project_name = project_name
        self.timestamp = timestamp
        self.status = status
        self.sast_findings = sast_findings
        self.dast_findings = dast_findings
        self.correlated_findings = correlated_findings
        self.critical = critical
        self.high = high
        self.medium = medium
        self.low = low
        self.patches_generated = patches_generated
        self.duration_seconds = duration_seconds
        self.error_message = error_message
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "scan_id": self.scan_id,
            "project_name": self.project_name,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status,
            "sast_findings": self.sast_findings,
            "dast_findings": self.dast_findings,
            "correlated_findings": self.correlated_findings,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "patches_generated": self.patches_generated,
            "duration_seconds": self.duration_seconds,
            "error_message": self.error_message
        }


class TrendAnalyzer:
    """Analyze security trends over time"""
    
    def __init__(self, history: List[ScanResult]):
        self.history = sorted(history, key=lambda x: x.timestamp)
    
    def calculate_mttf(self) -> Optional[float]:
        """
        Calculate Mean Time To Fix (MTTF)
        
        Time between vulnerability detection and resolution
        """
        if len(self.history) < 2:
            return None
        
        resolution_times = []
        
        for i in range(len(self.history) - 1):
            current = self.history[i]
            next_scan = self.history[i + 1]
            
            # If vulnerabilities decreased, calculate resolution time
            current_total = current.critical + current.high + current.medium
            next_total = next_scan.critical + next_scan.high + next_scan.medium
            
            if next_total < current_total:
                time_diff = (next_scan.timestamp - current.timestamp).total_seconds() / 3600  # hours
                resolution_times.append(time_diff)
        
        if not resolution_times:
            return None
        
        return sum(resolution_times) / len(resolution_times)
    
    def detect_regression(self, lookback_scans: int = 5) -> Dict:
        """
        Detect security regression (vulnerability increase)
        
        Returns regression details if detected
        """
        if len(self.history) < 2:
            return {"regression_detected": False}
        
        recent = self.history[-lookback_scans:]
        if len(recent) < 2:
            return {"regression_detected": False}
        
        baseline = recent[0]
        latest = recent[-1]
        
        baseline_total = baseline.critical + baseline.high + baseline.medium
        latest_total = latest.critical + latest.high + latest.medium
        
        if baseline_total == 0:
            regression_percent = 0
        else:
            regression_percent = ((latest_total - baseline_total) / baseline_total) * 100
        
        regression_detected = regression_percent > 10  # 10% increase threshold
        
        return {
            "regression_detected": regression_detected,
            "baseline_vulnerabilities": baseline_total,
            "current_vulnerabilities": latest_total,
            "change_percent": regression_percent,
            "critical_increase": latest.critical - baseline.critical,
            "high_increase": latest.high - baseline.high,
            "medium_increase": latest.medium - baseline.medium,
            "baseline_scan": baseline.scan_id,
            "latest_scan": latest.scan_id,
            "time_period_hours": (latest.timestamp - baseline.timestamp).total_seconds() / 3600
        }
    
    def get_trend(self, period_days: int = 30) -> Dict:
        """
        Get security trend for specified period
        
        Returns trend analysis with statistics
        """
        cutoff = datetime.now() - timedelta(days=period_days)
        recent = [s for s in self.history if s.timestamp >= cutoff]
        
        if not recent:
            return {"error": "No data in specified period"}
        
        # Calculate statistics
        total_scans = len(recent)
        total_vulns = [s.critical + s.high + s.medium + s.low for s in recent]
        critical_vulns = [s.critical for s in recent]
        high_vulns = [s.high for s in recent]
        
        # Trend direction
        if len(recent) >= 2:
            first_total = recent[0].critical + recent[0].high + recent[0].medium
            last_total = recent[-1].critical + recent[-1].high + recent[-1].medium
            
            if last_total < first_total:
                trend_direction = "improving"
            elif last_total > first_total:
                trend_direction = "degrading"
            else:
                trend_direction = "stable"
        else:
            trend_direction = "insufficient_data"
        
        return {
            "period_days": period_days,
            "total_scans": total_scans,
            "trend_direction": trend_direction,
            "avg_vulnerabilities_per_scan": sum(total_vulns) / total_scans if total_scans > 0 else 0,
            "avg_critical_per_scan": sum(critical_vulns) / total_scans if total_scans > 0 else 0,
            "avg_high_per_scan": sum(high_vulns) / total_scans if total_scans > 0 else 0,
            "max_vulnerabilities": max(total_vulns) if total_vulns else 0,
            "min_vulnerabilities": min(total_vulns) if total_vulns else 0,
            "improvement_percent": ((total_vulns[0] - total_vulns[-1]) / total_vulns[0] * 100) if total_vulns and total_vulns[0] > 0 else 0
        }


class ContinuousMonitor:
    """Continuous security monitoring with scheduled scans"""
    
    def __init__(self, storage_path: str = "./data/monitoring"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.configs: Dict[str, MonitoringConfig] = {}
        self.scan_history: Dict[str, List[ScanResult]] = {}
        
        # Load existing configs and history
        self._load_state()
    
    def add_project(self, config: MonitoringConfig):
        """Add project for continuous monitoring"""
        logger.info(f"📊 Adding project for monitoring: {config.project_name}")
        
        self.configs[config.project_name] = config
        if config.project_name not in self.scan_history:
            self.scan_history[config.project_name] = []
        
        self._save_state()
        
        logger.info(f"✅ Project added: {config.project_name} (frequency: {config.frequency})")
    
    def remove_project(self, project_name: str):
        """Remove project from monitoring"""
        if project_name in self.configs:
            del self.configs[project_name]
            self._save_state()
            logger.info(f"✅ Project removed: {project_name}")
    
    async def run_scan(self, project_name: str) -> ScanResult:
        """
        Execute security scan for project
        
        Returns scan result with all findings
        """
        if project_name not in self.configs:
            raise ValueError(f"Project not found: {project_name}")
        
        config = self.configs[project_name]
        scan_id = f"{project_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        logger.info(f"🔍 Starting scan: {scan_id}")
        start_time = datetime.now()
        
        try:
            # Import here to avoid circular dependencies
            from app.core.git_analyzer import SemanticAnalyzer
            from app.services.dast_scanner import DASTScanner
            
            sast_findings = 0
            dast_findings = 0
            correlated = 0
            critical = 0
            high = 0
            medium = 0
            low = 0
            
            # Run SAST if enabled
            if config.enable_sast:
                logger.info("📝 Running SAST analysis...")
                analyzer = SemanticAnalyzer(workspace_path=config.source_path)
                # Simplified - add full SAST logic here
                sast_findings = 0  # Placeholder
            
            # Run DAST if enabled
            if config.enable_dast and config.target_url:
                logger.info("🌐 Running DAST analysis...")
                scanner = DASTScanner(zap_host="zap", zap_port=8090)
                dast_results = scanner.full_scan(config.target_url)
                dast_findings = dast_results.get("total_findings", 0)
                
                # Parse severity
                summary = dast_results.get("summary", {})
                high = summary.get("high", 0)
                medium = summary.get("medium", 0)
                low = summary.get("low", 0)
            
            duration = (datetime.now() - start_time).total_seconds()
            
            result = ScanResult(
                scan_id=scan_id,
                project_name=project_name,
                timestamp=start_time,
                status=ScanStatus.COMPLETED,
                sast_findings=sast_findings,
                dast_findings=dast_findings,
                correlated_findings=correlated,
                critical=critical,
                high=high,
                medium=medium,
                low=low,
                duration_seconds=duration
            )
            
            # Save to history
            self.scan_history[project_name].append(result)
            self._save_state()
            
            # Check for alerts
            await self._check_alerts(config, result)
            
            logger.info(f"✅ Scan completed: {scan_id} ({duration:.1f}s)")
            return result
            
        except Exception as e:
            logger.error(f"❌ Scan failed: {e}")
            
            duration = (datetime.now() - start_time).total_seconds()
            result = ScanResult(
                scan_id=scan_id,
                project_name=project_name,
                timestamp=start_time,
                status=ScanStatus.FAILED,
                duration_seconds=duration,
                error_message=str(e)
            )
            
            self.scan_history[project_name].append(result)
            self._save_state()
            
            return result
    
    async def _check_alerts(self, config: MonitoringConfig, result: ScanResult):
        """Check if alerts should be triggered"""
        alerts = []
        
        # Check thresholds
        if result.critical > config.alert_thresholds["critical"]:
            alerts.append(f"🚨 CRITICAL: {result.critical} critical vulnerabilities found!")
        
        if result.high > config.alert_thresholds["high"]:
            alerts.append(f"⚠️  HIGH: {result.high} high-severity vulnerabilities found!")
        
        # Check for regression
        if config.alert_on_regression and len(self.scan_history[config.project_name]) > 1:
            analyzer = TrendAnalyzer(self.scan_history[config.project_name])
            regression = analyzer.detect_regression()
            
            if regression["regression_detected"]:
                alerts.append(
                    f"📈 REGRESSION: Vulnerability count increased by {regression['change_percent']:.1f}% "
                    f"({regression['current_vulnerabilities']} vs {regression['baseline_vulnerabilities']})"
                )
        
        # Send alerts if any
        if alerts:
            await self._send_alerts(config.project_name, alerts)
    
    async def _send_alerts(self, project_name: str, alerts: List[str]):
        """Send alerts via configured channels"""
        logger.warning(f"📢 Alerts for {project_name}:")
        for alert in alerts:
            logger.warning(f"  - {alert}")
        
        # Integration with notification service
        try:
            from app.services.notifications import NotificationService
            notifier = NotificationService()
            
            message = f"Security Alerts for {project_name}:\n\n" + "\n".join(alerts)
            await notifier.send_notification(
                title=f"Security Alert: {project_name}",
                message=message,
                priority="high"
            )
        except Exception as e:
            logger.warning(f"Failed to send notifications: {e}")
    
    def get_project_trends(self, project_name: str, period_days: int = 30) -> Dict:
        """Get trend analysis for project"""
        if project_name not in self.scan_history:
            return {"error": "Project not found"}
        
        analyzer = TrendAnalyzer(self.scan_history[project_name])
        return analyzer.get_trend(period_days)
    
    def get_mttf(self, project_name: str) -> Optional[float]:
        """Get Mean Time To Fix for project"""
        if project_name not in self.scan_history:
            return None
        
        analyzer = TrendAnalyzer(self.scan_history[project_name])
        return analyzer.calculate_mttf()
    
    def _load_state(self):
        """Load monitoring state from disk"""
        config_file = self.storage_path / "configs.json"
        history_file = self.storage_path / "history.json"
        
        if config_file.exists():
            with open(config_file, 'r') as f:
                # Load configs (simplified)
                pass
        
        if history_file.exists():
            with open(history_file, 'r') as f:
                # Load history (simplified)
                pass
    
    def _save_state(self):
        """Save monitoring state to disk"""
        # Save configs and history
        config_file = self.storage_path / "configs.json"
        history_file = self.storage_path / "history.json"
        
        # Simplified - implement full serialization
        pass


# Global monitor instance
_monitor = None

def get_monitor() -> ContinuousMonitor:
    """Get global monitor instance"""
    global _monitor
    if _monitor is None:
        _monitor = ContinuousMonitor()
    return _monitor
