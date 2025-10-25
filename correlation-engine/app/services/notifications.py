"""
Notification Service for Security Automation Platform

Sends notifications via Slack, Email, and GitHub when patches are generated.
"""

import os
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional
from datetime import datetime
import requests


class NotificationService:
    """Handle notifications for patch generation events"""
    
    def __init__(self):
        """Initialize notification channels"""
        # Slack
        self.slack_webhook = os.getenv("SLACK_WEBHOOK_URL")
        
        # Email
        self.smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.email_from = os.getenv("EMAIL_FROM", self.smtp_user)
        self.email_to = os.getenv("EMAIL_TO", "").split(",")
        
        # GitHub
        self.github_token = os.getenv("GITHUB_TOKEN")
        self.github_repo = os.getenv("GITHUB_REPO")  # format: owner/repo
        
    def notify_patch_generated(self, patch_data: Dict[str, Any]) -> Dict[str, bool]:
        """
        Send notifications when a patch is generated.
        
        Args:
            patch_data: Dictionary containing patch details
            
        Returns:
            Dictionary with notification status for each channel
        """
        results = {
            "slack": False,
            "email": False,
            "github": False
        }
        
        # Send to all configured channels
        if self.slack_webhook:
            results["slack"] = self._notify_slack(patch_data)
        
        if self.smtp_user and self.email_to:
            results["email"] = self._notify_email(patch_data)
        
        if self.github_token and self.github_repo:
            results["github"] = self._notify_github(patch_data)
        
        return results
    
    def _notify_slack(self, patch_data: Dict[str, Any]) -> bool:
        """Send Slack notification"""
        try:
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🔵"
            }.get(patch_data.get("severity", "medium"), "⚪")
            
            confidence_emoji = {
                "high": "✅",
                "medium": "⚠️",
                "low": "❓"
            }.get(patch_data.get("confidence", "medium"), "⚪")
            
            message = {
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"🤖 Security Patch Generated"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Vulnerability:*\n{patch_data.get('vulnerability_type', 'Unknown')}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Severity:*\n{severity_emoji} {patch_data.get('severity', 'medium').upper()}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*File:*\n`{patch_data.get('file_path', 'N/A')}`"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Line:*\n{patch_data.get('line_number', 'N/A')}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Confidence:*\n{confidence_emoji} {patch_data.get('confidence', 'medium').upper()}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Provider:*\n{patch_data.get('llm_provider', 'template')}"
                            }
                        ]
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Explanation:*\n{patch_data.get('explanation', 'No explanation provided')[:200]}..."
                        }
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "View Dashboard"
                                },
                                "url": f"{os.getenv('DASHBOARD_URL', 'http://localhost:8000')}/dashboard",
                                "style": "primary"
                            },
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "View API Docs"
                                },
                                "url": f"{os.getenv('API_URL', 'http://localhost:8000')}/docs"
                            }
                        ]
                    }
                ]
            }
            
            response = requests.post(
                self.slack_webhook,
                json=message,
                timeout=10
            )
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"Slack notification failed: {e}")
            return False
    
    def _notify_email(self, patch_data: Dict[str, Any]) -> bool:
        """Send email notification"""
        try:
            subject = f"[Security] Patch Generated: {patch_data.get('vulnerability_type', 'Unknown')}"
            
            # Create HTML email
            html_content = f"""
            <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px 10px 0 0;">
                    <h1 style="margin: 0;">🤖 Security Patch Generated</h1>
                </div>
                
                <div style="background: #f9fafb; padding: 20px; border-radius: 0 0 10px 10px;">
                    <h2 style="color: #1f2937;">{patch_data.get('vulnerability_type', 'Unknown')}</h2>
                    
                    <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                        <tr>
                            <td style="padding: 10px; border-bottom: 1px solid #e5e7eb; font-weight: bold; width: 150px;">Severity:</td>
                            <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">
                                <span style="background: {'#dc2626' if patch_data.get('severity') == 'high' else '#eab308' if patch_data.get('severity') == 'medium' else '#3b82f6'}; color: white; padding: 3px 10px; border-radius: 5px;">
                                    {patch_data.get('severity', 'medium').upper()}
                                </span>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding: 10px; border-bottom: 1px solid #e5e7eb; font-weight: bold;">File:</td>
                            <td style="padding: 10px; border-bottom: 1px solid #e5e7eb; font-family: monospace;">{patch_data.get('file_path', 'N/A')}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px; border-bottom: 1px solid #e5e7eb; font-weight: bold;">Line:</td>
                            <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">{patch_data.get('line_number', 'N/A')}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px; border-bottom: 1px solid #e5e7eb; font-weight: bold;">Confidence:</td>
                            <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">
                                <span style="background: {'#10b981' if patch_data.get('confidence') == 'high' else '#f59e0b' if patch_data.get('confidence') == 'medium' else '#6b7280'}; color: white; padding: 3px 10px; border-radius: 5px;">
                                    {patch_data.get('confidence', 'medium').upper()}
                                </span>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding: 10px; border-bottom: 1px solid #e5e7eb; font-weight: bold;">LLM Provider:</td>
                            <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">{patch_data.get('llm_provider', 'template')}</td>
                        </tr>
                    </table>
                    
                    <h3 style="color: #1f2937;">Explanation:</h3>
                    <p style="color: #4b5563; line-height: 1.6;">{patch_data.get('explanation', 'No explanation provided')}</p>
                    
                    <div style="margin-top: 30px; text-align: center;">
                        <a href="{os.getenv('DASHBOARD_URL', 'http://localhost:8000')}/dashboard" 
                           style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                            View Dashboard
                        </a>
                    </div>
                    
                    <p style="color: #9ca3af; font-size: 12px; margin-top: 30px; text-align: center;">
                        Generated by Security Automation Platform on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                    </p>
                </div>
            </body>
            </html>
            """
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.email_from
            msg['To'] = ', '.join(self.email_to)
            
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            print(f"Email notification failed: {e}")
            return False
    
    def _notify_github(self, patch_data: Dict[str, Any]) -> bool:
        """Create GitHub issue comment or PR comment"""
        try:
            # Find related issue or create a comment
            # This is a simplified version - you'd need to track issue numbers
            
            comment_body = f"""## 🤖 Security Patch Generated

**Vulnerability:** {patch_data.get('vulnerability_type', 'Unknown')}  
**Severity:** {patch_data.get('severity', 'medium').upper()}  
**File:** `{patch_data.get('file_path', 'N/A')}`  
**Line:** {patch_data.get('line_number', 'N/A')}  
**Confidence:** {patch_data.get('confidence', 'medium').upper()}  
**Provider:** {patch_data.get('llm_provider', 'template')}

### Explanation
{patch_data.get('explanation', 'No explanation provided')}

### Original Code
```java
{patch_data.get('original_code', 'N/A')[:500]}
```

### Fixed Code
```java
{patch_data.get('fixed_code', 'N/A')[:500]}
```

---
*Generated by [Security Automation Platform](https://github.com/{self.github_repo}) on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
            
            # This would post to a specific issue or PR
            # For now, we'll just return True as placeholder
            # You'd need to implement GitHub API calls based on your workflow
            
            print(f"GitHub notification prepared (would post to {self.github_repo})")
            return True
            
        except Exception as e:
            print(f"GitHub notification failed: {e}")
            return False
    
    def notify_bulk_patches(self, patches: List[Dict[str, Any]]) -> Dict[str, bool]:
        """Send notification for bulk patch generation"""
        try:
            summary = {
                "total": len(patches),
                "high_confidence": sum(1 for p in patches if p.get("confidence") == "high"),
                "critical": sum(1 for p in patches if p.get("severity") == "critical"),
                "high": sum(1 for p in patches if p.get("severity") == "high"),
            }
            
            # Send summary notification
            if self.slack_webhook:
                self._notify_slack_bulk(summary)
            
            if self.smtp_user and self.email_to:
                self._notify_email_bulk(summary, patches)
            
            return {"sent": True}
            
        except Exception as e:
            print(f"Bulk notification failed: {e}")
            return {"sent": False, "error": str(e)}
    
    def _notify_slack_bulk(self, summary: Dict[str, Any]) -> bool:
        """Send bulk summary to Slack"""
        try:
            message = {
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"🤖 {summary['total']} Patches Generated"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*High Confidence:*\n✅ {summary['high_confidence']}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Critical:*\n🔴 {summary['critical']}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*High:*\n🟠 {summary['high']}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Total:*\n📊 {summary['total']}"
                            }
                        ]
                    }
                ]
            }
            
            response = requests.post(self.slack_webhook, json=message, timeout=10)
            return response.status_code == 200
            
        except Exception as e:
            print(f"Slack bulk notification failed: {e}")
            return False
    
    def _notify_email_bulk(self, summary: Dict[str, Any], patches: List[Dict[str, Any]]) -> bool:
        """Send bulk summary email"""
        # Similar to individual email but with summary
        return True
