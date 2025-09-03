#!/usr/bin/env python3
"""
Alert Manager
Handles alert processing, enrichment, and notification following the alert flow architecture.
Integrates with SIEM systems (Splunk/QRadar) and notification channels (Teams/Email).
"""

import asyncio
import json
import logging
import smtplib
import ssl
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Any
import aiohttp
import requests
from requests.auth import HTTPBasicAuth

from ..utils.logging import SecurityLogger
from ..utils.config import Config


@dataclass
class Alert:
    """Data model for security alerts."""
    alert_id: str
    rule_id: str
    severity: str
    category: str
    description: str
    timestamp: datetime
    connection_data: Dict
    threat_intelligence: Optional[Dict] = None
    risk_score: float = 0.0
    status: str = "new"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


class RiskScoring:
    """Risk scoring engine for alert prioritization."""
    
    def __init__(self):
        self.severity_weights = {
            'LOW': 1.0,
            'MEDIUM': 3.0,
            'HIGH': 7.0,
            'CRITICAL': 10.0
        }
        
        self.category_multipliers = {
            'suspicious_port': 1.2,
            'high_risk_port': 1.0,
            'rate_anomaly': 1.5,
            'port_scanning': 2.0,
            'malicious_ip': 2.5
        }
    
    def calculate_risk_score(self, alert_data: Dict) -> float:
        """Calculate risk score based on alert attributes."""
        base_score = self.severity_weights.get(alert_data.get('severity', 'LOW'), 1.0)
        category_multiplier = self.category_multipliers.get(alert_data.get('category', ''), 1.0)
        
        # Threat intelligence boost
        threat_boost = 1.0
        if alert_data.get('threat_intelligence'):
            confidence = alert_data['threat_intelligence'].get('confidence', 0)
            threat_boost = 1.0 + (confidence * 1.5)
        
        # Time-based decay (newer alerts are more critical)
        time_factor = 1.0
        if 'timestamp' in alert_data:
            try:
                alert_time = datetime.fromisoformat(alert_data['timestamp'].replace('Z', '+00:00'))
                age_hours = (datetime.now() - alert_time.replace(tzinfo=None)).total_seconds() / 3600
                time_factor = max(0.5, 1.0 - (age_hours * 0.1))
            except:
                pass
        
        risk_score = base_score * category_multiplier * threat_boost * time_factor
        return min(risk_score, 100.0)  # Cap at 100


class SIEMIntegration:
    """Integration with SIEM systems (Splunk, QRadar)."""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = SecurityLogger(__name__)
    
    async def send_to_splunk(self, alerts: List[Dict]) -> bool:
        """Send alerts to Splunk via HEC (HTTP Event Collector)."""
        if not self.config.splunk_hec_url or not self.config.splunk_hec_token:
            return False
        
        try:
            headers = {
                'Authorization': f'Splunk {self.config.splunk_hec_token}',
                'Content-Type': 'application/json'
            }
            
            events = []
            for alert in alerts:
                event = {
                    'time': alert.get('timestamp'),
                    'sourcetype': 'network_monitor:alert',
                    'source': 'cursor_demo_monitor',
                    'index': self.config.splunk_index or 'security',
                    'event': alert
                }
                events.append(event)
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.config.splunk_hec_url,
                    headers=headers,
                    json={'event': events},
                    ssl=False if self.config.splunk_verify_ssl is False else None
                ) as response:
                    if response.status == 200:
                        self.logger.info(f"Successfully sent {len(alerts)} alerts to Splunk")
                        return True
                    else:
                        self.logger.error(f"Splunk HEC error: {response.status} - {await response.text()}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"Error sending alerts to Splunk: {e}")
            return False
    
    async def send_to_qradar(self, alerts: List[Dict]) -> bool:
        """Send alerts to QRadar via REST API."""
        if not self.config.qradar_api_url or not self.config.qradar_api_token:
            return False
        
        try:
            headers = {
                'SEC': self.config.qradar_api_token,
                'Content-Type': 'application/json',
                'Version': '12.0'
            }
            
            for alert in alerts:
                # Map to QRadar offense format
                offense_data = {
                    'description': alert.get('description', 'Network monitoring alert'),
                    'severity': self._map_severity_to_qradar(alert.get('severity', 'LOW')),
                    'credibility': int(alert.get('risk_score', 5)),
                    'relevance': 5,
                    'assigned_to': None,
                    'status': 'OPEN'
                }
                
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"{self.config.qradar_api_url}/api/siem/offenses",
                        headers=headers,
                        json=offense_data,
                        ssl=False if self.config.qradar_verify_ssl is False else None
                    ) as response:
                        if response.status in [200, 201]:
                            self.logger.info(f"Successfully sent alert to QRadar: {alert.get('alert_id')}")
                        else:
                            self.logger.error(f"QRadar API error: {response.status} - {await response.text()}")
                            return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending alerts to QRadar: {e}")
            return False
    
    def _map_severity_to_qradar(self, severity: str) -> int:
        """Map severity levels to QRadar numeric values."""
        mapping = {
            'LOW': 3,
            'MEDIUM': 5,
            'HIGH': 7,
            'CRITICAL': 9
        }
        return mapping.get(severity, 5)


class NotificationManager:
    """Handles alert notifications via Teams, Email, and other channels."""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = SecurityLogger(__name__)
    
    async def send_teams_notification(self, alerts: List[Dict]) -> bool:
        """Send alert notifications to Microsoft Teams."""
        if not self.config.teams_webhook_url:
            return False
        
        try:
            # Create Teams adaptive card
            card = self._create_teams_card(alerts)
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.config.teams_webhook_url,
                    json=card
                ) as response:
                    if response.status == 200:
                        self.logger.info(f"Successfully sent Teams notification for {len(alerts)} alerts")
                        return True
                    else:
                        self.logger.error(f"Teams webhook error: {response.status}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"Error sending Teams notification: {e}")
            return False
    
    def _create_teams_card(self, alerts: List[Dict]) -> Dict:
        """Create Teams adaptive card for alerts."""
        high_priority_count = sum(1 for alert in alerts if alert.get('severity') in ['HIGH', 'CRITICAL'])
        
        color = "attention" if high_priority_count > 0 else "warning"
        
        facts = []
        for alert in alerts[:5]:  # Show first 5 alerts
            facts.append({
                "title": f"{alert.get('severity', 'UNKNOWN')} - {alert.get('category', 'Unknown')}",
                "value": alert.get('description', 'No description')
            })
        
        if len(alerts) > 5:
            facts.append({
                "title": "Additional Alerts",
                "value": f"... and {len(alerts) - 5} more alerts"
            })
        
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": f"Network Security Alert - {len(alerts)} alerts",
            "themeColor": "FF6B6B" if color == "attention" else "FFB347",
            "sections": [{
                "activityTitle": "🚨 Network Security Alert",
                "activitySubtitle": f"Detected {len(alerts)} suspicious network activities",
                "facts": facts,
                "markdown": True
            }]
        }
    
    async def send_email_notification(self, alerts: List[Dict]) -> bool:
        """Send alert notifications via email."""
        if not all([self.config.smtp_server, self.config.smtp_username, 
                   self.config.smtp_password, self.config.email_recipients]):
            return False
        
        try:
            # Create email content
            subject = f"Network Security Alert - {len(alerts)} alerts detected"
            body = self._create_email_body(alerts)
            
            # Setup SMTP
            context = ssl.create_default_context()
            
            with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port or 587) as server:
                server.starttls(context=context)
                server.login(self.config.smtp_username, self.config.smtp_password)
                
                # Send to each recipient
                for recipient in self.config.email_recipients:
                    msg = MIMEMultipart()
                    msg['From'] = self.config.smtp_username
                    msg['To'] = recipient
                    msg['Subject'] = subject
                    
                    msg.attach(MIMEText(body, 'html'))
                    
                    server.send_message(msg)
            
            self.logger.info(f"Successfully sent email notifications for {len(alerts)} alerts")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending email notification: {e}")
            return False
    
    def _create_email_body(self, alerts: List[Dict]) -> str:
        """Create HTML email body for alerts."""
        html = f"""
        <html>
        <body>
            <h2>🚨 Network Security Alert Report</h2>
            <p><strong>Detection Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Total Alerts:</strong> {len(alerts)}</p>
            
            <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse;">
                <tr style="background-color: #f0f0f0;">
                    <th>Severity</th>
                    <th>Category</th>
                    <th>Description</th>
                    <th>Source IP</th>
                    <th>Risk Score</th>
                </tr>
        """
        
        for alert in alerts:
            conn_data = alert.get('connection_data', {})
            severity_color = {
                'CRITICAL': '#ff4444',
                'HIGH': '#ff8800',
                'MEDIUM': '#ffaa00',
                'LOW': '#44aa44'
            }.get(alert.get('severity', 'LOW'), '#888888')
            
            html += f"""
                <tr>
                    <td style="color: {severity_color}; font-weight: bold;">{alert.get('severity', 'UNKNOWN')}</td>
                    <td>{alert.get('category', 'Unknown')}</td>
                    <td>{alert.get('description', 'No description')}</td>
                    <td>{conn_data.get('remote_addr', 'Unknown')}</td>
                    <td>{alert.get('risk_score', 0):.1f}</td>
                </tr>
            """
        
        html += """
            </table>
            
            <h3>Recommended Actions:</h3>
            <ul>
                <li>Review the flagged connections in your SIEM system</li>
                <li>Investigate processes making suspicious connections</li>
                <li>Consider blocking malicious IPs at firewall level</li>
                <li>Update security rules if needed</li>
            </ul>
            
            <p><em>This alert was generated by the Cursor Demo Network Monitor</em></p>
        </body>
        </html>
        """
        
        return html


class AlertManager:
    """Main alert management class coordinating the alert flow."""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = SecurityLogger(__name__)
        self.risk_scoring = RiskScoring()
        self.siem_integration = SIEMIntegration(config)
        self.notification_manager = NotificationManager(config)
        
        # Alert deduplication
        self.recent_alerts: Dict[str, datetime] = {}
        self.dedup_window = timedelta(minutes=5)
    
    async def process_alerts(self, alert_data_list: List[Dict]):
        """Process alerts through the complete alert flow."""
        if not alert_data_list:
            return
        
        try:
            # Create Alert objects with risk scoring
            alerts = []
            for alert_data in alert_data_list:
                # Calculate risk score
                risk_score = self.risk_scoring.calculate_risk_score(alert_data)
                
                # Create alert object
                alert = Alert(
                    alert_id=f"NM_{int(datetime.now().timestamp())}_{len(alerts)}",
                    rule_id=alert_data.get('rule_id', 'UNKNOWN'),
                    severity=alert_data.get('severity', 'LOW'),
                    category=alert_data.get('category', 'unknown'),
                    description=alert_data.get('description', 'No description'),
                    timestamp=datetime.now(),
                    connection_data=alert_data.get('connection', {}),
                    threat_intelligence=alert_data.get('threat_intelligence'),
                    risk_score=risk_score
                )
                
                # Check for duplicates
                if not self._is_duplicate_alert(alert):
                    alerts.append(alert)
            
            if not alerts:
                return
            
            # Convert to dict format for processing
            alert_dicts = [alert.to_dict() for alert in alerts]
            
            # Log alerts
            for alert in alert_dicts:
                self.logger.warning(
                    f"SECURITY_ALERT: {alert['severity']} - {alert['description']} "
                    f"(Risk: {alert['risk_score']:.1f})"
                )
            
            # Send to SIEM systems
            siem_tasks = []
            if self.config.enable_splunk:
                siem_tasks.append(self.siem_integration.send_to_splunk(alert_dicts))
            if self.config.enable_qradar:
                siem_tasks.append(self.siem_integration.send_to_qradar(alert_dicts))
            
            if siem_tasks:
                await asyncio.gather(*siem_tasks, return_exceptions=True)
            
            # Send notifications for high-priority alerts
            high_priority_alerts = [
                alert for alert in alert_dicts 
                if alert['severity'] in ['HIGH', 'CRITICAL'] or alert['risk_score'] > 7.0
            ]
            
            if high_priority_alerts:
                notification_tasks = []
                if self.config.enable_teams_notifications:
                    notification_tasks.append(
                        self.notification_manager.send_teams_notification(high_priority_alerts)
                    )
                if self.config.enable_email_notifications:
                    notification_tasks.append(
                        self.notification_manager.send_email_notification(high_priority_alerts)
                    )
                
                if notification_tasks:
                    await asyncio.gather(*notification_tasks, return_exceptions=True)
            
        except Exception as e:
            self.logger.error(f"Error processing alerts: {e}")
    
    def _is_duplicate_alert(self, alert: Alert) -> bool:
        """Check if alert is a duplicate within the deduplication window."""
        alert_key = f"{alert.rule_id}_{alert.category}_{hash(str(alert.connection_data))}"
        
        now = datetime.now()
        if alert_key in self.recent_alerts:
            if now - self.recent_alerts[alert_key] < self.dedup_window:
                return True
        
        # Clean old entries
        self.recent_alerts = {
            k: v for k, v in self.recent_alerts.items() 
            if now - v < self.dedup_window
        }
        
        # Add current alert
        self.recent_alerts[alert_key] = now
        return False
