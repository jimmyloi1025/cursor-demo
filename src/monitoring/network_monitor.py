#!/usr/bin/env python3
"""
Network Connection Monitor
Monitors network connections and detects suspicious activity based on security rules.
Integrates with SIEM systems following the alert flow architecture.
"""

import asyncio
import json
import logging
import psutil
import socket
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque
import ipaddress
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..utils.logging import SecurityLogger
from ..utils.config import Config
from .alert_manager import AlertManager


@dataclass
class NetworkConnection:
    """Data model for network connection information."""
    pid: int
    process_name: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str
    protocol: str
    timestamp: datetime
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


@dataclass
class ThreatIndicator:
    """Data model for threat intelligence indicators."""
    ip_address: str
    threat_type: str
    confidence: float
    source: str
    last_seen: datetime
    description: str


class ThreatIntelligence:
    """Threat intelligence integration for IP reputation checking."""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = SecurityLogger(__name__)
        self.cache: Dict[str, ThreatIndicator] = {}
        self.cache_ttl = timedelta(hours=1)
        
        # Setup HTTP session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    async def check_ip_reputation(self, ip_address: str) -> Optional[ThreatIndicator]:
        """Check IP reputation against threat intelligence feeds."""
        try:
            # Check cache first
            if ip_address in self.cache:
                indicator = self.cache[ip_address]
                if datetime.now() - indicator.last_seen < self.cache_ttl:
                    return indicator
            
            # Skip private/local IPs
            try:
                ip_obj = ipaddress.ip_address(ip_address)
                if ip_obj.is_private or ip_obj.is_loopback:
                    return None
            except ValueError:
                return None
            
            # Query VirusTotal API (example implementation)
            if self.config.virustotal_api_key:
                indicator = await self._check_virustotal(ip_address)
                if indicator:
                    self.cache[ip_address] = indicator
                    return indicator
                    
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking IP reputation for {ip_address}: {e}")
            return None
    
    async def _check_virustotal(self, ip_address: str) -> Optional[ThreatIndicator]:
        """Check IP against VirusTotal API."""
        try:
            url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
            params = {
                'apikey': self.config.virustotal_api_key,
                'ip': ip_address
            }
            
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            if data.get('response_code') == 1 and data.get('positives', 0) > 0:
                return ThreatIndicator(
                    ip_address=ip_address,
                    threat_type="malicious_ip",
                    confidence=min(data.get('positives', 0) / 10.0, 1.0),
                    source="virustotal",
                    last_seen=datetime.now(),
                    description=f"Detected by {data.get('positives', 0)} security vendors"
                )
                
        except Exception as e:
            self.logger.error(f"VirusTotal API error for {ip_address}: {e}")
            
        return None


class SecurityRules:
    """Security rules engine implementing OWASP/CIS guidelines."""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = SecurityLogger(__name__)
        
        # Suspicious ports (common malware/backdoor ports)
        self.suspicious_ports = {
            1337, 31337, 12345, 54321, 9999, 40421, 40422, 40423, 40424,
            2222, 4444, 5555, 6666, 7777, 8888, 9090, 10101
        }
        
        # High-risk ports
        self.high_risk_ports = {
            23, 135, 139, 445, 1433, 1521, 3389, 5432, 5900, 6379
        }
        
        # Connection rate limits
        self.max_connections_per_minute = 100
        self.max_unique_destinations_per_minute = 50
        
        # Tracking
        self.connection_counts: Dict[int, deque] = defaultdict(lambda: deque(maxlen=60))
        self.destination_counts: Dict[int, Set[str]] = defaultdict(set)
        self.last_cleanup = time.time()
    
    def evaluate_connection(self, conn: NetworkConnection) -> List[Dict]:
        """Evaluate connection against security rules."""
        alerts = []
        
        # Rule 1: Suspicious port detection
        if conn.remote_port in self.suspicious_ports:
            alerts.append({
                'rule_id': 'SUSP_PORT_001',
                'severity': 'HIGH',
                'description': f'Connection to suspicious port {conn.remote_port}',
                'category': 'suspicious_port'
            })
        
        # Rule 2: High-risk port monitoring
        if conn.remote_port in self.high_risk_ports:
            alerts.append({
                'rule_id': 'RISK_PORT_001',
                'severity': 'MEDIUM',
                'description': f'Connection to high-risk port {conn.remote_port}',
                'category': 'high_risk_port'
            })
        
        # Rule 3: Connection rate anomaly
        current_time = time.time()
        self.connection_counts[conn.pid].append(current_time)
        
        # Count connections in last minute
        minute_ago = current_time - 60
        recent_connections = [t for t in self.connection_counts[conn.pid] if t > minute_ago]
        
        if len(recent_connections) > self.max_connections_per_minute:
            alerts.append({
                'rule_id': 'RATE_LIMIT_001',
                'severity': 'HIGH',
                'description': f'Process {conn.process_name} exceeded connection rate limit',
                'category': 'rate_anomaly'
            })
        
        # Rule 4: Port scanning detection
        self.destination_counts[conn.pid].add(f"{conn.remote_addr}:{conn.remote_port}")
        
        if len(self.destination_counts[conn.pid]) > self.max_unique_destinations_per_minute:
            alerts.append({
                'rule_id': 'PORT_SCAN_001',
                'severity': 'CRITICAL',
                'description': f'Potential port scanning from process {conn.process_name}',
                'category': 'port_scanning'
            })
        
        # Cleanup old data every 5 minutes
        if current_time - self.last_cleanup > 300:
            self._cleanup_tracking_data()
            self.last_cleanup = current_time
        
        return alerts
    
    def _cleanup_tracking_data(self):
        """Clean up old tracking data to prevent memory leaks."""
        current_time = time.time()
        minute_ago = current_time - 60
        
        # Clean connection counts
        for pid in list(self.connection_counts.keys()):
            self.connection_counts[pid] = deque(
                [t for t in self.connection_counts[pid] if t > minute_ago],
                maxlen=60
            )
            if not self.connection_counts[pid]:
                del self.connection_counts[pid]
        
        # Reset destination counts every minute
        self.destination_counts.clear()


class NetworkMonitor:
    """Main network monitoring class following the detection-validation-enrichment flow."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = Config(config_path)
        self.logger = SecurityLogger(__name__)
        self.alert_manager = AlertManager(self.config)
        self.security_rules = SecurityRules(self.config)
        self.threat_intel = ThreatIntelligence(self.config)
        
        self.running = False
        self.monitored_processes: Set[int] = set()
        self.connection_history: deque = deque(maxlen=1000)
    
    async def start_monitoring(self):
        """Start the network monitoring process."""
        self.logger.info("Starting network monitoring...")
        self.running = True
        
        try:
            while self.running:
                await self._monitor_cycle()
                await asyncio.sleep(self.config.monitoring_interval)
                
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
        except Exception as e:
            self.logger.error(f"Monitoring error: {e}")
        finally:
            self.running = False
    
    async def stop_monitoring(self):
        """Stop the monitoring process."""
        self.logger.info("Stopping network monitoring...")
        self.running = False
    
    async def _monitor_cycle(self):
        """Single monitoring cycle: detection -> validation -> enrichment -> notification."""
        try:
            # DETECTION PHASE
            connections = self._get_network_connections()
            
            for conn in connections:
                # VALIDATION PHASE
                alerts = self.security_rules.evaluate_connection(conn)
                
                if alerts:
                    # ENRICHMENT PHASE
                    threat_indicator = await self.threat_intel.check_ip_reputation(conn.remote_addr)
                    
                    # Enhance alerts with threat intelligence
                    for alert in alerts:
                        alert['connection'] = conn.to_dict()
                        alert['threat_intelligence'] = (
                            asdict(threat_indicator) if threat_indicator else None
                        )
                        
                        # Adjust severity based on threat intelligence
                        if threat_indicator and threat_indicator.confidence > 0.7:
                            alert['severity'] = 'CRITICAL'
                            alert['threat_confirmed'] = True
                    
                    # NOTIFICATION PHASE
                    await self.alert_manager.process_alerts(alerts)
                
                # Store connection for historical analysis
                self.connection_history.append(conn)
                
        except Exception as e:
            self.logger.error(f"Error in monitoring cycle: {e}")
    
    def _get_network_connections(self) -> List[NetworkConnection]:
        """Get current network connections from the system."""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    try:
                        process = psutil.Process(conn.pid) if conn.pid else None
                        process_name = process.name() if process else "unknown"
                        
                        network_conn = NetworkConnection(
                            pid=conn.pid or 0,
                            process_name=process_name,
                            local_addr=conn.laddr.ip,
                            local_port=conn.laddr.port,
                            remote_addr=conn.raddr.ip,
                            remote_port=conn.raddr.port,
                            status=conn.status,
                            protocol='TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                            timestamp=datetime.now()
                        )
                        
                        connections.append(network_conn)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
        except Exception as e:
            self.logger.error(f"Error getting network connections: {e}")
        
        return connections
    
    def get_monitoring_stats(self) -> Dict:
        """Get current monitoring statistics."""
        return {
            'running': self.running,
            'monitored_processes': len(self.monitored_processes),
            'connection_history_size': len(self.connection_history),
            'cache_size': len(self.threat_intel.cache),
            'last_update': datetime.now().isoformat()
        }


async def main():
    """Main entry point for the network monitor."""
    monitor = NetworkMonitor()
    
    try:
        await monitor.start_monitoring()
    except KeyboardInterrupt:
        await monitor.stop_monitoring()


if __name__ == "__main__":
    asyncio.run(main())
