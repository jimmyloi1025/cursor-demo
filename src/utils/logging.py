#!/usr/bin/env python3
"""
Security Logging Utility
Provides structured, secure logging for the network monitoring system.
Implements security-focused logging practices with proper sanitization.
"""

import logging
import json
import sys
import os
from datetime import datetime
from typing import Dict, Any, Optional
from logging.handlers import RotatingFileHandler, SysLogHandler
import socket


class SecurityLogFormatter(logging.Formatter):
    """Custom formatter for security logs with structured output."""
    
    def __init__(self):
        super().__init__()
        self.hostname = socket.gethostname()
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with security context."""
        # Create structured log entry
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'hostname': self.hostname,
            'level': record.levelname,
            'logger': record.name,
            'message': self._sanitize_message(record.getMessage()),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add extra fields if present
        if hasattr(record, 'security_event'):
            log_entry['security_event'] = record.security_event
        
        if hasattr(record, 'user_id'):
            log_entry['user_id'] = record.user_id
        
        if hasattr(record, 'source_ip'):
            log_entry['source_ip'] = self._sanitize_ip(record.source_ip)
        
        if hasattr(record, 'alert_id'):
            log_entry['alert_id'] = record.alert_id
        
        # Add process info for security events
        if record.levelno >= logging.WARNING:
            log_entry['pid'] = os.getpid()
            log_entry['severity'] = 'HIGH' if record.levelno >= logging.ERROR else 'MEDIUM'
        
        return json.dumps(log_entry, ensure_ascii=False)
    
    def _sanitize_message(self, message: str) -> str:
        """Sanitize log message to prevent log injection."""
        if not isinstance(message, str):
            message = str(message)
        
        # Remove control characters and potential injection attempts
        sanitized = ''.join(char for char in message if ord(char) >= 32 or char in '\t\n\r')
        
        # Limit message length to prevent DoS
        if len(sanitized) > 1000:
            sanitized = sanitized[:997] + "..."
        
        return sanitized
    
    def _sanitize_ip(self, ip_address: str) -> str:
        """Sanitize IP address for logging."""
        if not isinstance(ip_address, str):
            return "invalid_ip"
        
        # Basic IP validation to prevent injection
        parts = ip_address.split('.')
        if len(parts) == 4:
            try:
                for part in parts:
                    if not (0 <= int(part) <= 255):
                        return "invalid_ip"
                return ip_address
            except ValueError:
                return "invalid_ip"
        
        # IPv6 basic validation
        if ':' in ip_address:
            try:
                socket.inet_pton(socket.AF_INET6, ip_address)
                return ip_address
            except socket.error:
                return "invalid_ipv6"
        
        return "invalid_ip"


class SecurityLogger:
    """Security-focused logger with multiple output handlers."""
    
    def __init__(self, name: str, log_level: str = "INFO"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Prevent duplicate handlers
        if self.logger.handlers:
            return
        
        formatter = SecurityLogFormatter()
        
        # Console handler for development
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler for persistent logging
        log_dir = os.getenv('LOG_DIR', 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, 'security.log'),
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Syslog handler for SIEM integration
        try:
            syslog_handler = SysLogHandler(
                address=('localhost', 514),
                facility=SysLogHandler.LOG_SECURITY
            )
            syslog_handler.setFormatter(formatter)
            self.logger.addHandler(syslog_handler)
        except Exception:
            # Syslog may not be available in all environments
            pass
    
    def info(self, message: str, **kwargs):
        """Log info message with optional security context."""
        self._log_with_context(logging.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message with optional security context."""
        self._log_with_context(logging.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message with optional security context."""
        self._log_with_context(logging.ERROR, message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log critical message with optional security context."""
        self._log_with_context(logging.CRITICAL, message, **kwargs)
    
    def security_event(self, event_type: str, message: str, **kwargs):
        """Log security event with enhanced context."""
        kwargs['security_event'] = event_type
        self._log_with_context(logging.WARNING, f"SECURITY_EVENT: {message}", **kwargs)
    
    def audit_log(self, action: str, resource: str, result: str, **kwargs):
        """Log audit event for compliance."""
        audit_message = f"AUDIT: {action} on {resource} - {result}"
        kwargs['security_event'] = 'audit'
        self._log_with_context(logging.INFO, audit_message, **kwargs)
    
    def _log_with_context(self, level: int, message: str, **kwargs):
        """Log message with additional security context."""
        # Create log record
        record = self.logger.makeRecord(
            self.logger.name,
            level,
            __file__,
            0,
            message,
            (),
            None
        )
        
        # Add security context
        for key, value in kwargs.items():
            setattr(record, key, value)
        
        self.logger.handle(record)


class AuditLogger:
    """Specialized logger for audit trails and compliance."""
    
    def __init__(self, name: str = "audit"):
        self.logger = SecurityLogger(f"{name}.audit")
    
    def log_connection_attempt(self, source_ip: str, destination_ip: str, 
                             port: int, protocol: str, result: str):
        """Log network connection attempt."""
        self.logger.audit_log(
            action="network_connection",
            resource=f"{destination_ip}:{port}",
            result=result,
            source_ip=source_ip,
            protocol=protocol
        )
    
    def log_alert_generated(self, alert_id: str, rule_id: str, severity: str):
        """Log security alert generation."""
        self.logger.audit_log(
            action="alert_generated",
            resource=rule_id,
            result="success",
            alert_id=alert_id,
            severity=severity
        )
    
    def log_config_change(self, config_item: str, old_value: str, new_value: str, user_id: str):
        """Log configuration changes."""
        self.logger.audit_log(
            action="config_change",
            resource=config_item,
            result="success",
            user_id=user_id,
            old_value=old_value,
            new_value=new_value
        )
    
    def log_siem_integration(self, siem_type: str, alert_count: int, result: str):
        """Log SIEM integration events."""
        self.logger.audit_log(
            action="siem_integration",
            resource=siem_type,
            result=result,
            alert_count=alert_count
        )
