"""
Audit Logging Service for the Secure Auth API.
Implements comprehensive logging of all security events and user actions.
"""

import uuid
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from fastapi import Request
import structlog

from app.core.config import get_settings
from app.models.audit import AuditLog, AuditEventType, AuditSeverity, SecurityMetrics, ThreatIntelligence

settings = get_settings()

# Configure structlog
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)


class AuditService:
    """Service for comprehensive audit logging and security monitoring."""
    
    def __init__(self):
        self.logger = structlog.get_logger(__name__)
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup logging configuration based on settings."""
        if settings.log_format.lower() == "json":
            # JSON logging is already configured in structlog.configure above
            pass
        else:
            # Configure for human-readable logging
            structlog.configure(
                processors=[
                    structlog.stdlib.filter_by_level,
                    structlog.stdlib.add_logger_name,
                    structlog.stdlib.add_log_level,
                    structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
                    structlog.dev.ConsoleRenderer(colors=True)
                ],
                logger_factory=structlog.stdlib.LoggerFactory(),
                wrapper_class=structlog.stdlib.BoundLogger,
                cache_logger_on_first_use=True,
            )
            self.logger = structlog.get_logger(__name__)
    
    def log_event(
        self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        event_description: str,
        user_id: Optional[uuid.UUID] = None,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        endpoint: Optional[str] = None,
        http_method: Optional[str] = None,
        status_code: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
        error_details: Optional[str] = None
    ):
        """Log an audit event with comprehensive context."""
        log_data = {
            "event_type": event_type.value,
            "severity": severity.value,
            "event_description": event_description,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": str(user_id) if user_id else None,
            "username": username,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "request_id": request_id,
            "endpoint": endpoint,
            "http_method": http_method,
            "status_code": status_code,
            "metadata": metadata or {},
            "error_details": error_details
        }
        
        # Remove None values for cleaner logs
        log_data = {k: v for k, v in log_data.items() if v is not None}
        
        # Log based on severity
        if severity == AuditSeverity.CRITICAL:
            self.logger.critical("audit_event", **log_data)
        elif severity == AuditSeverity.HIGH:
            self.logger.error("audit_event", **log_data)
        elif severity == AuditSeverity.MEDIUM:
            self.logger.warning("audit_event", **log_data)
        else:
            self.logger.info("audit_event", **log_data)
        
        # Store in database (this would be implemented with actual database operations)
        self._store_audit_log(log_data)
    
    def log_login_success(
        self,
        user_id: uuid.UUID,
        username: str,
        ip_address: str,
        user_agent: str,
        request_id: str,
        endpoint: str
    ):
        """Log a successful user login."""
        self.log_event(
            event_type=AuditEventType.USER_LOGIN,
            severity=AuditSeverity.LOW,
            event_description="User successfully logged in",
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            endpoint=endpoint,
            http_method="POST",
            status_code=200,
            metadata={"login_method": "password", "success": True}
        )
    
    def log_login_failure(
        self,
        username: str,
        ip_address: str,
        user_agent: str,
        request_id: str,
        endpoint: str,
        error_details: str
    ):
        """Log a failed user login attempt."""
        self.log_event(
            event_type=AuditEventType.USER_LOGIN_FAILED,
            severity=AuditSeverity.MEDIUM,
            event_description="User login attempt failed",
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            endpoint=endpoint,
            http_method="POST",
            status_code=401,
            error_details=error_details,
            metadata={"login_method": "password", "success": False}
        )
    
    def log_rate_limit_exceeded(
        self,
        user_id: Optional[uuid.UUID],
        username: Optional[str],
        ip_address: str,
        endpoint: str,
        request_id: str
    ):
        """Log a rate limit violation."""
        self.log_event(
            event_type=AuditEventType.RATE_LIMIT_EXCEEDED,
            severity=AuditSeverity.HIGH,
            event_description="Rate limit exceeded for endpoint",
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            request_id=request_id,
            endpoint=endpoint,
            metadata={"rate_limit_type": "endpoint", "action_taken": "request_blocked"}
        )
    
    def log_account_locked(
        self,
        user_id: uuid.UUID,
        username: str,
        ip_address: str,
        user_agent: str,
        request_id: str
    ):
        """Log an account lockout."""
        self.log_event(
            event_type=AuditEventType.ACCOUNT_LOCKED,
            severity=AuditSeverity.HIGH,
            event_description="User account locked due to multiple failed login attempts",
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            metadata={"lock_reason": "brute_force_protection", "lock_duration_minutes": 30}
        )
    
    def log_suspicious_activity(
        self,
        user_id: Optional[uuid.UUID],
        username: Optional[str],
        ip_address: str,
        event_description: str,
        metadata: Dict[str, Any]
    ):
        """Log suspicious activity."""
        self.log_event(
            event_type=AuditEventType.SUSPICIOUS_ACTIVITY,
            severity=AuditSeverity.HIGH,
            event_description=event_description,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            metadata=metadata
        )
    
    def log_session_refreshed(
        self,
        user_id: uuid.UUID,
        username: str,
        ip_address: str,
        user_agent: str,
        request_id: str
    ):
        """Log a session token refresh."""
        self.log_event(
            event_type=AuditEventType.SESSION_REFRESHED,
            severity=AuditSeverity.LOW,
            event_description="User session token refreshed",
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            metadata={"session_action": "refresh"}
        )
    
    def log_session_revoked(
        self,
        user_id: uuid.UUID,
        username: str,
        ip_address: str,
        user_agent: str,
        request_id: str
    ):
        """Log a session token revocation."""
        self.log_event(
            event_type=AuditEventType.SESSION_REVOKED,
            severity=AuditSeverity.MEDIUM,
            event_description="User session token revoked",
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            metadata={"session_action": "revoke"}
        )
    
    def log_brute_force_attempt(
        self,
        username: str,
        ip_address: str,
        attempt_count: int,
        user_agent: str
    ):
        """Log a brute force attack attempt."""
        self.log_event(
            event_type=AuditEventType.BRUTE_FORCE_ATTEMPT,
            severity=AuditSeverity.CRITICAL,
            event_description=f"Brute force attempt detected - {attempt_count} failed attempts",
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={
                "attempt_count": attempt_count,
                "action_taken": "account_locked",
                "threat_level": "high"
            }
        )
    
    def log_user_registration(
        self,
        user_id: uuid.UUID,
        username: str,
        ip_address: str,
        user_agent: str,
        request_id: str
    ):
        """Log a new user registration."""
        self.log_event(
            event_type=AuditEventType.USER_REGISTERED,
            severity=AuditSeverity.LOW,
            event_description="New user registered",
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            metadata={"registration_method": "web_form"}
        )
    
    def log_password_change(
        self,
        user_id: uuid.UUID,
        username: str,
        ip_address: str,
        user_agent: str,
        request_id: str
    ):
        """Log a password change."""
        self.log_event(
            event_type=AuditEventType.PASSWORD_CHANGED,
            severity=AuditSeverity.MEDIUM,
            event_description="User password changed",
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            metadata={"password_change_method": "user_request"}
        )
    
    def log_api_request(
        self,
        request: Request,
        user_id: Optional[uuid.UUID] = None,
        username: Optional[str] = None,
        response_status: Optional[int] = None,
        response_time_ms: Optional[float] = None
    ):
        """Log API request details for monitoring."""
        # Extract request information
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")
        endpoint = str(request.url.path)
        method = request.method
        request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
        
        # Determine severity based on response status
        if response_status and response_status >= 500:
            severity = AuditSeverity.HIGH
        elif response_status and response_status >= 400:
            severity = AuditSeverity.MEDIUM
        else:
            severity = AuditSeverity.LOW
        
        metadata = {
            "response_status": response_status,
            "response_time_ms": response_time_ms,
            "request_size": request.headers.get("content-length", 0),
            "user_agent": user_agent
        }
        
        self.log_event(
            event_type=AuditEventType.SUSPICIOUS_ACTIVITY if severity == AuditSeverity.HIGH else AuditEventType.USER_LOGIN,
            severity=severity,
            event_description=f"API request: {method} {endpoint}",
            user_id=user_id,
            username=username,
            ip_address=client_ip,
            user_agent=user_agent,
            request_id=request_id,
            endpoint=endpoint,
            http_method=method,
            status_code=response_status,
            metadata=metadata
        )
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract the real client IP address from the request."""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    def _store_audit_log(self, log_data: Dict[str, Any]):
        """Store audit log in database. This is a placeholder implementation."""
        # In a real implementation, this would store the log in the database
        # For now, we'll just pass as the structlog already handles the output
        pass
    
    def get_audit_logs(
        self,
        user_id: Optional[uuid.UUID] = None,
        username: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        severity: Optional[AuditSeverity] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Retrieve audit logs with filtering options."""
        # This would be implemented with actual database queries
        # For now, return empty list
        return []
    
    def get_security_metrics(
        self,
        time_period: str = "hourly",
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Get security metrics for the specified time period."""
        # This would be implemented with actual database queries
        # For now, return placeholder data
        return {
            "time_period": time_period,
            "start_date": start_date.isoformat() if start_date else None,
            "end_date": end_date.isoformat() if end_date else None,
            "metrics": {
                "failed_login_attempts": 0,
                "rate_limit_violations": 0,
                "suspicious_activities": 0,
                "account_lockouts": 0
            }
        }
    
    def detect_threats(self, ip_address: str, user_agent: str) -> List[Dict[str, Any]]:
        """Detect potential threats based on IP and user agent patterns."""
        threats = []
        
        # Example threat detection logic
        # In a real implementation, this would query threat intelligence databases
        
        # Check for known malicious user agents
        malicious_agents = ["bot", "crawler", "scraper", "spider"]
        if any(agent in user_agent.lower() for agent in malicious_agents):
            threats.append({
                "threat_type": "suspicious_user_agent",
                "severity": "medium",
                "description": "Suspicious user agent detected",
                "indicators": {"user_agent": user_agent}
            })
        
        # Check for rapid request patterns (this would be implemented with rate limiting data)
        # Check for known malicious IP addresses (this would query threat intelligence feeds)
        
        return threats


# Dependency for getting the audit service
def get_audit_service() -> AuditService:
    """Get the audit service instance."""
    return AuditService()
