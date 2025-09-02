"""
Audit logging model for the Secure Auth API.
Tracks all security-relevant events and user actions.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import Column, String, DateTime, Text, Integer, JSON, Enum, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
import enum

Base = declarative_base()


class AuditEventType(enum.Enum):
    """Types of audit events."""
    
    # Authentication events
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_LOGIN_FAILED = "user_login_failed"
    USER_REGISTERED = "user_registered"
    USER_VERIFIED = "user_verified"
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_RESET_REQUESTED = "password_reset_requested"
    PASSWORD_RESET_COMPLETED = "password_reset_completed"
    
    # Session events
    SESSION_CREATED = "session_created"
    SESSION_REFRESHED = "session_refreshed"
    SESSION_REVOKED = "session_revoked"
    SESSION_EXPIRED = "session_expired"
    
    # Security events
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"
    
    # Profile events
    PROFILE_UPDATED = "profile_updated"
    EMAIL_CHANGED = "email_changed"
    PHONE_CHANGED = "phone_changed"
    
    # Administrative events
    USER_CREATED = "user_created"
    USER_DELETED = "user_deleted"
    USER_DISABLED = "user_disabled"
    USER_ENABLED = "user_enabled"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REMOVED = "role_removed"
    
    # System events
    CONFIGURATION_CHANGED = "configuration_changed"
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    BACKUP_CREATED = "backup_created"
    MAINTENANCE_MODE = "maintenance_mode"


class AuditSeverity(enum.Enum):
    """Severity levels for audit events."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditLog(Base):
    """Audit log model for tracking security events."""
    
    __tablename__ = "audit_logs"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Event information
    event_type = Column(Enum(AuditEventType), nullable=False, index=True)
    severity = Column(Enum(AuditSeverity), nullable=False, index=True)
    event_description = Column(Text, nullable=False)
    
    # User context
    user_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    username = Column(String(50), nullable=True, index=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(Text, nullable=True)
    
    # Request context
    request_id = Column(String(50), nullable=True, index=True)
    endpoint = Column(String(255), nullable=True)
    http_method = Column(String(10), nullable=True)
    status_code = Column(Integer, nullable=True)
    
    # Additional data
    metadata = Column(JSON, nullable=True)  # Structured data about the event
    error_details = Column(Text, nullable=True)  # Error information if applicable
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, event_type='{self.event_type.value}', user_id={self.user_id}, created_at='{self.created_at}')>"
    
    @classmethod
    def create_login_success(cls, user_id: uuid.UUID, username: str, ip_address: str, user_agent: str, request_id: str, endpoint: str):
        """Create a successful login audit log entry."""
        return cls(
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
            status_code=200
        )
    
    @classmethod
    def create_login_failure(cls, username: str, ip_address: str, user_agent: str, request_id: str, endpoint: str, error_details: str):
        """Create a failed login audit log entry."""
        return cls(
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
            error_details=error_details
        )
    
    @classmethod
    def create_rate_limit_exceeded(cls, user_id: Optional[uuid.UUID], username: Optional[str], ip_address: str, endpoint: str, request_id: str):
        """Create a rate limit exceeded audit log entry."""
        return cls(
            event_type=AuditEventType.RATE_LIMIT_EXCEEDED,
            severity=AuditSeverity.HIGH,
            event_description="Rate limit exceeded for endpoint",
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            request_id=request_id,
            endpoint=endpoint,
            metadata={"rate_limit_type": "endpoint"}
        )
    
    @classmethod
    def create_suspicious_activity(cls, user_id: Optional[uuid.UUID], username: Optional[str], ip_address: str, event_description: str, metadata: Dict[str, Any]):
        """Create a suspicious activity audit log entry."""
        return cls(
            event_type=AuditEventType.SUSPICIOUS_ACTIVITY,
            severity=AuditSeverity.HIGH,
            event_description=event_description,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            metadata=metadata
        )
    
    @classmethod
    def create_brute_force_attempt(cls, username: str, ip_address: str, attempt_count: int, user_agent: str):
        """Create a brute force attempt audit log entry."""
        return cls(
            event_type=AuditEventType.BRUTE_FORCE_ATTEMPT,
            severity=AuditSeverity.CRITICAL,
            event_description=f"Brute force attempt detected - {attempt_count} failed attempts",
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"attempt_count": attempt_count, "action_taken": "account_locked"}
        )


class SecurityMetrics(Base):
    """Security metrics model for tracking security-related statistics."""
    
    __tablename__ = "security_metrics"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Metric information
    metric_name = Column(String(100), nullable=False, index=True)
    metric_value = Column(Integer, nullable=False)
    metric_unit = Column(String(20), nullable=True)
    
    # Time context
    time_period = Column(String(20), nullable=False)  # hourly, daily, weekly, monthly
    period_start = Column(DateTime(timezone=True), nullable=False, index=True)
    period_end = Column(DateTime(timezone=True), nullable=False, index=True)
    
    # Additional context
    metadata = Column(JSON, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    
    def __repr__(self):
        return f"<SecurityMetrics(id={self.id}, metric_name='{self.metric_name}', value={self.metric_value}, period='{self.time_period}')>"
    
    @classmethod
    def create_failed_login_count(cls, count: int, period_start: datetime, period_end: datetime):
        """Create a failed login count metric."""
        return cls(
            metric_name="failed_login_attempts",
            metric_value=count,
            metric_unit="attempts",
            time_period="hourly",
            period_start=period_start,
            period_end=period_end
        )
    
    @classmethod
    def create_rate_limit_violations(cls, count: int, period_start: datetime, period_end: datetime):
        """Create a rate limit violations metric."""
        return cls(
            metric_name="rate_limit_violations",
            metric_value=count,
            metric_unit="violations",
            time_period="hourly",
            period_start=period_start,
            period_end=period_end
        )


class ThreatIntelligence(Base):
    """Threat intelligence model for tracking known threats and patterns."""
    
    __tablename__ = "threat_intelligence"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Threat information
    threat_type = Column(String(100), nullable=False, index=True)
    threat_source = Column(String(255), nullable=False)
    threat_description = Column(Text, nullable=False)
    severity = Column(Enum(AuditSeverity), nullable=False)
    
    # Indicators
    ip_addresses = Column(JSON, nullable=True)  # List of suspicious IPs
    user_agents = Column(JSON, nullable=True)  # List of suspicious user agents
    patterns = Column(JSON, nullable=True)  # Behavioral patterns
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Response
    response_action = Column(String(100), nullable=True)  # Action taken
    response_notes = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    def __repr__(self):
        return f"<ThreatIntelligence(id={self.id}, threat_type='{self.threat_type}', severity='{self.severity.value}')>"
    
    def update_last_seen(self):
        """Update the last seen timestamp."""
        self.last_seen = datetime.now(timezone.utc)
    
    def deactivate(self, response_action: str, response_notes: str):
        """Deactivate the threat and record response."""
        self.is_active = False
        self.response_action = response_action
        self.response_notes = response_notes
        self.updated_at = datetime.now(timezone.utc)
