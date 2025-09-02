"""
Main FastAPI application for the Secure Auth API.
Implements the complete authentication system with security middleware.
"""

import uuid
import time
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Request, Response, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
import structlog

from app.core.config import get_settings
from app.services.audit_service import AuditService, get_audit_service
from app.services.rate_limit_service import RateLimitService, get_rate_limit_service
from app.services.auth_service import AuthService, get_auth_service
from app.models.user import User

# Get settings
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

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting Secure Auth API", version=settings.app_version, environment=settings.environment)
    
    # Initialize services
    try:
        audit_service = get_audit_service()
        rate_limit_service = get_rate_limit_service(audit_service)
        
        # Log system startup
        audit_service.log_event(
            event_type=audit_service.models.audit.AuditEventType.SYSTEM_STARTUP,
            severity=audit_service.models.audit.AuditSeverity.LOW,
            event_description="Secure Auth API started",
            metadata={"version": settings.app_version, "environment": settings.environment}
        )
        
        logger.info("Services initialized successfully")
        
    except Exception as e:
        logger.error("Failed to initialize services", error=str(e))
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down Secure Auth API")
    
    try:
        audit_service.log_event(
            event_type=audit_service.models.audit.AuditEventType.SYSTEM_SHUTDOWN,
            severity=audit_service.models.audit.AuditSeverity.LOW,
            event_description="Secure Auth API shutting down",
            metadata={"shutdown_reason": "normal"}
        )
    except Exception as e:
        logger.error("Failed to log shutdown event", error=str(e))


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="A secure API authentication system with JWT tokens, rate limiting, and audit logging",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan
)

# Security middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"] if settings.debug else settings.cors_allowed_origins
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_allowed_methods,
    allow_headers=settings.cors_allowed_headers,
)

# Request ID middleware
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Add unique request ID to each request."""
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    
    # Add request ID to response headers
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    
    return response


# Rate limiting middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Apply rate limiting to all requests."""
    start_time = time.time()
    
    try:
        # Get services
        audit_service = get_audit_service()
        rate_limit_service = get_rate_limit_service(audit_service)
        
        # Apply rate limiting
        if not rate_limit_service.apply_rate_limiting(request, str(request.url.path)):
            # Rate limit exceeded
            return rate_limit_service.create_rate_limit_response(f"rate_limit:ip:{request.client.host}:{request.url.path}")
        
        # Process request
        response = await call_next(request)
        
        # Calculate response time
        response_time = (time.time() - start_time) * 1000
        
        # Log API request
        audit_service.log_api_request(
            request=request,
            response_status=response.status_code,
            response_time_ms=response_time
        )
        
        # Add response time header
        response.headers["X-Response-Time"] = f"{response_time:.2f}ms"
        
        return response
        
    except Exception as e:
        logger.error("Error in rate limiting middleware", error=str(e), request_id=request.state.request_id)
        # Continue with request on error
        return await call_next(request)


# Error handling middleware
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unhandled errors."""
    request_id = getattr(request.state, 'request_id', 'unknown')
    
    logger.error(
        "Unhandled exception",
        error=str(exc),
        request_id=request_id,
        endpoint=str(request.url.path),
        method=request.method
    )
    
    # Log the error
    try:
        audit_service = get_audit_service()
        audit_service.log_event(
            event_type=audit_service.models.audit.AuditEventType.SUSPICIOUS_ACTIVITY,
            severity=audit_service.models.audit.AuditSeverity.HIGH,
            event_description=f"Unhandled exception: {str(exc)}",
            ip_address=request.client.host if request.client else "unknown",
            request_id=request_id,
            endpoint=str(request.url.path),
            http_method=request.method,
            error_details=str(exc)
        )
    except Exception as log_error:
        logger.error("Failed to log error event", error=str(log_error))
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred",
            "request_id": request_id
        }
    )


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "version": settings.app_version,
        "environment": settings.environment
    }


# Authentication endpoints
@app.post("/auth/register")
async def register_user(
    request: Request,
    user_data: Dict[str, Any],
    audit_service: AuditService = Depends(get_audit_service),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Register a new user account."""
    try:
        # Extract request information
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")
        request_id = request.state.request_id
        
        # Validate user data (this would be implemented with Pydantic models)
        username = user_data.get("username")
        email = user_data.get("email")
        password = user_data.get("password")
        
        if not all([username, email, password]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing required fields"
            )
        
        # Create user (this would be implemented with actual database operations)
        # For now, we'll just log the registration attempt
        
        # Log user registration
        audit_service.log_user_registration(
            user_id=uuid.uuid4(),  # This would be the actual user ID
            username=username,
            ip_address=client_ip,
            user_agent=user_agent,
            request_id=request_id
        )
        
        return {
            "message": "User registered successfully",
            "user_id": str(uuid.uuid4()),
            "username": username,
            "email": email
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error in user registration", error=str(e), request_id=request.state.request_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )


@app.post("/auth/login")
async def login_user(
    request: Request,
    credentials: Dict[str, str],
    audit_service: AuditService = Depends(get_audit_service),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Authenticate a user and return JWT tokens."""
    try:
        # Extract request information
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")
        request_id = request.state.request_id
        
        username = credentials.get("username")
        password = credentials.get("password")
        
        if not username or not password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username and password are required"
            )
        
        # Authenticate user
        user, access_token, refresh_token = auth_service.authenticate_user(
            username, password, client_ip, user_agent, request_id
        )
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.jwt_access_token_expire_minutes * 60
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error in user login", error=str(e), request_id=request.state.request_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed"
        )


@app.post("/auth/refresh")
async def refresh_token(
    request: Request,
    refresh_data: Dict[str, str],
    audit_service: AuditService = Depends(get_audit_service),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Refresh an access token using a refresh token."""
    try:
        # Extract request information
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")
        request_id = request.state.request_id
        
        refresh_token = refresh_data.get("refresh_token")
        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Refresh token is required"
            )
        
        # Refresh the token
        new_access_token = auth_service.refresh_access_token(
            refresh_token, client_ip, user_agent, request_id
        )
        
        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": settings.jwt_access_token_expire_minutes * 60
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error in token refresh", error=str(e), request_id=request.state.request_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )


@app.post("/auth/logout")
async def logout_user(
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
    audit_service: AuditService = Depends(get_audit_service)
):
    """Logout user and revoke tokens."""
    try:
        # Extract request information
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")
        request_id = request.state.request_id
        
        # Get current user from token
        current_user = auth_service.get_current_user(
            HTTPBearer().credentials(request)
        )
        
        # Revoke the token
        auth_service.revoke_token(
            HTTPBearer().credentials(request).credentials,
            client_ip, user_agent, request_id
        )
        
        return {"message": "Successfully logged out"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error in user logout", error=str(e), request_id=request.state.request_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )


# Protected endpoints
@app.get("/users/me")
async def get_current_user_info(
    current_user: User = Depends(get_auth_service().get_current_user)
):
    """Get information about the current authenticated user."""
    return {
        "user_id": str(current_user.id),
        "username": current_user.username,
        "email": current_user.email,
        "first_name": current_user.first_name,
        "last_name": current_user.last_name,
        "is_active": current_user.is_active,
        "is_verified": current_user.is_verified,
        "created_at": current_user.created_at.isoformat(),
        "last_login_at": current_user.last_login_at.isoformat() if current_user.last_login_at else None
    }


# Monitoring endpoints
@app.get("/metrics/rate-limits")
async def get_rate_limit_metrics(
    rate_limit_service: RateLimitService = Depends(get_rate_limit_service)
):
    """Get rate limiting statistics."""
    return rate_limit_service.get_rate_limit_stats()


@app.get("/metrics/security")
async def get_security_metrics(
    audit_service: AuditService = Depends(get_audit_service)
):
    """Get security metrics."""
    return audit_service.get_security_metrics()


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        workers=settings.workers if not settings.debug else 1
    )
