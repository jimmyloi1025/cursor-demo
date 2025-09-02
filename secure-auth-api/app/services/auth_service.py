"""
JWT Authentication Service for the Secure Auth API.
Handles token generation, validation, and user authentication.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Tuple
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.core.config import get_settings
from app.models.user import User, UserSession
from app.services.audit_service import AuditService
from app.services.rate_limit_service import RateLimitService

settings = get_settings()

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# HTTP Bearer token scheme
security = HTTPBearer()


class AuthService:
    """Service for handling JWT authentication and user management."""
    
    def __init__(self, audit_service: AuditService, rate_limit_service: RateLimitService):
        self.audit_service = audit_service
        self.rate_limit_service = rate_limit_service
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a plain password against its hash."""
        return pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """Generate a password hash."""
        return pwd_context.hash(password)
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token."""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_access_token_expire_minutes)
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "type": "access"
        })
        
        encoded_jwt = jwt.encode(
            to_encode, 
            settings.jwt_secret_key.get_secret_value(), 
            algorithm=settings.jwt_algorithm
        )
        return encoded_jwt
    
    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        """Create a JWT refresh token."""
        to_encode = data.copy()
        
        expire = datetime.now(timezone.utc) + timedelta(days=settings.jwt_refresh_token_expire_days)
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "type": "refresh"
        })
        
        encoded_jwt = jwt.encode(
            to_encode, 
            settings.jwt_secret_key.get_secret_value(), 
            algorithm=settings.jwt_algorithm
        )
        return encoded_jwt
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode a JWT token."""
        try:
            payload = jwt.decode(
                token, 
                settings.jwt_secret_key.get_secret_value(), 
                algorithms=[settings.jwt_algorithm],
                issuer=settings.jwt_issuer,
                audience=settings.jwt_audience
            )
            
            # Check if token is expired
            if datetime.fromtimestamp(payload["exp"], tz=timezone.utc) < datetime.now(timezone.utc):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has expired"
                )
            
            return payload
            
        except JWTError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
    
    def authenticate_user(self, username: str, password: str, ip_address: str, user_agent: str, request_id: str) -> Tuple[User, str, str]:
        """Authenticate a user and return user object with tokens."""
        # Check rate limiting for login attempts
        rate_limit_key = f"login_attempts:{ip_address}"
        if not self.rate_limit_service.check_rate_limit(rate_limit_key, max_requests=5, window_seconds=300):
            self.audit_service.log_rate_limit_exceeded(
                None, username, ip_address, "/auth/login", request_id
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts. Please try again later."
            )
        
        # Get user from database (this would be implemented in a user service)
        # For now, we'll assume a user object is passed or retrieved
        user = self._get_user_by_username(username)
        
        if not user:
            self.audit_service.log_login_failure(
                username, ip_address, user_agent, request_id, "/auth/login", "User not found"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password"
            )
        
        if not user.is_active:
            self.audit_service.log_login_failure(
                username, ip_address, user_agent, request_id, "/auth/login", "Account disabled"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is disabled"
            )
        
        if user.is_locked:
            self.audit_service.log_login_failure(
                username, ip_address, user_agent, request_id, "/auth/login", "Account locked"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is locked. Please try again later."
            )
        
        if not self.verify_password(password, user.password_hash):
            # Increment failed login attempts
            user.increment_failed_login_attempts()
            
            # Lock account if too many failed attempts
            if user.failed_login_attempts >= 5:
                user.lock_account(duration_minutes=30)
                self.audit_service.log_account_locked(
                    user.id, username, ip_address, user_agent, request_id
                )
            
            self.audit_service.log_login_failure(
                username, ip_address, user_agent, request_id, "/auth/login", "Invalid password"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password"
            )
        
        # Reset failed login attempts on successful login
        user.reset_failed_login_attempts()
        user.update_last_login()
        
        # Create tokens
        access_token = self.create_access_token(data={"sub": str(user.id), "username": user.username})
        refresh_token = self.create_refresh_token(data={"sub": str(user.id), "username": user.username})
        
        # Log successful login
        self.audit_service.log_login_success(
            user.id, username, ip_address, user_agent, request_id, "/auth/login"
        )
        
        return user, access_token, refresh_token
    
    def refresh_access_token(self, refresh_token: str, ip_address: str, user_agent: str, request_id: str) -> str:
        """Refresh an access token using a refresh token."""
        try:
            # Verify refresh token
            payload = self.verify_token(refresh_token)
            
            # Check if it's actually a refresh token
            if payload.get("type") != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type"
                )
            
            user_id = payload.get("sub")
            username = payload.get("username")
            
            if not user_id or not username:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token payload"
                )
            
            # Check if user still exists and is active
            user = self._get_user_by_id(uuid.UUID(user_id))
            if not user or not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found or inactive"
                )
            
            # Create new access token
            new_access_token = self.create_access_token(
                data={"sub": str(user.id), "username": user.username}
            )
            
            # Log token refresh
            self.audit_service.log_session_refreshed(
                user.id, username, ip_address, user_agent, request_id
            )
            
            return new_access_token
            
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
    
    def revoke_token(self, token: str, ip_address: str, user_agent: str, request_id: str) -> bool:
        """Revoke a JWT token."""
        try:
            payload = self.verify_token(token)
            user_id = payload.get("sub")
            username = payload.get("username")
            
            # Add token to blacklist (implemented in Redis or database)
            self._blacklist_token(token)
            
            # Log token revocation
            if user_id and username:
                self.audit_service.log_session_revoked(
                    uuid.UUID(user_id), username, ip_address, user_agent, request_id
                )
            
            return True
            
        except JWTError:
            # Token is already invalid, consider it revoked
            return True
    
    def get_current_user(self, credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
        """Get the current authenticated user from JWT token."""
        token = credentials.credentials
        
        try:
            payload = self.verify_token(token)
            user_id = payload.get("sub")
            
            if user_id is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Could not validate credentials"
                )
            
            # Check if token is blacklisted
            if self._is_token_blacklisted(token):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked"
                )
            
            # Get user from database
            user = self._get_user_by_id(uuid.UUID(user_id))
            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found"
                )
            
            if not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User is inactive"
                )
            
            return user
            
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
    
    def _get_user_by_username(self, username: str) -> Optional[User]:
        """Get a user by username. This would be implemented with database queries."""
        # Placeholder implementation - replace with actual database query
        pass
    
    def _get_user_by_id(self, user_id: uuid.UUID) -> Optional[User]:
        """Get a user by ID. This would be implemented with database queries."""
        # Placeholder implementation - replace with actual database query
        pass
    
    def _blacklist_token(self, token: str) -> None:
        """Add a token to the blacklist. This would be implemented with Redis."""
        # Placeholder implementation - replace with actual Redis implementation
        pass
    
    def _is_token_blacklisted(self, token: str) -> bool:
        """Check if a token is blacklisted. This would be implemented with Redis."""
        # Placeholder implementation - replace with actual Redis implementation
        return False


# Dependency for getting the auth service
def get_auth_service(
    audit_service: AuditService = Depends(),
    rate_limit_service: RateLimitService = Depends()
) -> AuthService:
    """Get the authentication service instance."""
    return AuthService(audit_service, rate_limit_service)
