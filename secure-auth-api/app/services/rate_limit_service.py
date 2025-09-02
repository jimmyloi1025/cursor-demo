"""
Rate Limiting Service for the Secure Auth API.
Implements sliding window rate limiting using Redis.
"""

import time
import json
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timezone
import redis
from fastapi import HTTPException, status, Request, Depends
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.services.audit_service import AuditService

settings = get_settings()


class RateLimitService:
    """Service for implementing rate limiting using Redis."""
    
    def __init__(self, audit_service: AuditService):
        self.audit_service = audit_service
        self.redis_client = self._create_redis_client()
    
    def _create_redis_client(self) -> redis.Redis:
        """Create and configure Redis client."""
        try:
            redis_client = redis.from_url(
                settings.redis_url,
                db=settings.redis_db,
                password=settings.redis_password,
                max_connections=settings.redis_max_connections,
                decode_responses=True
            )
            # Test connection
            redis_client.ping()
            return redis_client
        except redis.ConnectionError as e:
            # Fallback to in-memory rate limiting if Redis is unavailable
            print(f"Redis connection failed: {e}. Falling back to in-memory rate limiting.")
            return None
    
    def check_rate_limit(
        self, 
        key: str, 
        max_requests: int, 
        window_seconds: int,
        burst_size: Optional[int] = None
    ) -> bool:
        """
        Check if a request is allowed based on rate limiting rules.
        
        Args:
            key: Unique identifier for the rate limit (e.g., IP address, user ID)
            max_requests: Maximum number of requests allowed in the time window
            window_seconds: Time window in seconds
            burst_size: Optional burst allowance for sudden traffic spikes
            
        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        if not self.redis_client:
            # Fallback to in-memory rate limiting
            return self._check_rate_limit_memory(key, max_requests, window_seconds, burst_size)
        
        try:
            current_time = int(time.time())
            window_start = current_time - window_seconds
            
            # Use Redis pipeline for atomic operations
            pipe = self.redis_client.pipeline()
            
            # Remove expired entries
            pipe.zremrangebyscore(key, 0, window_start)
            
            # Count current requests in window
            pipe.zcard(key)
            
            # Add current request timestamp
            pipe.zadd(key, {str(current_time): current_time})
            
            # Set expiration for the key
            pipe.expire(key, window_seconds)
            
            # Execute pipeline
            results = pipe.execute()
            current_count = results[1]
            
            # Check if rate limit exceeded
            if current_count > max_requests:
                return False
            
            return True
            
        except redis.RedisError as e:
            # Fallback to in-memory rate limiting on Redis errors
            print(f"Redis error: {e}. Falling back to in-memory rate limiting.")
            return self._check_rate_limit_memory(key, max_requests, window_seconds, burst_size)
    
    def _check_rate_limit_memory(
        self, 
        key: str, 
        max_requests: int, 
        window_seconds: int,
        burst_size: Optional[int] = None
    ) -> bool:
        """Fallback in-memory rate limiting implementation."""
        # This is a simplified in-memory implementation
        # In production, you might want to use a more sophisticated approach
        current_time = time.time()
        
        # Simple counter-based approach
        if not hasattr(self, '_memory_limits'):
            self._memory_limits = {}
        
        if key not in self._memory_limits:
            self._memory_limits[key] = {
                'count': 0,
                'window_start': current_time
            }
        
        limit_info = self._memory_limits[key]
        
        # Reset window if expired
        if current_time - limit_info['window_start'] > window_seconds:
            limit_info['count'] = 0
            limit_info['window_start'] = current_time
        
        # Check if limit exceeded
        if limit_info['count'] >= max_requests:
            return False
        
        # Increment counter
        limit_info['count'] += 1
        return True
    
    def get_rate_limit_info(self, key: str) -> Dict[str, Any]:
        """Get current rate limit information for a key."""
        if not self.redis_client:
            return {"error": "Redis not available"}
        
        try:
            current_time = int(time.time())
            window_start = current_time - settings.rate_limit_window_seconds
            
            # Remove expired entries and get current count
            pipe = self.redis_client.pipeline()
            pipe.zremrangebyscore(key, 0, window_start)
            pipe.zcard(key)
            pipe.ttl(key)
            
            results = pipe.execute()
            current_count = results[1]
            ttl = results[2]
            
            return {
                "key": key,
                "current_count": current_count,
                "max_requests": settings.rate_limit_max_requests,
                "window_seconds": settings.rate_limit_window_seconds,
                "remaining_requests": max(0, settings.rate_limit_max_requests - current_count),
                "reset_time": current_time + ttl if ttl > 0 else current_time + settings.rate_limit_window_seconds,
                "window_start": window_start,
                "window_end": current_time
            }
            
        except redis.RedisError as e:
            return {"error": f"Redis error: {e}"}
    
    def apply_rate_limiting(
        self, 
        request: Request,
        endpoint: str,
        user_id: Optional[str] = None,
        username: Optional[str] = None
    ) -> bool:
        """
        Apply rate limiting to a request.
        
        Args:
            request: FastAPI request object
            endpoint: API endpoint being accessed
            user_id: Optional user ID for user-based rate limiting
            username: Optional username for user-based rate limiting
            
        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        # Get client IP address
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")
        
        # Create rate limit keys
        ip_key = f"rate_limit:ip:{client_ip}:{endpoint}"
        user_key = None
        if user_id and settings.rate_limit_enable_user_limiting:
            user_key = f"rate_limit:user:{user_id}:{endpoint}"
        
        # Check IP-based rate limiting
        if settings.rate_limit_enable_ip_limiting:
            if not self.check_rate_limit(
                ip_key, 
                settings.rate_limit_max_requests, 
                settings.rate_limit_window_seconds,
                settings.rate_limit_burst_size
            ):
                # Log rate limit violation
                self.audit_service.log_rate_limit_exceeded(
                    user_id, username, client_ip, endpoint, 
                    request.headers.get("x-request-id", "unknown")
                )
                return False
        
        # Check user-based rate limiting
        if user_key and settings.rate_limit_enable_user_limiting:
            if not self.check_rate_limit(
                user_key,
                settings.rate_limit_max_requests,
                settings.rate_limit_window_seconds,
                settings.rate_limit_burst_size
            ):
                # Log rate limit violation
                self.audit_service.log_rate_limit_exceeded(
                    user_id, username, client_ip, endpoint,
                    request.headers.get("x-request-id", "unknown")
                )
                return False
        
        return True
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract the real client IP address from the request."""
        # Check for forwarded headers (common with load balancers)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            # Take the first IP in the chain
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        # Fallback to direct connection IP
        return request.client.host if request.client else "unknown"
    
    def create_rate_limit_response(self, key: str) -> JSONResponse:
        """Create a standardized rate limit exceeded response."""
        limit_info = self.get_rate_limit_info(key)
        
        response_data = {
            "error": "Rate limit exceeded",
            "message": "Too many requests. Please try again later.",
            "rate_limit_info": limit_info
        }
        
        headers = {
            "X-RateLimit-Limit": str(limit_info.get("max_requests", "unknown")),
            "X-RateLimit-Remaining": str(limit_info.get("remaining_requests", "unknown")),
            "X-RateLimit-Reset": str(limit_info.get("reset_time", "unknown")),
            "Retry-After": str(limit_info.get("window_seconds", "unknown"))
        }
        
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content=response_data,
            headers=headers
        )
    
    def cleanup_expired_keys(self) -> int:
        """Clean up expired rate limit keys from Redis."""
        if not self.redis_client:
            return 0
        
        try:
            current_time = int(time.time())
            pattern = "rate_limit:*"
            deleted_count = 0
            
            # Scan for rate limit keys
            cursor = 0
            while True:
                cursor, keys = self.redis_client.scan(
                    cursor=cursor, 
                    match=pattern, 
                    count=100
                )
                
                for key in keys:
                    # Check if key has expired
                    ttl = self.redis_client.ttl(key)
                    if ttl <= 0:
                        self.redis_client.delete(key)
                        deleted_count += 1
                
                if cursor == 0:
                    break
            
            return deleted_count
            
        except redis.RedisError as e:
            print(f"Error cleaning up expired keys: {e}")
            return 0
    
    def get_rate_limit_stats(self) -> Dict[str, Any]:
        """Get overall rate limiting statistics."""
        if not self.redis_client:
            return {"error": "Redis not available"}
        
        try:
            stats = {
                "total_keys": 0,
                "active_limits": 0,
                "expired_limits": 0,
                "endpoint_stats": {}
            }
            
            # Scan for rate limit keys
            pattern = "rate_limit:*"
            cursor = 0
            
            while True:
                cursor, keys = self.redis_client.scan(
                    cursor=cursor, 
                    match=pattern, 
                    count=100
                )
                
                for key in keys:
                    stats["total_keys"] += 1
                    
                    # Parse key to get endpoint information
                    parts = key.split(":")
                    if len(parts) >= 4:
                        limit_type = parts[1]  # ip or user
                        endpoint = parts[3]
                        
                        if endpoint not in stats["endpoint_stats"]:
                            stats["endpoint_stats"][endpoint] = {
                                "ip_limits": 0,
                                "user_limits": 0
                            }
                        
                        if limit_type == "ip":
                            stats["endpoint_stats"][endpoint]["ip_limits"] += 1
                        elif limit_type == "user":
                            stats["endpoint_stats"][endpoint]["user_limits"] += 1
                    
                    # Check if key is active
                    ttl = self.redis_client.ttl(key)
                    if ttl > 0:
                        stats["active_limits"] += 1
                    else:
                        stats["expired_limits"] += 1
                
                if cursor == 0:
                    break
            
            return stats
            
        except redis.RedisError as e:
            return {"error": f"Redis error: {e}"}


# Dependency for getting the rate limit service
def get_rate_limit_service(audit_service: AuditService = Depends()) -> RateLimitService:
    """Get the rate limiting service instance."""
    return RateLimitService(audit_service)
