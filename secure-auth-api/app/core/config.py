"""
Core configuration module for the Secure Auth API.
Handles environment variables and application settings.
"""

import os
from typing import List, Optional
from pydantic import BaseSettings, validator, Field
from pydantic.types import SecretStr


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application Configuration
    app_name: str = Field(default="Secure Auth API", env="APP_NAME")
    app_version: str = Field(default="1.0.0", env="APP_VERSION")
    debug: bool = Field(default=False, env="DEBUG")
    environment: str = Field(default="production", env="ENVIRONMENT")
    
    # Server Configuration
    host: str = Field(default="0.0.0.0", env="HOST")
    port: int = Field(default=8000, env="PORT")
    workers: int = Field(default=4, env="WORKERS")
    
    # JWT Configuration
    jwt_secret_key: SecretStr = Field(..., env="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    jwt_access_token_expire_minutes: int = Field(default=30, env="JWT_ACCESS_TOKEN_EXPIRE_MINUTES")
    jwt_refresh_token_expire_days: int = Field(default=7, env="JWT_REFRESH_TOKEN_EXPIRE_DAYS")
    jwt_issuer: str = Field(default="secure-auth-api", env="JWT_ISSUER")
    jwt_audience: str = Field(default="secure-auth-api-users", env="JWT_AUDIENCE")
    
    # Database Configuration
    database_url: str = Field(..., env="DATABASE_URL")
    database_pool_size: int = Field(default=20, env="DATABASE_POOL_SIZE")
    database_max_overflow: int = Field(default=30, env="DATABASE_MAX_OVERFLOW")
    database_pool_timeout: int = Field(default=30, env="DATABASE_POOL_TIMEOUT")
    
    # Redis Configuration
    redis_url: str = Field(default="redis://localhost:6379", env="REDIS_URL")
    redis_db: int = Field(default=0, env="REDIS_DB")
    redis_password: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    redis_max_connections: int = Field(default=20, env="REDIS_MAX_CONNECTIONS")
    
    # Rate Limiting Configuration
    rate_limit_max_requests: int = Field(default=100, env="RATE_LIMIT_MAX_REQUESTS")
    rate_limit_window_seconds: int = Field(default=60, env="RATE_LIMIT_WINDOW_SECONDS")
    rate_limit_burst_size: int = Field(default=10, env="RATE_LIMIT_BURST_SIZE")
    rate_limit_enable_ip_limiting: bool = Field(default=True, env="RATE_LIMIT_ENABLE_IP_LIMITING")
    rate_limit_enable_user_limiting: bool = Field(default=True, env="RATE_LIMIT_ENABLE_USER_LIMITING")
    
    # Security Configuration
    password_min_length: int = Field(default=8, env="PASSWORD_MIN_LENGTH")
    password_require_uppercase: bool = Field(default=True, env="PASSWORD_REQUIRE_UPPERCASE")
    password_require_lowercase: bool = Field(default=True, env="PASSWORD_REQUIRE_LOWERCASE")
    password_require_digits: bool = Field(default=True, env="PASSWORD_REQUIRE_DIGITS")
    password_require_special_chars: bool = Field(default=True, env="PASSWORD_REQUIRE_SPECIAL_CHARS")
    bcrypt_rounds: int = Field(default=12, env="BCRYPT_ROUNDS")
    
    # Logging Configuration
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(default="json", env="LOG_FORMAT")
    log_file_path: Optional[str] = Field(default=None, env="LOG_FILE_PATH")
    log_max_size: str = Field(default="100MB", env="LOG_MAX_SIZE")
    log_backup_count: int = Field(default=5, env="LOG_BACKUP_COUNT")
    
    # Monitoring Configuration
    enable_metrics: bool = Field(default=True, env="ENABLE_METRICS")
    metrics_port: int = Field(default=9090, env="METRICS_PORT")
    health_check_endpoint: str = Field(default="/health", env="HEALTH_CHECK_ENDPOINT")
    
    # CORS Configuration
    cors_allowed_origins: List[str] = Field(default=[], env="CORS_ALLOWED_ORIGINS")
    cors_allowed_methods: List[str] = Field(default=["GET", "POST", "PUT", "DELETE", "OPTIONS"], env="CORS_ALLOWED_METHODS")
    cors_allowed_headers: List[str] = Field(default=["Authorization", "Content-Type", "X-Requested-With"], env="CORS_ALLOWED_HEADERS")
    cors_allow_credentials: bool = Field(default=True, env="CORS_ALLOW_CREDENTIALS")
    
    # Session Configuration
    session_secret_key: SecretStr = Field(..., env="SESSION_SECRET_KEY")
    session_cookie_secure: bool = Field(default=True, env="SESSION_COOKIE_SECURE")
    session_cookie_httponly: bool = Field(default=True, env="SESSION_COOKIE_HTTPONLY")
    session_cookie_samesite: str = Field(default="strict", env="SESSION_COOKIE_SAMESITE")
    session_cookie_max_age: int = Field(default=3600, env="SESSION_COOKIE_MAX_AGE")
    
    # Email Configuration
    smtp_host: Optional[str] = Field(default=None, env="SMTP_HOST")
    smtp_port: Optional[int] = Field(default=None, env="SMTP_PORT")
    smtp_username: Optional[str] = Field(default=None, env="SMTP_USERNAME")
    smtp_password: Optional[SecretStr] = Field(default=None, env="SMTP_PASSWORD")
    smtp_use_tls: bool = Field(default=True, env="SMTP_USE_TLS")
    
    # External Services
    sentry_dsn: Optional[str] = Field(default=None, env="SENTRY_DSN")
    prometheus_endpoint: Optional[str] = Field(default=None, env="PROMETHEUS_ENDPOINT")
    
    @validator('cors_allowed_origins', pre=True)
    def parse_cors_origins(cls, v):
        """Parse CORS origins from comma-separated string."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(',') if origin.strip()]
        return v
    
    @validator('cors_allowed_methods', pre=True)
    def parse_cors_methods(cls, v):
        """Parse CORS methods from comma-separated string."""
        if isinstance(v, str):
            return [method.strip().upper() for method in v.split(',') if method.strip()]
        return v
    
    @validator('cors_allowed_headers', pre=True)
    def parse_cors_headers(cls, v):
        """Parse CORS headers from comma-separated string."""
        if isinstance(v, str):
            return [header.strip() for header in v.split(',') if header.strip()]
        return v
    
    @validator('log_level')
    def validate_log_level(cls, v):
        """Validate log level."""
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f'log_level must be one of {valid_levels}')
        return v.upper()
    
    @validator('jwt_algorithm')
    def validate_jwt_algorithm(cls, v):
        """Validate JWT algorithm."""
        valid_algorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512']
        if v.upper() not in valid_algorithms:
            raise ValueError(f'jwt_algorithm must be one of {valid_algorithms}')
        return v.upper()
    
    @validator('bcrypt_rounds')
    def validate_bcrypt_rounds(cls, v):
        """Validate bcrypt rounds."""
        if not 4 <= v <= 31:
            raise ValueError('bcrypt_rounds must be between 4 and 31')
        return v
    
    @validator('password_min_length')
    def validate_password_min_length(cls, v):
        """Validate password minimum length."""
        if v < 6:
            raise ValueError('password_min_length must be at least 6')
        return v
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get the global settings instance."""
    return settings
