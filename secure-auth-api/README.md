# Secure API Authentication System

A production-ready, secure API authentication system built with FastAPI that implements JWT tokens, rate limiting, and comprehensive audit logging.

## Features

- **JWT Authentication**: Secure token-based authentication with configurable expiration
- **Rate Limiting**: Per-user and per-endpoint rate limiting with Redis backend
- **Audit Logging**: Comprehensive logging of all authentication events and API calls
- **Password Security**: Bcrypt hashing with configurable rounds
- **Database Security**: SQLAlchemy with parameterized queries
- **Environment Configuration**: Secure configuration management
- **Monitoring**: Built-in security monitoring and alerting

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   API Gateway  │───▶│  Rate Limiting  │───▶│ Authentication  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │   Redis Cache   │    │  Audit Logger   │
                       └──────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │  Business Logic │    │   PostgreSQL    │
                       └──────────────────┘    └─────────────────┘
```

## Quick Start

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Initialize database**:
   ```bash
   alembic upgrade head
   ```

4. **Run the application**:
   ```bash
   uvicorn app.main:app --reload
   ```

## API Endpoints

### Public Endpoints
- `POST /auth/register` - User registration
- `POST /auth/login` - User authentication
- `POST /auth/refresh` - Token refresh

### Protected Endpoints
- `GET /users/me` - Get current user info
- `PUT /users/me` - Update user profile
- `POST /auth/logout` - Logout and invalidate token

## Security Features

- **JWT Security**: RS256 algorithm with configurable expiration
- **Rate Limiting**: Sliding window algorithm with Redis backend
- **Password Hashing**: Bcrypt with 12 rounds
- **Audit Logging**: Structured logging with JSON output
- **Input Validation**: Pydantic models with strict validation
- **SQL Injection Protection**: Parameterized queries only

## Configuration

Key configuration options in `.env`:

```env
# JWT Configuration
JWT_SECRET_KEY=your-secret-key
JWT_ALGORITHM=RS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Rate Limiting
RATE_LIMIT_MAX_REQUESTS=100
RATE_LIMIT_WINDOW_SECONDS=60

# Database
DATABASE_URL=postgresql://user:password@localhost/dbname

# Redis
REDIS_URL=redis://localhost:6379

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
```

## Monitoring and Alerting

The system includes built-in monitoring for:
- Failed authentication attempts
- Rate limit violations
- Suspicious activity patterns
- System performance metrics

## Development

### Running Tests
```bash
pytest
```

### Code Quality
```bash
# Format code
black .
# Lint code
flake8 .
# Type checking
mypy .
```

## Production Deployment

1. **Use HTTPS only** - Configure TLS certificates
2. **Set secure environment variables** - Use secrets management
3. **Configure monitoring** - Set up log aggregation and alerting
4. **Database security** - Use connection pooling and SSL
5. **Rate limiting** - Adjust limits based on your traffic patterns

## Security Considerations

- JWT tokens are stored in HTTP-only cookies
- Passwords are hashed with bcrypt
- Rate limiting prevents brute force attacks
- All authentication events are logged
- Input validation prevents injection attacks
- Database queries use parameterized statements

## License

MIT License - see LICENSE file for details.
