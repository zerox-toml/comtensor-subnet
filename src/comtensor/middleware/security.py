from typing import Callable, Optional
from fastapi import Request, Response, HTTPException
from fastapi.middleware.base import BaseHTTPMiddleware
from ..config.security import SecurityConfig
from ..base.security import SecurityManager
from ..base.rate_limiter import RateLimiter
import bittensor as bt

class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        security_config: SecurityConfig,
        security_manager: SecurityManager,
        rate_limiter: RateLimiter
    ):
        super().__init__(app)
        self.config = security_config
        self.security_manager = security_manager
        self.rate_limiter = rate_limiter

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process the request through security checks."""
        try:
            # Get client IP
            client_ip = request.client.host if request.client else "unknown"
            
            # Check if IP is blocked
            if client_ip in self.config.blocked_ips:
                raise HTTPException(status_code=403, detail="IP address is blocked")
            
            # Check rate limiting
            is_limited, reason = self.rate_limiter.is_rate_limited(client_ip)
            if is_limited:
                raise HTTPException(status_code=429, detail=f"Rate limit exceeded: {reason}")
            
            # Check request size
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > self.config.max_request_size:
                raise HTTPException(status_code=413, detail="Request too large")
            
            # Check content type
            content_type = request.headers.get("content-type", "")
            if not any(ct in content_type for ct in self.config.allowed_content_types):
                raise HTTPException(status_code=415, detail="Unsupported content type")
            
            # Check API key if required
            if self.config.api_key_required:
                api_key = request.headers.get(self.config.api_key_header)
                if not api_key:
                    raise HTTPException(status_code=401, detail="API key required")
                # TODO: Implement API key validation
            
            # Process the request
            response = await call_next(request)
            
            # Add security headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            
            if self.config.cors_enabled:
                response.headers["Access-Control-Allow-Origin"] = ", ".join(self.config.cors_origins)
                response.headers["Access-Control-Allow-Methods"] = ", ".join(self.config.cors_methods)
                response.headers["Access-Control-Allow-Headers"] = ", ".join(self.config.cors_headers)
            
            return response
            
        except HTTPException as e:
            # Log security events
            if self.config.log_ip_addresses:
                bt.logging.warning(f"Security event: {e.detail} from IP {client_ip}")
            raise e
        except Exception as e:
            bt.logging.error(f"Security middleware error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

def create_security_middleware(
    app,
    security_config: Optional[SecurityConfig] = None,
    security_manager: Optional[SecurityManager] = None,
    rate_limiter: Optional[RateLimiter] = None
) -> SecurityMiddleware:
    """Create a security middleware instance with default configurations if not provided."""
    if security_config is None:
        security_config = SecurityConfig()
    if security_manager is None:
        security_manager = SecurityManager()
    if rate_limiter is None:
        rate_limiter = RateLimiter(
            max_requests=security_config.rate_limit_max_requests,
            time_window=security_config.rate_limit_window
        )
    
    return SecurityMiddleware(app, security_config, security_manager, rate_limiter) 