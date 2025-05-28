from pydantic import BaseModel
from typing import Dict, List, Optional

class SecurityConfig(BaseModel):
    """Security configuration settings."""
    
    # Rate limiting settings
    rate_limit_max_requests: int = 100
    rate_limit_window: int = 60  # seconds
    rate_limit_block_duration: int = 300  # 5 minutes
    
    # Nonce settings
    nonce_expiry: int = 300  # 5 minutes
    
    # Signature verification settings
    min_signature_length: int = 64
    max_signature_length: int = 128
    
    # Blocked IPs and keys
    blocked_ips: List[str] = []
    blocked_hotkeys: List[str] = []
    
    # SSL/TLS settings
    ssl_enabled: bool = True
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None
    
    # API security
    api_key_required: bool = True
    api_key_header: str = "X-API-Key"
    
    # Request validation
    max_request_size: int = 1024 * 1024  # 1MB
    allowed_content_types: List[str] = [
        "application/json",
        "application/x-www-form-urlencoded"
    ]
    
    # Session security
    session_timeout: int = 3600  # 1 hour
    session_cookie_secure: bool = True
    session_cookie_httponly: bool = True
    
    # CORS settings
    cors_enabled: bool = True
    cors_origins: List[str] = ["*"]
    cors_methods: List[str] = ["GET", "POST", "PUT", "DELETE"]
    cors_headers: List[str] = ["*"]
    
    # Logging security
    log_sensitive_data: bool = False
    log_ip_addresses: bool = True
    log_user_agents: bool = True
    
    class Config:
        """Pydantic config."""
        env_prefix = "SECURITY_"
        case_sensitive = False 