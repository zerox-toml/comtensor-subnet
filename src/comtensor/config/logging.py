import logging
import logging.handlers
import os
from datetime import datetime
from typing import Optional
from pathlib import Path

class SecurityLogger:
    """Custom logger for security events."""
    
    def __init__(
        self,
        log_dir: str = "logs",
        log_level: int = logging.INFO,
        max_bytes: int = 10 * 1024 * 1024,  # 10MB
        backup_count: int = 5
    ):
        self.log_dir = Path(log_dir)
        self.log_level = log_level
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        
        # Create log directory if it doesn't exist
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Set up security logger
        self.security_logger = logging.getLogger("security")
        self.security_logger.setLevel(log_level)
        
        # Create handlers
        self._setup_handlers()
    
    def _setup_handlers(self):
        """Set up logging handlers."""
        # File handler for all security events
        security_file = self.log_dir / "security.log"
        file_handler = logging.handlers.RotatingFileHandler(
            security_file,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count
        )
        file_handler.setLevel(self.log_level)
        
        # File handler for critical security events
        critical_file = self.log_dir / "security_critical.log"
        critical_handler = logging.handlers.RotatingFileHandler(
            critical_file,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count
        )
        critical_handler.setLevel(logging.CRITICAL)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(self.log_level)
        
        # Create formatters
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        critical_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s\n'
            'IP: %(ip)s\nUser Agent: %(user_agent)s\n'
            'Request Path: %(path)s\nRequest Method: %(method)s'
        )
        
        # Set formatters
        file_handler.setFormatter(file_formatter)
        critical_handler.setFormatter(critical_formatter)
        console_handler.setFormatter(file_formatter)
        
        # Add handlers to logger
        self.security_logger.addHandler(file_handler)
        self.security_logger.addHandler(critical_handler)
        self.security_logger.addHandler(console_handler)
    
    def log_security_event(
        self,
        level: int,
        message: str,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        path: Optional[str] = None,
        method: Optional[str] = None
    ):
        """Log a security event with additional context."""
        extra = {
            'ip': ip or 'unknown',
            'user_agent': user_agent or 'unknown',
            'path': path or 'unknown',
            'method': method or 'unknown'
        }
        self.security_logger.log(level, message, extra=extra)
    
    def log_attack(
        self,
        message: str,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        path: Optional[str] = None,
        method: Optional[str] = None
    ):
        """Log a security attack attempt."""
        self.log_security_event(
            logging.CRITICAL,
            f"SECURITY ATTACK: {message}",
            ip,
            user_agent,
            path,
            method
        )
    
    def log_rate_limit(
        self,
        ip: str,
        request_count: int,
        path: Optional[str] = None,
        method: Optional[str] = None
    ):
        """Log a rate limit event."""
        self.log_security_event(
            logging.WARNING,
            f"Rate limit exceeded: {request_count} requests from {ip}",
            ip,
            path=path,
            method=method
        )
    
    def log_authentication_failure(
        self,
        ip: str,
        reason: str,
        path: Optional[str] = None,
        method: Optional[str] = None
    ):
        """Log an authentication failure."""
        self.log_security_event(
            logging.WARNING,
            f"Authentication failed: {reason}",
            ip,
            path=path,
            method=method
        )

# Create a default logger instance
security_logger = SecurityLogger() 