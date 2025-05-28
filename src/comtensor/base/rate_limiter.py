import time
from collections import defaultdict
from typing import Dict, Tuple
import bittensor as bt

class RateLimiter:
    def __init__(self, max_requests: int = 100, time_window: int = 60):
        """
        Initialize the rate limiter.
        
        Args:
            max_requests: Maximum number of requests allowed in the time window
            time_window: Time window in seconds
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests: Dict[str, list] = defaultdict(list)
        self.blocked_ips: Dict[str, float] = {}
        self.block_duration = 300  # 5 minutes block duration

    def is_rate_limited(self, ip: str) -> Tuple[bool, str]:
        """
        Check if an IP is rate limited.
        
        Args:
            ip: IP address to check
            
        Returns:
            Tuple of (is_limited, reason)
        """
        current_time = time.time()
        
        # Check if IP is blocked
        if ip in self.blocked_ips:
            if current_time - self.blocked_ips[ip] < self.block_duration:
                return True, "IP is blocked due to excessive requests"
            else:
                del self.blocked_ips[ip]
        
        # Clean up old requests
        self.requests[ip] = [t for t in self.requests[ip] if current_time - t < self.time_window]
        
        # Check if IP has exceeded rate limit
        if len(self.requests[ip]) >= self.max_requests:
            self.blocked_ips[ip] = current_time
            return True, "Rate limit exceeded"
        
        # Add new request
        self.requests[ip].append(current_time)
        return False, ""

    def cleanup(self):
        """Clean up old requests and blocked IPs."""
        current_time = time.time()
        
        # Clean up old requests
        for ip in list(self.requests.keys()):
            self.requests[ip] = [t for t in self.requests[ip] if current_time - t < self.time_window]
            if not self.requests[ip]:
                del self.requests[ip]
        
        # Clean up expired blocks
        for ip in list(self.blocked_ips.keys()):
            if current_time - self.blocked_ips[ip] >= self.block_duration:
                del self.blocked_ips[ip]

    def get_request_count(self, ip: str) -> int:
        """Get the current request count for an IP."""
        current_time = time.time()
        self.requests[ip] = [t for t in self.requests[ip] if current_time - t < self.time_window]
        return len(self.requests[ip])

    def reset(self, ip: str):
        """Reset the rate limit for an IP."""
        if ip in self.requests:
            del self.requests[ip]
        if ip in self.blocked_ips:
            del self.blocked_ips[ip] 