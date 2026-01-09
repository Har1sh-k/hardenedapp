"""
Centralized security logging module.
Provides structured logging for security-relevant events.
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime


def setup_security_logger():
    """
    Configure and return a security-focused logger.
    
    Returns:
        logging.Logger: Configured security logger
    """
    logger = logging.getLogger('security')
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    logger.setLevel(logging.INFO)
    
    # Create logs directory if it doesn't exist
    log_dir = os.getenv('LOG_DIR', 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # File handler with rotation (10MB max, keep 10 backups)
    log_file = os.path.join(log_dir, 'security.log')
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=10
    )
    file_handler.setLevel(logging.INFO)
    
    # Console handler for development
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    
    # Structured format for security events
    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)s | %(event_type)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger


# Initialize the security logger
security_logger = setup_security_logger()


class SecurityLogAdapter(logging.LoggerAdapter):
    """Adapter to add event_type to all log messages."""
    
    def process(self, msg, kwargs):
        kwargs.setdefault('extra', {})
        kwargs['extra']['event_type'] = self.extra.get('event_type', 'GENERAL')
        return msg, kwargs


def get_security_logger(event_type='GENERAL'):
    """Get a logger adapter with specific event type."""
    return SecurityLogAdapter(security_logger, {'event_type': event_type})


def log_auth_success(username: str, ip_address: str, user_agent: str = None):
    """Log successful authentication."""
    logger = get_security_logger('AUTH_SUCCESS')
    logger.info(f"user={username} ip={ip_address} user_agent={user_agent or 'unknown'}")


def log_auth_failure(username: str, ip_address: str, reason: str = 'invalid_credentials'):
    """Log failed authentication attempt."""
    logger = get_security_logger('AUTH_FAILURE')
    logger.warning(f"user={username} ip={ip_address} reason={reason}")


def log_auth_logout(user_id: int, ip_address: str):
    """Log user logout."""
    logger = get_security_logger('AUTH_LOGOUT')
    logger.info(f"user_id={user_id} ip={ip_address}")


def log_authz_failure(user_id: int, resource: str, ip_address: str, required_role: str = None):
    """Log authorization failure."""
    logger = get_security_logger('AUTHZ_FAILURE')
    logger.warning(f"user_id={user_id} resource={resource} ip={ip_address} required_role={required_role or 'owner'}")


def log_role_change(admin_id: int, target_user_id: int, new_role: str, ip_address: str):
    """Log role modification."""
    logger = get_security_logger('ROLE_CHANGE')
    logger.info(f"admin_id={admin_id} target_user_id={target_user_id} new_role={new_role} ip={ip_address}")


def log_profile_access(user_id: int, target_user_id: int, ip_address: str):
    """Log profile data access."""
    logger = get_security_logger('PROFILE_ACCESS')
    logger.info(f"user_id={user_id} target_user_id={target_user_id} ip={ip_address}")


def log_profile_update(user_id: int, target_user_id: int, fields: list, ip_address: str):
    """Log profile data modification."""
    logger = get_security_logger('PROFILE_UPDATE')
    logger.info(f"user_id={user_id} target_user_id={target_user_id} fields={','.join(fields)} ip={ip_address}")


def log_rate_limit(ip_address: str, endpoint: str):
    """Log rate limit violation."""
    logger = get_security_logger('RATE_LIMIT')
    logger.warning(f"ip={ip_address} endpoint={endpoint}")


def log_security_event(event_type: str, message: str, level: str = 'INFO'):
    """Log generic security event."""
    logger = get_security_logger(event_type)
    log_func = getattr(logger, level.lower(), logger.info)
    log_func(message)
