"""
Input validation schemas for secure data handling.
All user inputs must pass through these validators.
"""

from pydantic import BaseModel, Field, field_validator, EmailStr
import re


class LoginSchema(BaseModel):
    """Validate login credentials."""
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1, max_length=128)
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        """Ensure username contains only safe characters."""
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username must contain only letters, numbers, hyphens, and underscores')
        return v


class ProfileUpdateSchema(BaseModel):
    """Validate profile update data."""
    email: EmailStr = Field(..., max_length=100)
    phone: str = Field(..., max_length=20)
    address: str = Field(..., max_length=200)
    
    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v):
        """Validate phone number format."""
        # Remove common formatting characters
        cleaned = re.sub(r'[\s\-\(\)\.]', '', v)
        # Check if it's a valid phone number (digits, optional + prefix)
        if not re.match(r'^\+?[0-9]{7,15}$', cleaned):
            raise ValueError('Invalid phone number format')
        return v
    
    @field_validator('address')
    @classmethod
    def validate_address(cls, v):
        """Ensure address doesn't contain suspicious characters."""
        # Allow letters, numbers, spaces, and common punctuation
        if not re.match(r'^[a-zA-Z0-9\s,.\-#]+$', v):
            raise ValueError('Address contains invalid characters')
        return v


class RoleUpdateSchema(BaseModel):
    """Validate role update requests."""
    user_id: int = Field(..., gt=0)
    role: str = Field(..., min_length=1, max_length=20)
    
    @field_validator('role')
    @classmethod
    def validate_role(cls, v):
        """Ensure role is one of the allowed values."""
        allowed_roles = ['user', 'admin']
        if v not in allowed_roles:
            raise ValueError(f'Role must be one of: {", ".join(allowed_roles)}')
        return v


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password meets security requirements.
    
    Returns:
        tuple: (is_valid, error_message)
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, ""
