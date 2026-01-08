"""
Secure authentication and authorization decorators.
Fixes vulnapp's broken verify_user_access() function and implements proper RBAC.
"""

from functools import wraps
from flask import session, jsonify, redirect, url_for


def login_required(f):
    """
    Decorator to require authentication for a route.
    Checks if user_id exists in session.
    
    Args:
        f: Function to decorate
        
    Returns:
        Decorated function that enforces authentication
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # For API routes, return JSON error
            if '/api/' in str(f.__name__) or '/api/' in str(f):
                return jsonify({"error": "Authentication required"}), 401
            # For web routes, redirect to login
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """
    Decorator to require admin role for a route.
    Enforces role-based access control (RBAC).
    
    SECURITY FIX: This decorator was missing from vulnapp's /update_role route,
    allowing any authenticated user to escalate privileges.
    
    Args:
        f: Function to decorate
        
    Returns:
        Decorated function that enforces admin access
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # For API routes, return JSON error
            if '/api/' in str(f.__name__) or '/api/' in str(f):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for('login'))
        
        if 'role' not in session or session['role'] != 'admin':
            # For API routes, return JSON error
            if '/api/' in str(f.__name__) or '/api/' in str(f):
                return jsonify({"error": "Admin access required"}), 403
            # For web routes, return forbidden error  
            return jsonify({"error": "Admin access required"}), 403
        
        return f(*args, **kwargs)
    return decorated_function


def verify_user_access(user_id: int) -> bool:
    """
    Verify if the current user can access the specified user's data.
    
    SECURITY FIX: In vulnapp, this function always returned True,
    creating an IDOR (Insecure Direct Object Reference) vulnerability.
    
    Access is granted if:
    - The user is accessing their own data, OR
    - The user has admin role
    
    Args:
        user_id: ID of the user whose data is being accessed
        
    Returns:
        bool: True if access is allowed, False otherwise
    """
    if 'user_id' not in session:
        return False
    
    # Users can always access their own data
    if session['user_id'] == user_id:
        return True
    
    # Admins can access any user's data
    if session.get('role') == 'admin':
        return True
    
    return False
