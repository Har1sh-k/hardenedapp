"""
Secure profile management API routes.
Implements object-level authorization to fix IDOR vulnerabilities.
"""

from flask import Blueprint, request, jsonify, session
from flask_limiter.util import get_remote_address
from database import get_db
from auth import login_required, verify_user_access
from validators import ProfileUpdateSchema
from pydantic import ValidationError
from security_logger import log_profile_access, log_profile_update, log_authz_failure


profile = Blueprint('profile', __name__)


@profile.route('/api/profile/<int:user_id>', methods=['GET'])
@login_required
def get_profile(user_id):
    """
    Get user profile data.
    
    SECURITY FIX: Added object-level authorization check.
    In vulnapp, any authenticated user could view any profile.
    Now users can only view their own profile OR must be admin.
    
    Args:
        user_id: ID of user whose profile to retrieve
        
    Returns:
        JSON: Profile data or error
    """
    # SECURITY: Verify user has access to this profile
    if not verify_user_access(user_id):
        log_authz_failure(
            user_id=session.get('user_id'),
            resource=f'profile/{user_id}',
            ip_address=get_remote_address(),
            required_role='owner'
        )
        return jsonify({"error": "Access denied: You can only view your own profile"}), 403
    
    db = get_db()
    user = db.execute(
        'SELECT id, username, email, phone, address FROM users WHERE id = ?', 
        (user_id,)
    ).fetchone()
    
    if user:
        log_profile_access(
            user_id=session['user_id'],
            target_user_id=user_id,
            ip_address=get_remote_address()
        )
        return jsonify({
            "id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "phone": user['phone'],
            "address": user['address']
        })
    return jsonify({"error": "Profile not found"}), 404


@profile.route('/api/profile/<int:user_id>/update', methods=['POST'])
@login_required
def update_profile(user_id):
    """
    Update user profile data.
    
    SECURITY FIX: Added object-level authorization check.
    In vulnapp, any authenticated user could modify any profile.
    Now users can only modify their own profile OR must be admin.
    
    Args:
        user_id: ID of user whose profile to update
        
    Returns:
        JSON: Success message or error
    """
    # SECURITY: Verify user has access to modify this profile
    if not verify_user_access(user_id):
        log_authz_failure(
            user_id=session.get('user_id'),
            resource=f'profile/{user_id}/update',
            ip_address=get_remote_address(),
            required_role='owner'
        )
        return jsonify({"error": "Access denied: You can only update your own profile"}), 403
    
    # SECURITY: Validate input data
    try:
        data = ProfileUpdateSchema(
            email=request.form.get('email', ''),
            phone=request.form.get('phone', ''),
            address=request.form.get('address', '')
        )
    except ValidationError as e:
        return jsonify({"error": "Invalid input", "details": e.errors()}), 400
    
    db = get_db()
    db.execute(
        'UPDATE users SET email = ?, phone = ?, address = ? WHERE id = ?',
        (data.email, data.phone, data.address, user_id)
    )
    db.commit()
    
    log_profile_update(
        user_id=session['user_id'],
        target_user_id=user_id,
        fields=['email', 'phone', 'address'],
        ip_address=get_remote_address()
    )
    
    return jsonify({"message": "Profile updated successfully"})
