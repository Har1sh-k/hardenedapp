"""
Authorization security tests for hardenedapp.
Tests admin-only routes and object-level authorization (IDOR prevention).
"""

import pytest


def test_non_admin_cannot_update_role(user_session):
    """
    CRITICAL: Test that non-admin users cannot change roles.
    This was a privilege escalation vulnerability in vulnapp.
    """
    response = user_session.post('/update_role', data={
        'user_id': 2,
        'role': 'admin'
    })
    
    # Should return 403 Forbidden
    assert response.status_code == 403
    assert b'Admin access required' in response.data


def test_admin_can_update_role(admin_session):
    """Test that admin users can successfully update roles."""
    response = admin_session.post('/update_role', data={
        'user_id': 2,
        'role': 'admin'
    }, follow_redirects=False)
    
    # Should redirect to dashboard
    assert response.status_code == 302
    assert '/dashboard' in response.location


def test_user_can_view_own_profile_api(user_session):
    """Test that users can view their own profile via API."""
    response = user_session.get('/api/user/2')
    
    assert response.status_code == 200
    data = response.get_json()
    assert data['id'] == 2
    assert data['username'] == 'user'


def test_user_cannot_view_other_profile_api(user_session):
    """
    CRITICAL: Test IDOR prevention - users cannot view other users' profiles.
    This was a vulnerability in vulnapp.
    """
    response = user_session.get('/api/user/1')  # Try to view admin's profile
    
    assert response.status_code == 403
    assert b'Access denied' in response.data


def test_admin_can_view_any_profile_api(admin_session):
    """Test that admins can view any user's profile."""
    response = admin_session.get('/api/user/2')  # Admin viewing regular user
    
    assert response.status_code == 200
    data = response.get_json()
    assert data['id'] == 2


def test_user_can_view_own_profile_blueprint(user_session):
    """Test that users can view their own profile via profile blueprint."""
    response = user_session.get('/api/profile/2')
    
    assert response.status_code == 200
    data = response.get_json()
    assert data['id'] == 2
    assert 'password' not in data  # Password should never be exposed


def test_user_cannot_view_other_profile_blueprint(user_session):
    """
    CRITICAL: Test IDOR prevention on profile blueprint.
    """
    response = user_session.get('/api/profile/1')  # Try to view admin's profile
    
    assert response.status_code == 403
    assert b'Access denied' in response.data


def test_user_can_update_own_profile(user_session):
    """Test that users can update their own profile."""
    response = user_session.post('/api/profile/2/update', data={
        'email': 'newemail@example.com',
        'phone': '555-1234',
        'address': '789 New Street'
    })
    
    assert response.status_code == 200
    data = response.get_json()
    assert data['message'] == 'Profile updated successfully'


def test_user_cannot_update_other_profile(user_session):
    """
    CRITICAL: Test IDOR prevention on profile updates.
    """
    response = user_session.post('/api/profile/1/update', data={
        'email': 'hacked@evil.com',
        'phone': '666-6666',
        'address': 'Hacker Street'
    })
    
    assert response.status_code == 403
    assert b'Access denied' in response.data


def test_admin_can_update_any_profile(admin_session):
    """Test that admins can update any user's profile."""
    response = admin_session.post('/api/profile/2/update', data={
        'email': 'admin-updated@example.com',
        'phone': '111-2222',
        'address': 'Admin Updated Address'
    })
    
    assert response.status_code == 200
    data = response.get_json()
    assert data['message'] == 'Profile updated successfully'


def test_role_update_requires_valid_role(admin_session):
    """Test that role updates validate the role value."""
    response = admin_session.post('/update_role', data={
        'user_id': 2,
        'role': 'superadmin'  # Invalid role
    })
    
    assert response.status_code == 400
    assert b'Invalid input' in response.data
