"""
Authentication security tests for hardenedapp.
Tests login, logout, session management, and rate limiting.
"""

import pytest


def test_login_with_valid_credentials(client, clean_db):
    """Test successful login with valid admin credentials."""
    response = client.post('/login', data={
        'username': 'admin',
        'password': 'AdminPass123!'
    }, follow_redirects=False)
    
    assert response.status_code == 302  # Redirect
    assert '/dashboard' in response.location


def test_login_with_invalid_password(client, clean_db):
    """Test login fails with incorrect password."""
    response = client.post('/login', data={
        'username': 'admin',
        'password': 'WrongPassword'
    })
    
    assert response.status_code == 200
    assert b'Invalid credentials' in response.data


def test_login_with_invalid_username(client, clean_db):
    """Test login fails with non-existent username."""
    response = client.post('/login', data={
        'username': 'nonexistent',
        'password': 'SomePassword123!'
    })
    
    assert response.status_code == 200
    assert b'Invalid credentials' in response.data


def test_session_created_on_login(client, clean_db):
    """Test that session is created with user_id and role on successful login."""
    client.post('/login', data={
        'username': 'admin',
        'password': 'AdminPass123!'
    })
    
    with client.session_transaction() as sess:
        assert 'user_id' in sess
        assert sess['user_id'] == 1
        assert 'role' in sess
        assert sess['role'] == 'admin'


def test_logout_clears_session(client, clean_db):
    """Test that logout clears the session."""
    # Login first
    client.post('/login', data={
        'username': 'admin',
        'password': 'AdminPass123!'
    })
    
    # Then logout
    response = client.get('/logout', follow_redirects=False)
    
    assert response.status_code == 302
    assert '/login' in response.location
    
    with client.session_transaction() as sess:
        assert 'user_id' not in sess
        assert 'role' not in sess


def test_protected_route_requires_auth(client):
    """Test that accessing dashboard without auth redirects to login."""
    response = client.get('/dashboard', follow_redirects=False)
    
    assert response.status_code == 302
    assert '/login' in response.location


def test_api_route_requires_auth(client):
    """Test that API routes return 401 without authentication."""
    response = client.get('/api/user/1')
    
    assert response.status_code == 401
    assert b'Authentication required' in response.data


def test_login_input_validation(client,clean_db):
    """Test that invalid input formats are rejected."""
    # Test with special characters in username (should fail validation)
    response = client.post('/login', data={
        'username': 'admin\'; DROP TABLE users; --',
        'password': 'AdminPass123!'
    })
    
    assert response.status_code == 200
    assert b'Invalid credentials' in response.data
