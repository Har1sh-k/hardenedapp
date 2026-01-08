"""
Functional parity tests for hardenedapp.
Verifies that hardenedapp provides the same functional surface as vulnapp.
"""

import pytest


def test_all_routes_exist(client, clean_db):
    """Test that all vulnapp routes exist in hardenedapp."""
    # Public routes
    assert client.get('/').status_code in [200, 302]
    assert client.get('/login').status_code == 200
    assert client.get('/logout').status_code == 302
    
    # Login to test protected routes
    client.post('/login', data={
        'username': 'admin',
        'password': 'AdminPass123!'
    })
    
    # Protected routes
    assert client.get('/dashboard').status_code == 200
    assert client.get('/api/user/1').status_code == 200
    assert client.post('/update_role', data={'user_id': 2, 'role': 'user'}).status_code in [200, 302]
    assert client.get('/api/profile/1').status_code == 200
    assert client.post('/api/profile/1/update', data={
        'email': 'test@example.com',
        'phone': '555-1234',
        'address': '123 Main St'
    }).status_code == 200


def test_default_users_exist(client, clean_db):
    """Test that default admin and user accounts exist with correct attributes."""
    # Login as admin
    client.post('/login', data={
        'username': 'admin',
        'password': 'AdminPass123!'
    })
    
    # Check admin user
    response = client.get('/api/user/1')
    assert response.status_code == 200
    data = response.get_json()
    assert data['id'] == 1
    assert data['username'] == 'admin'
    assert data['role'] == 'admin'
    assert data['email'] == 'admin@company.com'
    assert data['phone'] == '123-456-7890'
    assert data['address'] == '123 Admin Street, City, 12345'
    
    # Check regular user
    response = client.get('/api/user/2')
    assert response.status_code == 200
    data = response.get_json()
    assert data['id'] == 2
    assert data['username'] == 'user'
    assert data['role'] == 'user'
    assert data['email'] == 'user@company.com'
    assert data['phone'] == '098-765-4321'
    assert data['address'] == '456 User Avenue, City, 54321'


def test_login_workflow(client, clean_db):
    """Test the complete login workflow matches vulnapp."""
    # GET /login returns form
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Login' in response.data
    
    # POST /login with valid credentials redirects to dashboard
    response = client.post('/login', data={
        'username': 'admin',
        'password': 'AdminPass123!'
    }, follow_redirects=False)
    assert response.status_code == 302
    assert '/dashboard' in response.location
    
    # Verify session was created
    with client.session_transaction() as sess:
        assert sess['user_id'] == 1
        assert sess['role'] == 'admin'


def test_dashboard_workflow(client, clean_db):
    """Test the dashboard displays user list like vulnapp."""
    # Login first
    client.post('/login', data={
        'username': 'admin',
        'password': 'AdminPass123!'
    })
    
    # Access dashboard
    response = client.get('/dashboard')
    assert response.status_code == 200
    
    # Verify UI elements exist
    assert b'User Management Dashboard' in response.data
    assert b'admin' in response.data
    assert b'user' in response.data
    assert b'Logout' in response.data
    assert b'Your role: admin' in response.data


def test_api_user_response_format(admin_session):
    """Test that /api/user/<id> returns same JSON structure as vulnapp."""
    response = admin_session.get('/api/user/1')
    assert response.status_code == 200
    
    data = response.get_json()
    
    # Verify all expected fields are present
    required_fields = ['id', 'username', 'role', 'email', 'phone', 'address']
    for field in required_fields:
        assert field in data, f"Missing field: {field}"
    
    # Verify password is NOT exposed
    assert 'password' not in data


def test_api_profile_response_format(admin_session):
    """Test that /api/profile/<id> returns same JSON structure as vulnapp."""
    response = admin_session.get('/api/profile/1')
    assert response.status_code == 200
    
    data = response.get_json()
    
    # Verify all expected fields are present
    required_fields = ['id', 'username', 'email', 'phone', 'address']
    for field in required_fields:
        assert field in data, f"Missing field: {field}"
    
    # Verify sensitive fields are NOT exposed
    assert 'password' not in data
    assert 'role' not in data  # Role not in profile endpoint (only in user endpoint)


def test_profile_update_response_format(user_session):
    """Test that profile update returns same response as vulnapp."""
    response = user_session.post('/api/profile/2/update', data={
        'email': 'updated@example.com',
        'phone': '555-9999',
        'address': 'New Address'
    })
    
    assert response.status_code == 200
    data = response.get_json()
    assert 'message' in data
    assert data['message'] == 'Profile updated successfully'


def test_logout_workflow(client, clean_db):
    """Test that logout clears session and redirects like vulnapp."""
    # Login first
    client.post('/login', data={
        'username': 'admin',
        'password': 'AdminPass123!'
    })
    
    # Logout
    response = client.get('/logout', follow_redirects=False)
    assert response.status_code == 302
    assert '/login' in response.location
    
    # Verify session cleared
    with client.session_transaction() as sess:
        assert 'user_id' not in sess


def test_index_redirect_when_logged_in(client, clean_db):
    """Test that / redirects to dashboard when logged in."""
    # Login
    client.post('/login', data={
        'username': 'admin',
        'password': 'AdminPass123!'
    })
    
    # Access index
    response = client.get('/', follow_redirects=False)
    assert response.status_code == 302
    assert '/dashboard' in response.location


def test_index_shows_login_when_not_logged_in(client):
    """Test that / shows login form when not logged in."""
    response = client.get('/')
    assert response.status_code == 200
    assert b'Login' in response.data
