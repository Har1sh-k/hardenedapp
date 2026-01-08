"""
Input validation tests for hardenedapp.
Tests that all inputs are properly validated and sanitized.
"""

import pytest


def test_profile_update_validates_email(user_session):
    """Test that invalid email formats are rejected."""
    response = user_session.post('/api/profile/2/update', data={
        'email': 'not-an-email',
        'phone': '555-1234',
        'address': '123 Main St'
    })
    
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data


def test_profile_update_validates_phone(user_session):
    """Test that invalid phone numbers are rejected."""
    response = user_session.post('/api/profile/2/update', data={
        'email': 'valid@email.com',
        'phone': 'abc-defg-hijk',  # Invalid phone
        'address': '123 Main St'
    })
    
    assert response.status_code == 400


def test_profile_update_validates_address(user_session):
    """Test that addresses with suspicious characters are rejected."""
    response = user_session.post('/api/profile/2/update', data={
        'email': 'valid@email.com',
        'phone': '555-1234',
        'address': '<script>alert("xss")</script>'  # Malicious input
    })
    
    assert response.status_code == 400


def test_profile_update_accepts_valid_data(user_session):
    """Test that valid profile data is accepted."""
    response = user_session.post('/api/profile/2/update', data={
        'email': 'valid.email@example.com',
        'phone': '+1-555-123-4567',
        'address': '123 Main Street, Apt #5, City, State 12345'
    })
    
    assert response.status_code == 200


def test_role_update_validates_role_value(admin_session):
    """Test that only 'user' and 'admin' roles are accepted."""
    # Test with invalid role
    response = admin_session.post('/update_role', data={
        'user_id': 2,
        'role': 'invalid_role'
    })
    
    assert response.status_code == 400
    
    # Test with valid role
    response = admin_session.post('/update_role', data={
        'user_id': 2,
        'role': 'admin'
    }, follow_redirects=False)
    
    assert response.status_code == 302


def test_role_update_validates_user_id(admin_session):
    """Test that user_id must be a positive integer."""
    response = admin_session.post('/update_role', data={
        'user_id': -1,  # Negative ID
        'role': 'user'
    })
    
    assert response.status_code == 400


def test_login_validates_username_format(client, clean_db):
    """Test that usernames with SQL injection attempts are rejected."""
    response = client.post('/login', data={
        'username': "admin' OR '1'='1",
        'password': 'password'
    })
    
    # Should fail validation and return invalid credentials
    assert b'Invalid credentials' in response.data


def test_phone_number_accepts_various_formats(user_session):
    """Test that phone validation accepts common formats."""
    valid_phones = [
        '555-1234',
        '(555) 123-4567',
        '+1 555 123 4567',
        '5551234567',
        '+15551234567'
    ]
    
    for phone in valid_phones:
        response = user_session.post('/api/profile/2/update', data={
            'email': 'test@example.com',
            'phone': phone,
            'address': '123 Main St'
        })
        
        # All should be accepted (cleaned by validator)
        assert response.status_code == 200, f"Phone {phone} should be valid"
