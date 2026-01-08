"""
Pytest configuration and fixtures for testing hardenedapp.
"""

import pytest
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from app import app as flask_app
from database import get_db, hash_password
import sqlite3


@pytest.fixture
def app():
    """Create and configure a test Flask app instance."""
    # Set testing mode
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for easier testing
    flask_app.config['SECRET_KEY'] = 'test-secret-key'
    
    # Use in-memory database for tests
    os.environ['DATABASE_PATH'] = ':memory:'
    
    yield flask_app


@pytest.fixture
def client(app):
    """Create a test client for making requests."""
    return app.test_client()


@pytest.fixture
def clean_db(app):
    """Reset database before each test."""
    with app.app_context():
        db = get_db()
        
        # Drop and recreate users table
        db.execute('DROP TABLE IF EXISTS users')
        db.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            address TEXT
        )
        ''')
        
        # Insert test users
        admin_hash = hash_password('AdminPass123!')
        user_hash = hash_password('UserPass456!')
        
        db.execute(
            'INSERT INTO users (id, username, password, role, email, phone, address) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (1, 'admin', admin_hash, 'admin', 'admin@company.com', '123-456-7890', '123 Admin Street, City, 12345')
        )
        db.execute(
            'INSERT INTO users (id, username, password, role, email, phone, address) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (2, 'user', user_hash, 'user', 'user@company.com', '098-765-4321', '456 User Avenue, City, 54321')
        )
        db.commit()
        
        yield db


@pytest.fixture
def admin_session(client, clean_db):
    """Create a client with admin session authenticated."""
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['role'] = 'admin'
    return client


@pytest.fixture
def user_session(client, clean_db):
    """Create a client with regular user session authenticated."""
    with client.session_transaction() as sess:
        sess['user_id'] = 2
        sess['role'] = 'user'
    return client
