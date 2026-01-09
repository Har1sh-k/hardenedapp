"""
Secure database initialization and access layer.
Uses Argon2id for password hashing (replaces vulnapp's MD5).
Supports optional SQLCipher encryption for data at rest.
"""

import sqlite3
import stat
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import os
from dotenv import load_dotenv

load_dotenv()

# Try to import SQLCipher for encrypted database support
try:
    from pysqlcipher3 import dbapi2 as sqlcipher
    SQLCIPHER_AVAILABLE = True
except ImportError:
    SQLCIPHER_AVAILABLE = False

# Initialize Argon2 password hasher with secure defaults
ph = PasswordHasher(
    time_cost=2,        # Number of iterations
    memory_cost=65536,   # Memory usage in KiB (64MB)
    parallelism=1,       # Number of parallel threads
    hash_len=32,         # Length of the hash in bytes
    salt_len=16          # Length of the salt in bytes
)


def get_db():
    """
    Get database connection with row factory for dict-like access.
    Supports optional encryption via SQLCipher when DB_ENCRYPTION_KEY is set.
    
    Returns:
        sqlite3.Connection: Database connection (encrypted if configured)
    """
    db_path = os.getenv('DATABASE_PATH', 'users.db')
    encryption_key = os.getenv('DB_ENCRYPTION_KEY')
    
    # Use encrypted database if key is provided and SQLCipher is available
    if encryption_key and SQLCIPHER_AVAILABLE:
        db = sqlcipher.connect(db_path)
        db.row_factory = sqlcipher.Row
        # Set encryption key (PRAGMA key must be first command)
        db.execute(f"PRAGMA key = '{encryption_key}'")
        # Use SQLCipher 4 defaults
        db.execute("PRAGMA cipher_compatibility = 4")
    elif encryption_key and not SQLCIPHER_AVAILABLE:
        print("WARNING: DB_ENCRYPTION_KEY is set but pysqlcipher3 is not installed.")
        print("         Install with: pip install pysqlcipher3")
        print("         Database will be unencrypted!")
        db = sqlite3.connect(db_path)
        db.row_factory = sqlite3.Row
    else:
        db = sqlite3.connect(db_path)
        db.row_factory = sqlite3.Row
    
    return db


def hash_password(password: str) -> str:
    """
    Hash password using Argon2id.
    
    Args:
        password: Plain text password
        
    Returns:
        str: Hashed password
    """
    return ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """
    Verify password against Argon2 hash.
    
    Args:
        password_hash: Stored Argon2 hash
        password: Plain text password to verify
        
    Returns:
        bool: True if password matches, False otherwise
    """
    try:
        ph.verify(password_hash, password)
        # Check if rehashing is needed (password hasher settings changed)
        if ph.check_needs_rehash(password_hash):
            # In a real application, you'd rehash and update the database here
            pass
        return True
    except VerifyMismatchError:
        return False


def init_db():
    """
    Initialize database with secure defaults.
    Creates users table and seeds with admin and regular user accounts.
    Passwords are loaded from environment variables and must be secure.
    """
    db = get_db()
    
    # Create users table (same schema as vulnapp for parity)
    db.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        address TEXT
    )
    ''')
    
    # Get passwords from environment - NO WEAK DEFAULTS
    admin_password = os.getenv('ADMIN_PASSWORD')
    user_password = os.getenv('USER_PASSWORD')
    
    if not admin_password or not user_password:
        raise ValueError(
            "ADMIN_PASSWORD and USER_PASSWORD must be set in environment variables. "
            "Copy .env.example to .env and set secure passwords."
        )
    
    # Hash passwords with Argon2id (replaces vulnapp's MD5)
    admin_password_hash = hash_password(admin_password)
    user_password_hash = hash_password(user_password)
    
    # Check if users already exist
    existing_admin = db.execute('SELECT id FROM users WHERE id = 1').fetchone()
    
    if not existing_admin:
        try:
            # Insert default users (same IDs and attributes as vulnapp for parity)
            db.execute(
                'INSERT INTO users (id, username, password, role, email, phone, address) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (1, 'admin', admin_password_hash, 'admin', 
                 'admin@company.com', '123-456-7890', '123 Admin Street, City, 12345')
            )
            db.execute(
                'INSERT INTO users (id, username, password, role, email, phone, address) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (2, 'user', user_password_hash, 'user', 
                 'user@company.com', '098-765-4321', '456 User Avenue, City, 54321')
            )
            db.commit()
            print("✓ Database initialized with secure default users")
        except sqlite3.IntegrityError as e:
            print(f"Note: Default users already exist ({e})")
            pass
    else:
        print("✓ Database already initialized")
    
    db.close()
    
    # Set restrictive file permissions on database (owner read/write only)
    db_path = os.getenv('DATABASE_PATH', 'users.db')
    if os.path.exists(db_path):
        try:
            # Set permissions to 600 (owner read/write only)
            os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)
            print(f"✓ Database file permissions set to 600: {db_path}")
        except OSError as e:
            # On Windows, chmod may not work the same way
            print(f"Note: Could not set file permissions on {db_path}: {e}")
    
    # Warn if encryption is not configured for production
    encryption_key = os.getenv('DB_ENCRYPTION_KEY')
    if not encryption_key and os.getenv('FLASK_ENV') == 'production':
        print("⚠️  WARNING: DB_ENCRYPTION_KEY is not set in production!")
        print("   Database file is stored unencrypted. Set DB_ENCRYPTION_KEY for encryption at rest.")
