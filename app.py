"""
Secure Flask Application - hardenedapp
This is the secure counterpart to vulnapp (https://github.com/anshumanbh/vulnapp)

Maintains 100% functional parity while implementing security best practices:
- Argon2id password hashing (replaces MD5)
- CSRF protection on all forms
- Rate limiting on authentication
- Secure session configuration
- Security headers (CSP, X-Frame-Options, etc.)
- Admin-only authorization on role changes
- Object-level authorization on profile access
- Input validation
"""

from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from profile_routes import profile
from database import init_db, get_db, verify_password
from auth import login_required, admin_required, verify_user_access
from validators import LoginSchema, RoleUpdateSchema
from pydantic import ValidationError
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# SECURITY: Load secret key from environment (no hardcoded value)
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key or app.secret_key == 'CHANGEME_GENERATE_RANDOM_SECRET_KEY_64_CHARACTERS_MINIMUM':
    raise ValueError(
        "SECRET_KEY must be set to a secure random value in .env file. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )

# SECURITY: Secure session configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Enable secure cookies in production (requires HTTPS)
app.config['SESSION_COOKIE_SECURE'] = os.getenv('COOKIE_SECURE', 'false').lower() == 'true'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

# SECURITY: CSRF Protection
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = None  # CSRF tokens don't expire within session
csrf = CSRFProtect(app)

# SECURITY: Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)

# Register blueprints
app.register_blueprint(profile)


# SECURITY: Security headers middleware
@app.after_request
def set_security_headers(response):
    """Add comprehensive security headers to all responses."""
    # Content Security Policy - restrict resource loading
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Enable XSS protection (legacy browsers)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Strict Transport Security (HTTPS enforcement in production)
    if app.config['SESSION_COOKIE_SECURE']:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response


@app.route('/')
def index():
    """
    Index page - redirect to dashboard if logged in, otherwise show login.
    Maintains same behavior as vulnapp.
    """
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit(os.getenv('LOGIN_RATE_LIMIT', '5 per minute'))
def login():
    """
    Authentication endpoint.
    
    SECURITY IMPROVEMENTS over vulnapp:
    - Rate limiting to prevent brute force attacks
    - Argon2id password verification (replaces MD5)
    - Input validation
    - Generic error message (no username enumeration)
    """
    if request.method == 'POST':
        # SECURITY: Validate input data
        try:
            credentials = LoginSchema(
                username=request.form.get('username', ''),
                password=request.form.get('password', '')
            )
        except ValidationError as e:
            return render_template('login.html', error="Invalid credentials")
        
        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE username = ?', (credentials.username,)
        ).fetchone()
        
        # SECURITY: Use constant-time comparison via Argon2 verify
        # Generic error message prevents username enumeration
        if user and verify_password(user['password'], credentials.password):
            session['user_id'] = user['id']
            session['role'] = user['role']
            session.permanent = True  # Use permanent session with timeout
            return redirect(url_for('dashboard'))
        
        return render_template('login.html', error="Invalid credentials")
    
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    """
    Dashboard showing user list with role management.
    Maintains same UI/UX as vulnapp.
    
    SECURITY: Role dropdown visibility is UI-only in vulnapp.
    We maintain same UI but enforce authorization on backend (@admin_required on /update_role).
    """
    db = get_db()
    users = db.execute('SELECT id, username, role FROM users').fetchall()
    return render_template('dashboard.html', users=users, current_role=session['role'])


@app.route('/api/user/<int:user_id>')
@login_required
def get_user_details(user_id):
    """
    Get detailed user information via API.
    
    SECURITY FIX: Added object-level authorization.
    In vulnapp, any authenticated user could view any user's details.
    Now users can only view their own details OR must be admin.
    """
    # SECURITY: Verify user has access to this user's data
    if not verify_user_access(user_id):
        return jsonify({"error": "Access denied: You can only view your own information"}), 403
    
    db = get_db()
    user = db.execute(
        'SELECT id, username, role, email, phone, address FROM users WHERE id = ?', 
        (user_id,)
    ).fetchone()
    
    if user:
        return jsonify({
            "id": user['id'],
            "username": user['username'],
            "role": user['role'],
            "email": user['email'],
            "phone": user['phone'],
            "address": user['address']
        })
    return jsonify({"error": "User not found"}), 404


@app.route('/update_role', methods=['POST'])
@login_required
@admin_required  # CRITICAL FIX: Missing in vulnapp - any user could escalate privileges!
def update_role():
    """
    Update user role.
    
    CRITICAL SECURITY FIX: Added @admin_required decorator.
    In vulnapp, this route only had @login_required, allowing privilege escalation.
    Any authenticated user could make themselves admin by POSTing to this endpoint.
    
    Now only admins can change roles.
    """
    # SECURITY: Validate input data
    try:
        data = RoleUpdateSchema(
            user_id=int(request.form.get('user_id', 0)),
            role=request.form.get('role', '')
        )
    except (ValidationError, ValueError) as e:
        return jsonify({"error": "Invalid input"}), 400
    
    db = get_db()
    db.execute(
        'UPDATE users SET role = ? WHERE id = ?',
        (data.role, data.user_id)
    )
    db.commit()
    
    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    """
    Logout endpoint - clear session.
    Maintains same behavior as vulnapp.
    """
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    # Initialize database with secure defaults
    init_db()
    
    # SECURITY: Disable debug mode in production
    debug_mode = os.getenv('FLASK_ENV', 'production') == 'development'
    port = int(os.getenv('FLASK_PORT', 5001))
    host = os.getenv('FLASK_HOST', '127.0.0.1')
    
    if debug_mode:
        print("\n" + "=" * 60)
        print("⚠️  WARNING: Running in DEVELOPMENT mode")
        print("=" * 60)
        print("Debug mode is enabled. Do NOT use in production.")
        print("Set FLASK_ENV=production in .env for production use.")
        print("=" * 60 + "\n")
    
    app.run(debug=debug_mode, port=port, host=host)
