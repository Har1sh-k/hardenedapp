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
from database import init_db, get_db, verify_password, DUMMY_PASSWORD_HASH
from auth import login_required, admin_required, verify_user_access
from validators import LoginSchema, RoleUpdateSchema
from pydantic import ValidationError
from dotenv import load_dotenv
from security_logger import (
    log_auth_success, log_auth_failure, log_auth_logout,
    log_role_change, log_rate_limit, log_security_event
)
import os
import traceback

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
# VULN-004 FIX: Force secure cookies in production, configurable in development
if os.getenv('FLASK_ENV') == 'production':
    app.config['SESSION_COOKIE_SECURE'] = True
else:
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


# VULN-004 FIX: HTTP to HTTPS redirect in production
@app.before_request
def redirect_to_https():
    """Redirect HTTP requests to HTTPS in production."""
    if os.getenv('FLASK_ENV') == 'production':
        # Check if request is not secure (handles both direct and proxy scenarios)
        if not request.is_secure and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)


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
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    
    return response


# VULN-005 FIX: Centralized error handlers
@app.errorhandler(400)
def bad_request(e):
    """Handle 400 Bad Request errors."""
    log_security_event('HTTP_400', f'path={request.path} ip={get_remote_address()}', 'WARNING')
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Bad request'}), 400
    return render_template('login.html', error='Bad request'), 400


@app.errorhandler(401)
def unauthorized(e):
    """Handle 401 Unauthorized errors."""
    log_security_event('HTTP_401', f'path={request.path} ip={get_remote_address()}', 'WARNING')
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Authentication required'}), 401
    return redirect(url_for('login'))


@app.errorhandler(403)
def forbidden(e):
    """Handle 403 Forbidden errors."""
    log_security_event('HTTP_403', f'path={request.path} ip={get_remote_address()} user_id={session.get("user_id")}', 'WARNING')
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Access forbidden'}), 403
    return jsonify({'error': 'Access forbidden'}), 403


@app.errorhandler(404)
def not_found(e):
    """Handle 404 Not Found errors."""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Resource not found'}), 404
    return render_template('login.html', error='Page not found'), 404


@app.errorhandler(429)
def rate_limit_exceeded(e):
    """Handle 429 Too Many Requests (rate limiting)."""
    log_rate_limit(ip_address=get_remote_address(), endpoint=request.path)
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Too many requests. Please try again later.'}), 429
    return render_template('login.html', error='Too many attempts. Please wait before trying again.'), 429


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 Internal Server errors."""
    log_security_event('HTTP_500', f'path={request.path} error={str(e)} ip={get_remote_address()}', 'ERROR')
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('login.html', error='An unexpected error occurred'), 500


@app.errorhandler(Exception)
def handle_exception(e):
    """Global exception handler - catch all unhandled exceptions."""
    # Log full traceback server-side
    log_security_event(
        'UNHANDLED_EXCEPTION',
        f'path={request.path} error={str(e)} ip={get_remote_address()}\n{traceback.format_exc()}',
        'ERROR'
    )
    # Return generic message to user (no sensitive details)
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('login.html', error='An unexpected error occurred'), 500


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
        
        # VULN-009 FIX: Always verify password to prevent timing attacks
        # Use real hash if user exists, dummy hash if not (constant-time)
        password_hash = user['password'] if user else DUMMY_PASSWORD_HASH
        password_valid = verify_password(password_hash, credentials.password)
        
        # Only succeed if BOTH user exists AND password is valid
        if user and password_valid:
            session['user_id'] = user['id']
            session['role'] = user['role']
            session.permanent = True  # Use permanent session with timeout
            log_auth_success(
                username=credentials.username,
                ip_address=get_remote_address(),
                user_agent=request.headers.get('User-Agent')
            )
            return redirect(url_for('dashboard'))
        
        log_auth_failure(
            username=credentials.username,
            ip_address=get_remote_address(),
            reason='invalid_credentials'
        )
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
    
    log_role_change(
        admin_id=session['user_id'],
        target_user_id=data.user_id,
        new_role=data.role,
        ip_address=get_remote_address()
    )
    
    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    """
    Logout endpoint - clear session.
    Maintains same behavior as vulnapp.
    """
    if 'user_id' in session:
        log_auth_logout(
            user_id=session['user_id'],
            ip_address=get_remote_address()
        )
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
