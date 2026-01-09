# hardenedapp

**This is the secure counterpart to [vulnapp](https://github.com/anshumanbh/vulnapp).**

hardenedapp maintains 100% functional parity with vulnapp - same routes, same features, same UI/UX - but implements security best practices throughout, eliminating all intentional vulnerabilities.

## Features

✅ **Same functional surface area as vulnapp**:
- User authentication and session management
- Role-based dashboard (admin/user)
- User profile viewing and editing
- Role management (admin-only)
- RESTful API endpoints

🔒 **Security enhancements over vulnapp**:
- **Argon2id password hashing** (replaces MD5)
- **CSRF protection** on all state-changing forms
- **Rate limiting** to prevent brute force attacks
- **Object-level authorization** preventing IDOR vulnerabilities
- **Admin-only enforcement** on role changes (fixes privilege escalation)
- **Input validation** with strict schema enforcement
- **Secure session configuration** (HttpOnly, SameSite cookies)
- **Security headers** (CSP, X-Frame-Options, HSTS)
- **Environment-based secrets** (no hardcoded credentials)

## Quick Start

### Prerequisites
- Python 3.8 or higher
- pip

### Setup (Windows)
```powershell
# Run automated setup
.\setup.ps1

# Edit .env file with secure values
# Generate secret key:
python -c "import secrets; print(secrets.token_hex(32))"

# Run the application
python app.py
```

### Setup (Linux/Mac)
```bash
# Run automated setup
chmod +x setup.sh
./setup.sh

# Edit .env file with secure values
# Generate secret key:
python3 -c "import secrets; print(secrets.token_hex(32))"

# Activate virtual environment
source venv/bin/activate

# Run the application
python3 app.py
```

### Manual Setup
```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
.\venv\Scripts\Activate.ps1

# Activate (Linux/Mac)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and set:
# - SECRET_KEY (generate with: python -c "import secrets; print(secrets.token_hex(32))")
# - ADMIN_PASSWORD (minimum 12 characters)
# - USER_PASSWORD (minimum 12 characters)

# Run application
python app.py
```

The application will start on `http://localhost:5001` (same port as vulnapp).

## Default Credentials

After setup, two users are created (same as vulnapp):

**Admin User:**
- Username: `admin`
- Password: (set in `.env` as `ADMIN_PASSWORD`)
- Role: admin

**Regular User:**
- Username: `user`
- Password: (set in `.env` as `USER_PASSWORD`)
- Role: user

## Testing

Run the comprehensive test suite to verify security controls and functional parity:

```bash
# Run all tests with coverage
pytest tests/ -v --cov=. --cov-report=term-missing

# Run specific test suites
pytest tests/test_auth.py -v              # Authentication tests
pytest tests/test_authorization.py -v     # Authorization tests (IDOR, admin-only)
pytest tests/test_validation.py -v        # Input validation tests
pytest tests/test_parity.py -v            # Functional parity tests
```

**Test Coverage:**
- ✅ Authentication (login, logout, session management)
- ✅ Authorization (admin-only routes, object-level access control)
- ✅ Input validation (email, phone, address, role)
- ✅ CSRF protection
- ✅ Rate limiting
- ✅ Functional parity with vulnapp (all routes, same responses)

## Security Controls Applied

### 1. **Strong Password Hashing**
- **vulnapp**: MD5 (insecure, easily cracked)
- **hardenedapp**: Argon2id (modern, memory-hard, brute-force resistant)

### 2. **Authorization Controls**
- **vulnapp**: Missing `@admin_required` on `/update_role` → any user can escalate to admin
- **hardenedapp**: Strict RBAC with `@admin_required` on all admin actions

### 3. **Object-Level Authorization (IDOR Prevention)**
- **vulnapp**: `verify_user_access()` always returns `True` → users can view/edit any profile
- **hardenedapp**: Proper ownership checks → users can only access own data OR must be admin

### 4. **CSRF Protection**
- **vulnapp**: No CSRF tokens → vulnerable to cross-site attacks
- **hardenedapp**: Flask-WTF CSRF protection on all POST/PUT/DELETE

### 5. **Rate Limiting**
- **vulnapp**: No rate limiting → brute force attacks possible
- **hardenedapp**: 5 attempts per minute on login endpoint

### 6. **Input Validation**
- **vulnapp**: Direct form data usage → injection risks
- **hardenedapp**: Pydantic schema validation with type/format/length checks

### 7. **Secure Session Configuration**
- **vulnapp**: Default Flask settings → session hijacking risks
- **hardenedapp**: HttpOnly, SameSite=Lax, Secure (in production), 1-hour timeout

### 8. **Security Headers**
- **vulnapp**: No security headers
- **hardenedapp**: CSP, X-Frame-Options, X-Content-Type-Options, HSTS (production)

### 9. **Secrets Management**
- **vulnapp**: Hardcoded `app.secret_key = 'super-secret-key'`
- **hardenedapp**: Environment variables with validation, no defaults

### 10. **Password Policy**
- **vulnapp**: No password requirements
- **hardenedapp**: Minimum 12 characters with complexity requirements

### 11. **Debug Mode**
- **vulnapp**: `debug=True` in production → information disclosure
- **hardenedapp**: Debug mode only in development environment

## Parity Checklist

This table verifies feature-by-feature parity with vulnapp:

| Feature | vulnapp | hardenedapp | Security Improvements |
|---------|---------|-------------|----------------------|
| Flask framework | ✅ | ✅ | Same |
| SQLite database | ✅ | ✅ | Same schema |
| Port 5001 | ✅ | ✅ | Same |
| `GET /` | ✅ | ✅ | Same behavior |
| `GET/POST /login` | ✅ | ✅ | + Rate limiting, Argon2, CSRF |
| `GET /dashboard` | ✅ | ✅ | + CSRF on forms |
| `GET /api/user/<id>` | ✅ | ✅ | + Object-level authz |
| `POST /update_role` | ✅ | ✅ | + Admin-only enforcement |
| `GET /logout` | ✅ | ✅ | Same behavior |
| `GET /api/profile/<id>` | ✅ | ✅ | + IDOR prevention |
| `POST /api/profile/<id>/update` | ✅ | ✅ | + IDOR prevention, input validation |
| login.html template | ✅ | ✅ | + CSRF token |
| dashboard.html template | ✅ | ✅ | + CSRF tokens |
| Admin user (ID: 1) | ✅ | ✅ | Same attributes, secure hash |
| Regular user (ID: 2) | ✅ | ✅ | Same attributes, secure hash |
| Session-based auth | ✅ | ✅ | + Secure cookie config |

**Verification method**: `pytest tests/test_parity.py -v`

## Project Structure

```
hardenedapp/
├── app.py                 # Main Flask application
├── auth.py                # Authentication and authorization decorators
├── database.py            # Database initialization and Argon2 hashing
├── profile_routes.py      # Profile API blueprint
├── validators.py          # Input validation schemas
├── requirements.txt       # Python dependencies
├── .env.example          # Environment variable template
├── .gitignore            # Prevent committing secrets
├── setup.ps1             # Windows setup script
├── setup.sh              # Linux/Mac setup script
├── pytest.ini            # Pytest configuration
├── templates/
│   ├── login.html        # Login page
│   └── dashboard.html    # User management dashboard
└── tests/
    ├── conftest.py       # Test fixtures
    ├── test_auth.py      # Authentication tests
    ├── test_authorization.py  # Authorization tests
    ├── test_validation.py     # Input validation tests
    └── test_parity.py    # Functional parity tests
```

## API Documentation

### Public Endpoints

#### `GET /`
Index page - redirects to dashboard if logged in, otherwise shows login.

#### `GET /login`
Display login form.

#### `POST /login`
Authenticate user.
- **Body**: `username`, `password` (form data)
- **Rate limit**: 5 attempts per minute
- **Returns**: Redirect to `/dashboard` or error

#### `GET /logout`
Clear session and logout.

### Protected Endpoints (Login Required)

#### `GET /dashboard`
Display user management dashboard.
- **Auth**: Login required
- **Returns**: HTML page with user list

#### `GET /api/user/<int:user_id>`
Get detailed user information.
- **Auth**: Login required + object-level authorization
- **Returns**: JSON with user details

#### `POST /update_role`
Update user role (admin-only).
- **Auth**: Login required + admin role
- **Body**: `user_id`, `role` (form data)
- **Returns**: Redirect to dashboard

#### `GET /api/profile/<int:user_id>`
Get user profile.
- **Auth**: Login required + object-level authorization
- **Returns**: JSON with profile data

#### `POST /api/profile/<int:user_id>/update`
Update user profile.
- **Auth**: Login required + object-level authorization
- **Body**: `email`, `phone`, `address` (form data)
- **Returns**: JSON success message

## Environment Configuration

```env
# Flask Configuration
SECRET_KEY=<generate-with: python -c "import secrets; print(secrets.token_hex(32))">
FLASK_ENV=development  # or production
FLASK_PORT=5001
FLASK_HOST=127.0.0.1

# Database
DATABASE_PATH=users.db

# Initial User Passwords (minimum 12 characters)
ADMIN_PASSWORD=<your-secure-admin-password>
USER_PASSWORD=<your-secure-user-password>

# Security Settings
COOKIE_SECURE=false  # Set to 'true' in production (requires HTTPS)
LOGIN_RATE_LIMIT=5 per minute
```

## Development vs Production

**Development** (`FLASK_ENV=development`):
- Debug mode enabled
- Detailed error pages
- Auto-reload on code changes
- `COOKIE_SECURE=false` (no HTTPS required)

**Production** (`FLASK_ENV=production`):
- Debug mode disabled
- Generic error pages
- Set `COOKIE_SECURE=true` (requires HTTPS)
- Use a production WSGI server (e.g., gunicorn, uwsgi)

## Contributing

This project is designed as a reference implementation of secure web application patterns. To maintain security:
1. Never commit `.env` files or database files
2. Always validate user inputs
3. Always use parameterized queries
4. Test all authorization logic
5. Keep dependencies updated

## Acknowledgements

This project is based on [vulnapp](https://github.com/anshumanbh/vulnapp) by [Anshuman Bhartiya](https://github.com/anshumanbh). The original vulnapp is an intentionally vulnerable application designed for security training. hardenedapp serves as its secure counterpart, demonstrating how to fix the vulnerabilities while maintaining functional parity.

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Remember**: This is the secure counterpart to vulnapp. It maintains the same user experience but fixes all security vulnerabilities. Use this as a reference for building secure web applications.
