#!/bin/bash
# Bash setup script for hardenedapp (Linux/Mac)

echo "===================================================="
echo "  hardenedapp Setup - Secure Counterpart to vulnapp"
echo "===================================================="
echo ""

# Check Python installation
echo "[1/5] Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo "✓ Found: $PYTHON_VERSION"
else
    echo "✗ Python 3 not found. Please install Python 3.8 or higher."
    exit 1
fi

# Create virtual environment
echo ""
echo "[2/5] Creating virtual environment..."
if [ -d "venv" ]; then
    echo "Virtual environment already exists."
else
    python3 -m venv venv
    echo "✓ Virtual environment created"
fi

# Activate virtual environment
echo ""
echo "[3/5] Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo ""
echo "[4/5] Installing dependencies..."
pip install -r requirements.txt
echo "✓ Dependencies installed"

# Setup environment file
echo ""
echo "[5/5] Setting up environment configuration..."
if [ -f ".env" ]; then
    echo ".env file already exists. Skipping..."
else
    cp .env.example .env
    echo "✓ Created .env file from template"
    echo ""
    echo "IMPORTANT: Edit .env file and set secure values!"
    echo "Required changes:"
    echo "  1. Generate a secret key:"
    echo "     python3 -c \"import secrets; print(secrets.token_hex(32))\""
    echo "  2. Set ADMIN_PASSWORD (minimum 12 characters)"
    echo "  3. Set USER_PASSWORD (minimum 12 characters)"
fi

echo ""
echo "===================================================="
echo "  Setup Complete!"
echo "===================================================="
echo ""
echo "Next steps:"
echo "  1. Edit .env file with secure values"
echo "  2. Activate venv: source venv/bin/activate"
echo "  3. Run the application: python3 app.py"
echo "  4. Run tests: pytest tests/ -v"
echo ""
