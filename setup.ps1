#!/usr/bin/env pwsh
# PowerShell setup script for hardenedapp (Windows)

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  hardenedapp Setup - Secure Counterpart to vulnapp" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host ""

# Check Python installation
Write-Host "[1/5] Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ Found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Python not found. Please install Python 3.8 or higher." -ForegroundColor Red
    exit 1
}

# Create virtual environment
Write-Host "`n[2/5] Creating virtual environment..." -ForegroundColor Yellow
if (Test-Path "venv") {
    Write-Host "Virtual environment already exists." -ForegroundColor Gray
} else {
    python -m venv venv
    Write-Host "✓ Virtual environment created" -ForegroundColor Green
}

# Activate virtual environment
Write-Host "`n[3/5] Activating virtual environment..." -ForegroundColor Yellow
& .\venv\Scripts\Activate.ps1

# Install dependencies
Write-Host "`n[4/5] Installing dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt
Write-Host "✓ Dependencies installed" -ForegroundColor Green

# Setup environment file
Write-Host "`n[5/5] Setting up environment configuration..." -ForegroundColor Yellow
if (Test-Path ".env") {
    Write-Host ".env file already exists. Skipping..." -ForegroundColor Gray
} else {
    Copy-Item ".env.example" ".env"
    Write-Host "✓ Created .env file from template" -ForegroundColor Green
    Write-Host ""
    Write-Host "IMPORTANT: Edit .env file and set secure values!" -ForegroundColor Red
    Write-Host "Required changes:" -ForegroundColor Yellow
    Write-Host "  1. Generate a secret key:" -ForegroundColor White
    Write-Host "     python -c `"import secrets; print(secrets.token_hex(32))`"" -ForegroundColor Gray
    Write-Host "  2. Set ADMIN_PASSWORD (minimum 12 characters)" -ForegroundColor White
    Write-Host "  3. Set USER_PASSWORD (minimum 12 characters)" -ForegroundColor White
}

Write-Host ""
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Edit .env file with secure values" -ForegroundColor White
Write-Host "  2. Run the application: python app.py" -ForegroundColor White
Write-Host "  3. Run tests: pytest tests/ -v" -ForegroundColor White
Write-Host ""
