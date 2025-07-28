# OIDC Configuration Manager Environment Variables - Windows PowerShell
# =============================================================================

# OIDC Configuration Manager Service
$env:PORT="7468"
$env:GIN_MODE="debug"
$env:LOG_LEVEL="info"
$env:LOG_FORMAT="json"

# Database Configuration
$env:DB_NAME="authfuck"
$env:DB_USER="authsec"
$env:DB_PASSWORD="authsec@kloudone"
$env:DB_HOST="localhost"
$env:DB_PORT="7001"
$env:DB_SCHEMA="public"
$env:DB_SSL_MODE="disable"
$env:MASTER_DB_URL="postgres://authsec:authsec%40kloudone@localhost:7001/authfuck?sslmode=disable"

# Hydra Configuration
$env:HYDRA_ADMIN_URL="http://localhost:4445"
$env:HYDRA_PUBLIC_URL="http://localhost:4444"

# OAuth Login Service
$env:OAUTH_LOGIN_SERVICE_PORT="8080"
$env:OAUTH_LOGIN_SERVICE_URL="http://localhost:8080"
$env:BASE_URL="http://localhost:8080"

# Security & Authentication
$env:SESSION_SECRET="your-32-byte-secret-key-here-change-this-in-production"
$env:JWT_SECRET="your-jwt-secret-key-change-this-in-production"
$env:ENCRYPTION_KEY="your-32-byte-encryption-key-change-this"

# Environment Settings
$env:ENVIRONMENT="development"
$env:DEBUG_MODE="true"
$env:ENABLE_CORS="true"


echo "Environment variables set for Windows environment."

# To run this script, use the command: .\env_ex_local_win.ps1
# Ensure to run it in a PowerShell session with appropriate permissions.
# If needed, run: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser