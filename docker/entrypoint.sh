#!/bin/bash
set -e

# --- Configuration ---
# Get the absolute path of the directory where this script is run from
SCRIPT_DIR="$(pwd)"
VENV_DIR="/app/.venv"
REGISTRY_ENV_FILE="/app/registry/.env"
FININFO_ENV_FILE="/app/servers/fininfo/.env"
REGISTRY_ENV_TEMPLATE="/app/registry/.env.template"
EMBEDDINGS_MODEL_NAME="all-MiniLM-L6-v2"
EMBEDDINGS_MODEL_DIMENSIONS=384
FININFO_ENV_TEMPLATE="/app/servers/fininfo/.env.template"
NGINX_CONF_SRC="/app/docker/nginx_rev_proxy.conf"
NGINX_CONF_DEST="/etc/nginx/conf.d/nginx_rev_proxy.conf"
SSL_CERT_DIR="/etc/ssl/certs"
SSL_KEY_DIR="/etc/ssl/private"
SSL_CERT_PATH="$SSL_CERT_DIR/fullchain.pem"
SSL_KEY_PATH="$SSL_KEY_DIR/privkey.pem"

# --- Helper Functions ---
generate_secret_key() {
  python -c 'import secrets; print(secrets.token_hex(32))'
}

# Function to handle errors
handle_error() {
  echo "ERROR: An error occurred at line $1, exiting..."
  exit 1
}

# Set up error handling
trap 'handle_error $LINENO' ERR

# Install PyJWT with crypto support if needed - required for OAuth
echo "Ensuring required packages for OAuth are installed..."
pip install "pyjwt[crypto]>=2.8.0" "pycognito>=2024.3.1" "boto3>=1.28.0"

# 1. Registry .env
echo "Setting up Registry environment ($REGISTRY_ENV_FILE)..."
# Use provided values or defaults/generated ones
SECRET_KEY_VALUE=${SECRET_KEY:-$(generate_secret_key)}
ADMIN_USER_VALUE=${ADMIN_USER:-admin}

# Check if ADMIN_PASSWORD is set
if [ -z "$ADMIN_PASSWORD" ]; then
  echo "ERROR: ADMIN_PASSWORD environment variable is not set."
  echo "Please set ADMIN_PASSWORD to a secure value before running the container."
  exit 1
fi

ADMIN_PASSWORD_VALUE=${ADMIN_PASSWORD}

# Check if ADMIN_PASSWORD is set when OAuth is enabled
if [ "${MCP_AUTH_ENABLED}" = "true" ] && [ -z "${ADMIN_PASSWORD}" ]; then
  echo "ERROR: ADMIN_PASSWORD environment variable is not set."
  echo "When OAuth is enabled, please set ADMIN_PASSWORD to a secure value before running the container."
  exit 1
fi

# Create .env file for registry
echo "Setting up Registry environment (/app/registry/.env)..."
if [ ! -f /app/registry/.env ]; then
    # Generate a secure random key if not provided
    SECURE_KEY=${SECRET_KEY:-$(python -c 'import secrets; print(secrets.token_hex(32))')}
    
    cat > /app/registry/.env << EOL
SECRET_KEY=${SECURE_KEY}
ADMIN_USER=${ADMIN_USER:-admin}
ADMIN_PASSWORD=${ADMIN_PASSWORD:-password}

# Gateway Configuration
MCP_GATEWAY_DEV_MODE=${MCP_GATEWAY_DEV_MODE:-true}

# OAuth Configuration
MCP_AUTH_ENABLED=${MCP_AUTH_ENABLED:-false}
MCP_AUTH_PROVIDER_TYPE=${MCP_AUTH_PROVIDER_TYPE:-}
MCP_AUTH_CONFIG=${MCP_AUTH_CONFIG:-}

# For Cognito provider
MCP_AUTH_COGNITO_USER_POOL_ID=${MCP_AUTH_COGNITO_USER_POOL_ID:-}
MCP_AUTH_COGNITO_CLIENT_ID=${MCP_AUTH_COGNITO_CLIENT_ID:-}
MCP_AUTH_COGNITO_CLIENT_SECRET=${MCP_AUTH_COGNITO_CLIENT_SECRET:-}
MCP_AUTH_COGNITO_CALLBACK_URI=${MCP_AUTH_COGNITO_CALLBACK_URI:-http://localhost:7860/oauth/callback/cognito}
MCP_AUTH_COGNITO_REGION=${MCP_AUTH_COGNITO_REGION:-us-east-1}

# For Okta provider
MCP_AUTH_OKTA_TENANT_URL=${MCP_AUTH_OKTA_TENANT_URL:-}
MCP_AUTH_OKTA_CLIENT_ID=${MCP_AUTH_OKTA_CLIENT_ID:-}
MCP_AUTH_OKTA_CLIENT_SECRET=${MCP_AUTH_OKTA_CLIENT_SECRET:-}
MCP_AUTH_OKTA_CALLBACK_URI=${MCP_AUTH_OKTA_CALLBACK_URI:-http://localhost:7860/oauth/callback/okta}

# For generic OAuth providers
MCP_AUTH_CLIENT_ID=${MCP_AUTH_CLIENT_ID:-}
MCP_AUTH_CLIENT_SECRET=${MCP_AUTH_CLIENT_SECRET:-}
MCP_AUTH_AUTHORIZE_URL=${MCP_AUTH_AUTHORIZE_URL:-}
MCP_AUTH_TOKEN_URL=${MCP_AUTH_TOKEN_URL:-}
MCP_AUTH_JWKS_URL=${MCP_AUTH_JWKS_URL:-}
MCP_AUTH_CALLBACK_URI=${MCP_AUTH_CALLBACK_URI:-}
MCP_AUTH_SCOPES=${MCP_AUTH_SCOPES:-openid profile email}
MCP_AUTH_AUDIENCE=${MCP_AUTH_AUDIENCE:-}
MCP_AUTH_ISSUER=${MCP_AUTH_ISSUER:-}
EOL
    echo "Registry .env created."
fi

# Create .env file for Fininfo server
echo "Setting up Fininfo server environment (/app/servers/fininfo/.env)..."
if [ ! -f /app/servers/fininfo/.env ]; then
    cat > /app/servers/fininfo/.env << EOL
POLYGON_API_KEY=${POLYGON_API_KEY:-}
EOL
    echo "Fininfo .env created."
fi

# Generate OAuth configuration file if specified
if [ ! -z "$MCP_AUTH_CONFIG_JSON" ]; then
    echo "Generating OAuth configuration file from JSON environment variable..."
    echo "$MCP_AUTH_CONFIG_JSON" > /app/registry/auth_config.json
    export MCP_AUTH_CONFIG="/app/registry/auth_config.json"
    echo "OAuth configuration file created at $MCP_AUTH_CONFIG"
fi

# --- Python Environment Setup ---
echo "Checking for Python virtual environment..."
if [ ! -d "$VENV_DIR" ] || [ ! -f "$VENV_DIR/bin/activate" ]; then
  echo "Setting up Python environment..."
  
  # Install uv if not already installed
  if ! command -v uv &> /dev/null; then
    echo "Installing uv package manager..."
    pip install uv
  fi
  
  # Create virtual environment
  echo "Creating virtual environment..."
  uv venv "$VENV_DIR" --python 3.12
  
  # Install dependencies
  echo "Installing Python dependencies..."
  source "$VENV_DIR/bin/activate"
  uv pip install \
    "fastapi>=0.115.12" \
    "itsdangerous>=2.2.0" \
    "jinja2>=3.1.6" \
    "mcp>=1.6.0" \
    "pydantic>=2.11.3" \
    "httpx>=0.27.0" \
    "python-dotenv>=1.1.0" \
    "python-multipart>=0.0.20" \
    "uvicorn[standard]>=0.34.2" \
    "faiss-cpu>=1.7.4" \
    "sentence-transformers>=2.2.2" \
    "websockets>=15.0.1" \
    "scikit-learn>=1.3.0" \
    "torch>=1.6.0" \
    "huggingface-hub[cli,hf_xet]>=0.31.1" \
    "hf_xet>=0.1.0"
  
  # Install the package itself
  uv pip install -e /app
  
  echo "Python environment setup complete."
else
  echo "Python virtual environment already exists, skipping setup."
fi

# --- SSL Certificate Generation ---
echo "Checking for SSL certificates..."
if [ ! -f "$SSL_CERT_PATH" ] || [ ! -f "$SSL_KEY_PATH" ]; then
  echo "Generating self-signed SSL certificate for Nginx..."
  # Create directories for SSL certs if they don't exist
  mkdir -p "$SSL_CERT_DIR" "$SSL_KEY_DIR"
  # Generate the certificate and key
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout "$SSL_KEY_PATH" \
      -out "$SSL_CERT_PATH" \
      -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=localhost"
  echo "SSL certificate generated."
else
  echo "SSL certificates already exist, skipping generation."
fi

# Configure Nginx
echo "Configuring Nginx..."

# Remove default site to prevent conflicts
rm -f /etc/nginx/sites-enabled/default

# Copy our custom Nginx configuration
# --- Nginx Configuration ---
echo "Copying custom Nginx configuration..."
cp /app/docker/nginx_rev_proxy.conf /etc/nginx/conf.d/nginx_rev_proxy.conf
echo "Nginx configuration copied to /etc/nginx/conf.d/nginx_rev_proxy.conf."

# Ensure proper line endings (convert DOS to Unix if needed)
sed -i 's/\r$//' /etc/nginx/conf.d/nginx_rev_proxy.conf

# --- Model Verification ---
EMBEDDINGS_MODEL_DIR="/app/registry/models/$EMBEDDINGS_MODEL_NAME"
echo "Checking for sentence-transformers model..."
if [ ! -d "$EMBEDDINGS_MODEL_DIR" ] || [ -z "$(ls -A "$EMBEDDINGS_MODEL_DIR")" ]; then
  echo "Downloading sentence-transformers model..."
  mkdir -p "$EMBEDDINGS_MODEL_DIR"
  source "$VENV_DIR/bin/activate"
  
  # Ensure CA certificates are installed for SSL verification
  echo "Ensuring CA certificates are installed..."
  apt-get update && apt-get install -y ca-certificates && update-ca-certificates
  
  # Try standard download method first (more reliable)
  echo "Downloading model using standard method..."
  if huggingface-cli download sentence-transformers/$EMBEDDINGS_MODEL_NAME --local-dir "$EMBEDDINGS_MODEL_DIR" --quiet; then
    echo "Model downloaded successfully using standard method."
  else
    echo "Standard download failed, trying alternative methods..."
    
    # Try with Xet support
    echo "Installing Xet support packages..."
    uv pip install "huggingface-hub[hf_xet]" "hf_xet>=0.1.0" --quiet
    
    # Try with Xet but disable SSL verification if needed
    if ! huggingface-cli download sentence-transformers/$EMBEDDINGS_MODEL_NAME --local-dir "$EMBEDDINGS_MODEL_DIR" --quiet; then
      echo "Trying download with SSL verification disabled..."
      # Set environment variables to disable SSL verification as a last resort
      export CURL_CA_BUNDLE=""
      export SSL_CERT_FILE=""
      huggingface-cli download sentence-transformers/$EMBEDDINGS_MODEL_NAME --local-dir "$EMBEDDINGS_MODEL_DIR" --quiet
    fi
  fi
  
  echo "Model downloaded to $EMBEDDINGS_MODEL_DIR"
else
  echo "Model already exists at $EMBEDDINGS_MODEL_DIR, skipping download."
fi

# --- Start Background Services ---
export EMBEDDINGS_MODEL_NAME=$EMBEDDINGS_MODEL_NAME
export EMBEDDINGS_MODEL_DIMENSIONS=$EMBEDDINGS_MODEL_DIMENSIONS

# Configure Nginx to use configured ports for HTTP and HTTPS
# Use environment variables with sensible defaults
NGINX_HTTP_PORT=${NGINX_HTTP_PORT:-80}
NGINX_HTTPS_PORT=${NGINX_HTTPS_PORT:-443}

# Update Nginx configuration with port settings
sed -i "s/listen 80;/listen $NGINX_HTTP_PORT;/g" /etc/nginx/conf.d/nginx_rev_proxy.conf
sed -i "s/listen 443 ssl;/listen $NGINX_HTTPS_PORT ssl;/g" /etc/nginx/conf.d/nginx_rev_proxy.conf

# Verify Nginx configuration syntax before starting
echo "Testing Nginx configuration..."

# Always use our known-good simplified config
echo "Using simplified default Nginx configuration..."
cat > /etc/nginx/conf.d/nginx_rev_proxy.conf << 'EOL'
# First server block handles HTTP requests
server {
    listen 80;
    server_name localhost;

    # Route for registry service
    location / {
        proxy_pass http://127.0.0.1:7860/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Pass through authentication headers for service-specific tokens
        proxy_pass_request_headers on;
        proxy_set_header X-Service-Auth-Github $http_x_service_auth_github;
        proxy_set_header X-Service-Auth-AWS $http_x_service_auth_aws;
        proxy_set_header X-Service-Auth-Token $http_x_service_auth_token;
    }

    # Only one set of dynamic markers
    # DYNAMIC_LOCATIONS_START
    # Add dynamic locations here
    # DYNAMIC_LOCATIONS_END

    error_log /var/log/nginx/error.log debug;
}

# HTTPS server for clients that prefer it
server {
    listen 443 ssl;
    server_name localhost;

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/fullchain.pem;
    ssl_certificate_key /etc/ssl/private/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    # Duplicate the same location blocks for HTTPS access
    location / {
        proxy_pass http://127.0.0.1:7860/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Pass through authentication headers for service-specific tokens
        proxy_pass_request_headers on;
        proxy_set_header X-Service-Auth-Github $http_x_service_auth_github;
        proxy_set_header X-Service-Auth-AWS $http_x_service_auth_aws;
        proxy_set_header X-Service-Auth-Token $http_x_service_auth_token;
    }
    
    error_log /var/log/nginx/error.log debug;
}
EOL
echo "Created simplified Nginx configuration"

# Test new configuration
if ! nginx -t; then
    echo "FATAL ERROR: Could not create a working Nginx configuration!"
    exit 1
fi

# Update ports in the minimal configuration if it was created
if [ "$NGINX_HTTP_PORT" != "80" ]; then
  sed -i "s/listen 80;/listen $NGINX_HTTP_PORT;/g" /etc/nginx/conf.d/nginx_rev_proxy.conf
fi

if [ "$NGINX_HTTPS_PORT" != "443" ]; then
  sed -i "s/listen 443 ssl;/listen $NGINX_HTTPS_PORT ssl;/g" /etc/nginx/conf.d/nginx_rev_proxy.conf
fi

# Generate SSL certificate if needed
if [ ! -f /etc/ssl/certs/fullchain.pem ] || [ ! -f /etc/ssl/private/privkey.pem ]; then
    echo "Generating self-signed SSL certificate..."
    mkdir -p /etc/ssl/certs /etc/ssl/private
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/privkey.pem \
        -out /etc/ssl/certs/fullchain.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=localhost"
    echo "SSL certificate generated."
fi

# Start the MCP Registry service
echo "Starting MCP Registry in the background..."
cd /app && . /app/.venv/bin/activate && nohup python -m registry.main > /app/logs/registry.log 2>&1 &
REGISTRY_PID=$!
echo "MCP Registry started with PID: $REGISTRY_PID"
sleep 3  # Give registry time to start

# Start example MCP servers with custom ports
echo "Starting example MCP servers in the background with custom ports..."
echo "MCP servers start command issued."
echo "Activating the pre-built virtual environment at /app/.venv..."
source /app/.venv/bin/activate

# Port variables with defaults
SERVER_PORT_CURRENTTIME=${SERVER_PORT_CURRENTTIME:-8001}
SERVER_PORT_FININFO=${SERVER_PORT_FININFO:-8002}
SERVER_PORT_MCPGW=${SERVER_PORT_MCPGW:-8003}

# Start each server on its own port
for server_dir in /app/servers/*; do
    if [ -d "$server_dir" ]; then
        server_name=$(basename "$server_dir")
        # Get the port for this server from environment variable
        port_var="SERVER_PORT_${server_name^^}"  # Uppercase the server name
        server_port=${!port_var:-8000}  # Default to 8000 if not set
        
        echo "Processing directory: $server_dir (port: $server_port, server: $server_name)"
        cd "$server_dir"
        
        # Use the global virtual environment instead of creating individual ones
        # The global venv already has all necessary dependencies installed
        
        if [ -f "pyproject.toml" ]; then
            # Check for README.md file that might be referenced in pyproject.toml
            if ! [ -f "README.md" ] && grep -q 'readme.*=.*"README.md"' pyproject.toml; then
                echo "Creating placeholder README.md for $server_name"
                echo "# $server_name MCP Server" > README.md
            fi
            
            # Install the server package dependencies into the global venv
            echo "Installing dependencies for $server_name in global venv"
            uv pip install -e . 2>&1 || {
                echo "WARNING: Failed to install $server_name as editable package."
                echo "This may cause import issues for the server."
                # Continue anyway since dependencies might already be installed globally
            }
        fi
        
        # Start the server in background
        echo "Starting server on port $server_port (logs in /app/logs/${server_name}_${server_port}.log)..."
        
        # Try to run as module first, fallback to direct file execution if needed
        if python -c "import server" 2>/dev/null; then
            nohup python -m server --port $server_port > /app/logs/${server_name}_${server_port}.log 2>&1 &
        else
            echo "Module 'server' not importable, trying direct file execution"
            nohup python server.py --port $server_port > /app/logs/${server_name}_${server_port}.log 2>&1 &
        fi
        
        echo "Server started with PID: $!"
        echo "-----------------------------------"
        cd /app
    fi
done

# Start Nginx in the foreground (this keeps the container running)
echo "Starting Nginx in the foreground..."
nginx -g "daemon off;"