#!/bin/bash
set -e

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

# Configure Nginx
echo "Configuring Nginx..."

# Remove default site to prevent conflicts
rm -f /etc/nginx/sites-enabled/default

# Copy our custom Nginx configuration
echo "Copying custom Nginx configuration..."
cp /app/docker/nginx_rev_proxy.conf /etc/nginx/conf.d/nginx_rev_proxy.conf
echo "Nginx configuration copied to /etc/nginx/conf.d/nginx_rev_proxy.conf."

# Ensure proper line endings (convert DOS to Unix if needed)
sed -i 's/\r$//' /etc/nginx/conf.d/nginx_rev_proxy.conf

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
    ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
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
if [ ! -f /etc/ssl/certs/nginx-selfsigned.crt ] || [ ! -f /etc/ssl/private/nginx-selfsigned.key ]; then
    echo "Generating self-signed SSL certificate..."
    mkdir -p /etc/ssl/certs /etc/ssl/private
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/nginx-selfsigned.key \
        -out /etc/ssl/certs/nginx-selfsigned.crt \
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
        
        # Create virtual environment if needed
        uv venv .venv
        source .venv/bin/activate
        
        if [ -f "pyproject.toml" ]; then
            # Check for README.md file that might be referenced in pyproject.toml
            if ! [ -f "README.md" ] && grep -q 'readme.*=.*"README.md"' pyproject.toml; then
                echo "Creating placeholder README.md for $server_name"
                echo "# $server_name MCP Server" > README.md
            fi
            
            # Install the server package
            echo "Installing server package for $server_name"
            uv pip install -e . || {
                echo "WARNING: Failed to install $server_name with uv. Falling back to direct module execution."
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