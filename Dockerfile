FROM python:3.12-slim

# Set environment variables to prevent interactive prompts during installation
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install Nginx, curl, and other dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    curl \
    procps \
    openssl \
    git \
    build-essential \
    sudo \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install uv package manager
RUN pip install uv

# Set the working directory
WORKDIR /app

# Copy the pyproject.toml and lock file first (if any) to leverage Docker caching
COPY pyproject.toml uv.lock /app/

# Create a virtual environment
RUN uv venv /app/.venv --python 3.12

# Install dependencies
RUN . /app/.venv/bin/activate && uv pip install \
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
    "huggingface-hub[cli]>=0.31.1" \
    "pyjwt[crypto]>=2.8.0" \
    "pycognito>=2024.3.1" \
    "boto3>=1.28.0"

# Copy the entire project
COPY . /app/

# Install the project in development mode
RUN . /app/.venv/bin/activate && uv pip install -e /app

# Create necessary directories
RUN mkdir -p /app/logs /app/registry/servers /app/registry/models/all-MiniLM-L6-v2

# Download the sentence transformer model
RUN . /app/.venv/bin/activate && python -c "from huggingface_hub import snapshot_download; snapshot_download('sentence-transformers/all-MiniLM-L6-v2', local_dir='/app/registry/models/all-MiniLM-L6-v2')"

# Create self-signed SSL certificate (for development/testing only)
RUN mkdir -p /etc/ssl/private /etc/ssl/certs
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/nginx-selfsigned.key \
    -out /etc/ssl/certs/nginx-selfsigned.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Copy Nginx configurations
COPY docker/nginx_rev_proxy.conf /app/docker/

# Expose ports for HTTP, HTTPS and the Registry
EXPOSE 80 443 7860

# Define environment variables for registry/server configuration (can be overridden at runtime)
# Provide sensible defaults or leave empty if they should be explicitly set
ARG SECRET_KEY=""
ARG ADMIN_USER="admin"
ARG ADMIN_PASSWORD=""
ARG POLYGON_API_KEY=""
ARG MCP_AUTH_ENABLED="false"
ARG MCP_GATEWAY_DEV_MODE="true"

# Server port configuration
ARG SERVER_PORT_CURRENTTIME="8001"
ARG SERVER_PORT_FININFO="8002"
ARG SERVER_PORT_MCPGW="8003"
ARG SERVER_PORT_REALSERVERFAKETOOLS="8004"

# Pass build args to runtime environment
ENV SECRET_KEY=$SECRET_KEY
ENV ADMIN_USER=$ADMIN_USER
ENV ADMIN_PASSWORD=$ADMIN_PASSWORD
ENV POLYGON_API_KEY=$POLYGON_API_KEY
ENV MCP_AUTH_ENABLED=$MCP_AUTH_ENABLED
ENV MCP_GATEWAY_DEV_MODE=$MCP_GATEWAY_DEV_MODE

# Set server ports in environment
ENV SERVER_PORT_CURRENTTIME=$SERVER_PORT_CURRENTTIME
ENV SERVER_PORT_FININFO=$SERVER_PORT_FININFO
ENV SERVER_PORT_MCPGW=$SERVER_PORT_MCPGW
ENV SERVER_PORT_REALSERVERFAKETOOLS=$SERVER_PORT_REALSERVERFAKETOOLS

# Set the entrypoint script
COPY docker/entrypoint.sh /app/docker/entrypoint.sh
RUN chmod +x /app/docker/entrypoint.sh

# Start the services
ENTRYPOINT ["/app/docker/entrypoint.sh"]