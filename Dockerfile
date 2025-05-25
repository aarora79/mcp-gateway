# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set environment variables to prevent interactive prompts during installation
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install minimal system dependencies needed for the container to function
# All Python-related setup moved to entrypoint.sh for a more lightweight image
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

# Set the working directory in the container
WORKDIR /app

# Copy dependency files first to leverage Docker cache
COPY pyproject.toml uv.lock /app/

# Create the shared virtual environment that start_all_servers.sh will use
RUN pip install uv
RUN uv venv /app/.venv --python 3.12

# Install dependencies directly from pyproject.toml
# This installs all dependencies without requiring the actual package code
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
    "boto3>=1.28.0" \
    "requests>=2.32.3"

# Copy the rest of the application
COPY . /app/

# Copy the custom Nginx configuration (will be moved by entrypoint)
# Note: We copy it here so it's part of the image layer
COPY docker/nginx_rev_proxy.conf /app/docker/nginx_rev_proxy.conf

# Make the entrypoint script executable
COPY docker/entrypoint.sh /app/docker/entrypoint.sh
RUN chmod +x /app/docker/entrypoint.sh

# Expose ports for Nginx (HTTP/HTTPS) and the Registry (direct access, though usually proxied)
EXPOSE 80 443 7860

# Define environment variables for registry/server configuration (can be overridden at runtime)
# Provide sensible defaults or leave empty if they should be explicitly set
ARG SECRET_KEY=""
ARG ADMIN_USER="admin"
ARG ADMIN_PASSWORD=""
ARG POLYGON_API_KEY=""
ARG MCP_AUTH_ENABLED="false"
ARG MCP_GATEWAY_DEV_MODE="true"

# Pass build args to runtime environment
ENV SECRET_KEY=$SECRET_KEY
ENV ADMIN_USER=$ADMIN_USER
ENV ADMIN_PASSWORD=$ADMIN_PASSWORD
ENV POLYGON_API_KEY=$POLYGON_API_KEY
ENV MCP_AUTH_ENABLED=$MCP_AUTH_ENABLED
ENV MCP_GATEWAY_DEV_MODE=$MCP_GATEWAY_DEV_MODE

# Run the entrypoint script when the container launches
ENTRYPOINT ["/app/docker/entrypoint.sh"]