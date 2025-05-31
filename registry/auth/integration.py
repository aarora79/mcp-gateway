"""
Integration module for MCP Gateway authentication.

This module provides the integration functions for adding
OAuth 2.1 authentication to the MCP Gateway FastAPI application.
"""
import os
import json
import logging
from typing import Optional

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates

from .middleware import setup_auth_middleware
from .settings import AuthSettings, IdPSettings, ScopeMapping
from .provider import ConfigurableIdPAdapter, CognitoOAuthProvider, OktaOAuthProvider
from .routes import setup_auth_routes

logger = logging.getLogger(__name__)


def integrate_oauth(app: FastAPI, templates: Jinja2Templates) -> Optional[ConfigurableIdPAdapter]:
    """
    Integrate OAuth 2.1 authentication with the MCP Gateway.
    
    This function sets up the authentication middleware, routes, and provider
    for the MCP Gateway FastAPI application based on environment configuration.
    
    Args:
        app: The FastAPI application
        templates: The templates engine
        
    Returns:
        The configured OAuth provider adapter, or None if disabled
    """
    # Check if OAuth is enabled
    enabled = os.environ.get("MCP_AUTH_ENABLED", "").lower() in ("true", "1", "yes")
    if not enabled:
        logger.info("OAuth 2.1 integration is disabled")
        return None
        
    # Check for config file
    config_path = os.environ.get("MCP_AUTH_CONFIG")
    if config_path:
        logger.info(f"Loading OAuth 2.1 configuration from {config_path}")
        return setup_from_config(app, templates, config_path)
        
    # Load configuration from environment variables
    logger.info("Loading OAuth 2.1 configuration from environment variables")
    
    # Determine provider type
    provider_type = os.environ.get("MCP_AUTH_PROVIDER_TYPE", "").lower()
    if not provider_type:
        logger.warning("OAuth 2.1 provider type not specified")
        return None
        
    # Configure the provider based on type
    if provider_type == "cognito":
        return _setup_cognito_from_env(app, templates)
    elif provider_type == "okta":
        return _setup_okta_from_env(app, templates)
    else:
        return _setup_generic_from_env(app, templates, provider_type)


def _setup_cognito_from_env(app: FastAPI, templates: Jinja2Templates) -> Optional[CognitoOAuthProvider]:
    """Set up Cognito OAuth provider from environment variables."""
    user_pool_id = os.environ.get("MCP_AUTH_COGNITO_USER_POOL_ID")
    client_id = os.environ.get("MCP_AUTH_COGNITO_CLIENT_ID")
    client_secret = os.environ.get("MCP_AUTH_COGNITO_CLIENT_SECRET")
    callback_uri = os.environ.get("MCP_AUTH_COGNITO_CALLBACK_URI")
    region = os.environ.get("MCP_AUTH_COGNITO_REGION", "us-east-1")
    custom_domain = os.environ.get("MCP_AUTH_COGNITO_CUSTOM_DOMAIN")
    
    if not all([user_pool_id, client_id, client_secret, callback_uri]):
        logger.warning("Missing required Cognito configuration")
        return None
    
    # Log the configuration for debugging
    logger.info(f"Setting up Cognito with user_pool_id={user_pool_id}, region={region}")
    if custom_domain:
        logger.info(f"Using custom Cognito domain: {custom_domain}")
    
    # Create the Cognito provider with enhanced security
    provider = CognitoOAuthProvider.from_user_pool(
        user_pool_id=user_pool_id,
        client_id=client_id,
        client_secret=client_secret,
        callback_uri=callback_uri,
        region=region,
        custom_domain=custom_domain
    )
    
    # Ensure we don't set audience for Cognito
    if hasattr(provider.settings.idp_settings, 'audience'):
        provider.settings.idp_settings.audience = None
        logger.info("Removed audience parameter for Cognito OAuth flow")
    
    # Set up middleware and routes
    setup_auth_middleware(app, provider, provider.settings)
    setup_auth_routes(app, provider, provider.settings, templates)
    
    logger.info(f"Cognito OAuth provider set up with user pool {user_pool_id}")
    
    return provider


def _setup_okta_from_env(app: FastAPI, templates: Jinja2Templates) -> Optional[OktaOAuthProvider]:
    """Set up Okta OAuth provider from environment variables."""
    tenant_url = os.environ.get("MCP_AUTH_OKTA_TENANT_URL")
    client_id = os.environ.get("MCP_AUTH_OKTA_CLIENT_ID")
    client_secret = os.environ.get("MCP_AUTH_OKTA_CLIENT_SECRET")
    callback_uri = os.environ.get("MCP_AUTH_OKTA_CALLBACK_URI")
    
    if not all([tenant_url, client_id, client_secret, callback_uri]):
        logger.warning("Missing required Okta configuration")
        return None
        
    # Create the provider
    provider = OktaOAuthProvider.from_tenant(
        tenant_url=tenant_url,
        client_id=client_id,
        client_secret=client_secret,
        callback_uri=callback_uri
    )
    
    # Set up middleware and routes
    setup_auth_middleware(app, provider, provider.settings)
    setup_auth_routes(app, provider, provider.settings, templates)
    
    logger.info(f"Okta OAuth provider set up with tenant {tenant_url}")
    
    return provider


def _setup_generic_from_env(app: FastAPI, templates: Jinja2Templates, provider_type: str) -> Optional[ConfigurableIdPAdapter]:
    """Set up a generic OAuth provider from environment variables."""
    client_id = os.environ.get("MCP_AUTH_CLIENT_ID")
    client_secret = os.environ.get("MCP_AUTH_CLIENT_SECRET")
    authorize_url = os.environ.get("MCP_AUTH_AUTHORIZE_URL")
    token_url = os.environ.get("MCP_AUTH_TOKEN_URL")
    jwks_url = os.environ.get("MCP_AUTH_JWKS_URL")
    callback_uri = os.environ.get("MCP_AUTH_CALLBACK_URI")
    
    if not all([client_id, client_secret, authorize_url, token_url, jwks_url, callback_uri]):
        logger.warning(f"Missing required configuration for {provider_type} OAuth provider")
        return None
        
    # Create settings
    settings = AuthSettings()
    settings.idp_settings = IdPSettings(
        provider_type=provider_type,
        client_id=client_id,
        client_secret=client_secret,
        authorize_url=authorize_url,
        token_url=token_url,
        jwks_url=jwks_url,
        callback_uri=callback_uri,
        scopes=os.environ.get("MCP_AUTH_SCOPES", "openid profile email").split(),
        audience=os.environ.get("MCP_AUTH_AUDIENCE"),
        issuer=os.environ.get("MCP_AUTH_ISSUER")
    )
    
    # Create default scope mapping 
    settings.scope_mapping = ScopeMapping(
        idp_to_mcp={
            "admin": ["mcp:registry:admin"],
            "user": ["mcp:registry:read"],
        }
    )
    
    # Set default client ID and secret for client access
    settings.default_client_id = client_id
    settings.default_client_secret = client_secret
    
    # Create the provider
    provider = ConfigurableIdPAdapter(settings)
    
    # Set up middleware and routes
    setup_auth_middleware(app, provider, settings)
    setup_auth_routes(app, provider, settings, templates)
    
    logger.info(f"{provider_type.title()} OAuth provider set up")
    
    return provider


def setup_from_config(app: FastAPI, templates, config_path: Optional[str] = None):
    """
    Set up OAuth 2.1 from a configuration file.
    
    Args:
        app: The FastAPI application
        templates: The templates engine
        config_path: Path to the configuration file
    """
    settings = load_auth_settings(config_path)
    
    if not settings.enabled or not settings.idp_settings:
        logger.info("OAuth 2.1 integration is disabled or not configured")
        return None
        
    # Create the provider based on provider type
    provider_type = settings.idp_settings.provider_type.lower()
    if provider_type == "cognito":
        provider = CognitoOAuthProvider(settings)
    elif provider_type == "okta":
        provider = OktaOAuthProvider(settings)
    else:
        # Generic provider for other IdPs
        provider = ConfigurableIdPAdapter(settings)
        
    # Set up middleware and routes
    setup_auth_middleware(app, provider, settings)
    setup_auth_routes(app, provider, settings, templates)
    
    logger.info(f"OAuth 2.1 set up with {provider_type} provider from config file")
    
    return provider


def load_auth_settings(config_path: str) -> AuthSettings:
    """
    Load authentication settings from a configuration file.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        Authentication settings
    """
    settings = AuthSettings()
    
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
            # Process config
            settings.enabled = config.get("enabled", True)
            
            idp_config = config.get("idp", {})
            if idp_config:
                settings.idp_settings = IdPSettings(
                    provider_type=idp_config.get("provider_type", ""),
                    client_id=idp_config.get("client_id", ""),
                    client_secret=idp_config.get("client_secret", ""),
                    authorize_url=idp_config.get("authorize_url", ""),
                    token_url=idp_config.get("token_url", ""),
                    jwks_url=idp_config.get("jwks_url", ""),
                    callback_uri=idp_config.get("callback_uri", ""),
                    scopes=idp_config.get("scopes", ["openid", "profile", "email"]),
                    audience=idp_config.get("audience"),
                    issuer=idp_config.get("issuer")
                )
                
                # Set default client ID and secret for client access
                settings.default_client_id = idp_config.get("client_id", "")
                settings.default_client_secret = idp_config.get("client_secret", "")
                
            # Process scope mappings
            scope_mapping_config = config.get("scope_mapping", {})
            if scope_mapping_config:
                settings.scope_mapping = ScopeMapping(
                    idp_to_mcp=scope_mapping_config.get("idp_to_mcp", {}),
                    mcp_to_idp=scope_mapping_config.get("mcp_to_idp", {})
                )
            else:
                # Create default scope mapping if none provided
                settings.scope_mapping = ScopeMapping(
                    idp_to_mcp={
                        "admin": ["mcp:registry:admin"],
                        "user": ["mcp:registry:read"],
                    }
                )
                
            # Process scope names
            scopes = config.get("scopes", {})
            if scopes:
                settings.registry_admin_scope = scopes.get(
                    "registry_admin", settings.registry_admin_scope
                )
                settings.registry_read_scope = scopes.get(
                    "registry_read", settings.registry_read_scope
                )
                settings.server_execute_scope_prefix = scopes.get(
                    "server_prefix", settings.server_execute_scope_prefix
                )
                settings.server_execute_scope_suffix = scopes.get(
                    "server_suffix", settings.server_execute_scope_suffix
                )
                
            # Process public routes
            public_routes = config.get("public_routes")
            if public_routes:
                settings.public_routes = public_routes
                
            logger.info(f"Loaded auth settings from {config_path}")
            return settings
            
    except Exception as e:
        logger.error(f"Error loading auth config from {config_path}: {e}")
        raise ValueError(f"Failed to load OAuth configuration from {config_path}: {e}")