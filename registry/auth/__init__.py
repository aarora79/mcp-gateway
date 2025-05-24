"""
Authentication module for MCP Gateway.

This module implements OAuth 2.1 authentication for MCP Gateway,
allowing integration with external identity providers like AWS Cognito and Okta.
"""

from .provider import CognitoOAuthProvider, ConfigurableIdPAdapter
from .middleware import setup_auth_middleware, requires_scope
from .settings import AuthSettings

__all__ = [
    "CognitoOAuthProvider",
    "ConfigurableIdPAdapter",
    "setup_auth_middleware",
    "requires_scope",
    "AuthSettings",
]