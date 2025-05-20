"""
OAuth routes for MCP Gateway.

This module implements the routes required for the OAuth 2.1 flow,
including the login route and callback handler.
"""
import os
import logging
import secrets
from typing import Optional, List
from urllib.parse import urlparse
from datetime import datetime
import jwt

from fastapi import APIRouter, Request, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette import status
from starlette.routing import Route
from pydantic import AnyHttpUrl
from fastapi.responses import HTMLResponse
from itsdangerous import URLSafeTimedSerializer

from mcp.server.auth.routes import create_auth_routes, AUTHORIZATION_PATH, TOKEN_PATH
from mcp.server.auth.provider import TokenError, AuthorizeError, RegistrationError, AuthorizationParams
from .provider import create_authorization_params
from mcp.shared.auth import OAuthMetadata, OAuthClientInformationFull, OAuthClientMetadata

from .provider import ConfigurableIdPAdapter
from .settings import AuthSettings

logger = logging.getLogger(__name__)

# Create a router for auth routes
router = APIRouter(tags=["auth"])

# Global storage for OAuth state
OAUTH_STATE_STORAGE = {}

# Global variables to store provider, settings, and templates
# These will be set by setup_auth_routes
_provider = None
_settings = None
_templates = None


def setup_auth_routes(app, provider: ConfigurableIdPAdapter, settings: AuthSettings, templates: Jinja2Templates):
    """
    Set up authentication routes for the application.
    
    Args:
        app: The FastAPI application
        provider: The OAuth provider adapter
        settings: Authentication settings
        templates: The templates engine
    """
    # Store globals for route handlers
    global _provider, _settings, _templates
    _provider = provider
    _settings = settings
    _templates = templates
    
    # Add standard OAuth routes using the SDK helper
    if settings.enabled and settings.idp_settings:
        base_url = os.environ.get("MCP_AUTH_BASE_URL", "http://localhost:7860")
        issuer_url = AnyHttpUrl(base_url)
        
        # Create standard OAuth routes
        sdk_routes = create_auth_routes(
            provider=provider,
            issuer_url=issuer_url,
            service_documentation_url=None,
            client_registration_options=None,
            revocation_options=None
        )
        
        # Add these routes to the application
        for route in sdk_routes:
            app.routes.append(route)
    
    # Add custom routes
    app.include_router(router)

@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, error: Optional[str] = None):
    """Render the login page with OAuth option."""
    # Create the response with the login template
    response = _templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": error,
            "oauth_enabled": _settings.enabled if _settings else False,
            "provider_type": _settings.idp_settings.provider_type if _settings and _settings.enabled and _settings.idp_settings else None,
            "timestamp": datetime.now().timestamp(),
        }
    )
    
    # Add cache control headers to prevent browsers from caching the login page
    # This helps prevent automatic login after logout
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response


@router.get("/oauth/login")
async def oauth_login(request: Request, t: str = None):
    """
    Initiate the OAuth flow by redirecting to the IdP.
    The 't' parameter is a timestamp for cache busting - used for state generation.
    """
    if not _settings or not _provider or not _settings.enabled or not _settings.idp_settings:
        raise AuthorizeError(
            error="server_error",
            error_description="OAuth is not enabled or not configured properly"
        )
    
    # Ensure we always have a timestamp parameter for cache-busting
    timestamp = t if t else str(int(datetime.now().timestamp()))
    logger.info(f"OAuth login initiated with timestamp: {timestamp}")
        
    # Create a simple client for the OAuth flow
    client_id = _settings.idp_settings.client_id
    callback_uri = _settings.idp_settings.callback_uri
    
    # Generate a completely unique callback URI with current timestamp
    # This ensures the browser cannot reuse a cached redirect
    if "?" not in callback_uri:
        callback_uri = f"{callback_uri}?t={timestamp}&r={secrets.token_hex(8)}"
    else:
        callback_uri = f"{callback_uri}&t={timestamp}&r={secrets.token_hex(8)}"
    
    logger.info(f"Generated callback URI with cache busting: {callback_uri}")
    
    # Create OAuth client information
    client = OAuthClientInformationFull(
        client_id=client_id,
        client_secret=_settings.idp_settings.client_secret,
        redirect_uris=[callback_uri],
        client_metadata=OAuthClientMetadata(
            client_name="MCP Gateway",
            client_uri=os.environ.get("MCP_AUTH_BASE_URL", "http://localhost:7860"),
            redirect_uris=[callback_uri]
        )
    )
    
    # Create completely unique state with timestamp and random token
    # This makes each OAuth flow unique and prevents browser caching
    unique_state = f"{secrets.token_hex(16)}_{timestamp}_{secrets.token_hex(8)}"
    
    # Create base params with unique state and additional parameters
    params = AuthorizationParams(
        redirect_uri=callback_uri,
        scopes=_settings.idp_settings.scopes or [],
        state=unique_state,
        code_challenge=secrets.token_hex(32),  
        redirect_uri_provided_explicitly=True,
        # Add prompt=login to force re-authentication even if already logged in
        extra_params={"prompt": "login"}
    )
    
    # Get the authorization URL - our implementation will handle PKCE internally
    auth_url = await _provider.authorize(client, params)
    
    # Log the full authorization URL for debugging
    logger.info(f"Generated authorization URL: {auth_url}")
    
    # Redirect to the IdP's authorization page with strong no-cache headers
    response = RedirectResponse(url=auth_url, status_code=status.HTTP_303_SEE_OTHER)
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Clear-Site-Data'] = '"cookies", "storage"'
    return response


@router.get("/oauth/callback")
async def oauth_callback(request: Request, code: str = None, state: str = None):
    """Handle the callback from the IdP."""
    logger.info(f"OAuth callback received with code={code is not None}, state={state[:10] if state else None}")
    
    if not code or not state:
        # Use StandardError format from SDK
        raise AuthorizeError(
            error="invalid_request",
            error_description="Missing code or state parameter"
        )
    
    if not _settings or not _provider:
        raise AuthorizeError(
            error="server_error",
            error_description="OAuth is not configured properly"
        )
        
    try:
        # Process the callback using the SDK
        try:
            # Step 1: Get redirect URL and auth code
            # The provider's handle_external_callback method will do the exchange
            redirect_url = "/"
            auth_code = None
            
            # Try to process with the provider with improved logging and error handling
            try:
                logger.info(f"Calling provider.handle_external_callback with code length: {len(code) if code else 0}, state: {state[:10] if state else None}")
                
                # Get the result from the provider
                redirect_result = await _provider.handle_external_callback(code, state, request)
                
                # Log the received result type for debugging
                logger.info(f"Received result from handle_external_callback: type={type(redirect_result)}")
                
                # Properly handle the tuple result
                if isinstance(redirect_result, tuple) and len(redirect_result) == 2:
                    redirect_url, auth_code = redirect_result
                    logger.info(f"Successfully unpacked redirect_url: {redirect_url} and auth_code: {auth_code}")
                elif isinstance(redirect_result, str):
                    # If we got just a string (the redirect URL), use that
                    redirect_url = redirect_result
                    # Create a new auth code
                    auth_code = secrets.token_hex(16)
                    logger.info(f"Got redirect URL string only, generated auth_code: {auth_code}")
                else:
                    # This should not happen with the fixed provider code
                    logger.error(f"Unexpected result type from handle_external_callback: {type(redirect_result)}")
                    raise ValueError(f"Expected tuple or string result from handle_external_callback, got {type(redirect_result)}")
            except Exception as e:
                # Log the error with full traceback and raise it - no fallback
                logger.error(f"Error in handle_external_callback: {e}", exc_info=True)
                raise
        
            # Step 2: Get the auth code object (if it exists)
            auth_code_obj = _provider._auth_codes.get(auth_code)
            
            # Step 3: Extract user information from token with enhanced logging
            user_info = {"name": None, "email": ""}
            
            # If we have an auth code object with an external code, use it to get the token
            if auth_code_obj and hasattr(auth_code_obj, 'external_code'):
                try:
                    # Get the external token with detailed logging
                    logger.info(f"Attempting to exchange auth code for token using external_code")
                    token_data = await _provider._exchange_code_with_idp(auth_code_obj.external_code, auth_code_obj)
                    logger.info(f"Token exchange successful. Token data keys: {list(token_data.keys())}")
                    
                    # Extract user identity from token with detailed logging
                    if 'id_token' in token_data:
                        logger.info("ID token found in token data, attempting to decode")
                        try:
                            id_token_claims = jwt.decode(
                                token_data['id_token'], 
                                options={"verify_signature": False}
                            )
                            logger.info(f"JWT decoded successfully. Available claims: {list(id_token_claims.keys())}")
                            
                            # Extract user identity information with detailed logging
                            if 'cognito:username' in id_token_claims:
                                user_info['name'] = id_token_claims['cognito:username']
                                logger.info(f"Using 'cognito:username' claim: {user_info['name']}")
                                
                                # Extract Cognito groups if available - but don't store them yet
                                if 'cognito:groups' in id_token_claims and isinstance(id_token_claims['cognito:groups'], list):
                                    groups = id_token_claims['cognito:groups']
                                    logger.info(f"Found Cognito groups in token: {groups}")
                            elif 'preferred_username' in id_token_claims:
                                user_info['name'] = id_token_claims['preferred_username']
                                logger.info(f"Using 'preferred_username' claim: {user_info['name']}")
                            elif 'name' in id_token_claims:
                                user_info['name'] = id_token_claims['name']
                                logger.info(f"Using 'name' claim: {user_info['name']}")
                            elif 'email' in id_token_claims:
                                user_info['name'] = id_token_claims['email']
                                user_info['email'] = id_token_claims['email']
                                logger.info(f"Using 'email' claim: {user_info['name']}")
                            else:
                                # Log all available claims to help diagnose issues
                                logger.error(f"No usable identity claims found in token. Available claims: {list(id_token_claims.keys())}")
                                raise ValueError("No usable identity claims found in token")
                                
                            logger.info(f"Successfully extracted user identity: {user_info['name']}")
                        except Exception as e:
                            logger.error(f"Error decoding ID token: {e}", exc_info=True)
                            raise  # Re-raise to prevent fallback to default user
                    else:
                        logger.error(f"No ID token found in token data. Available keys: {list(token_data.keys())}")
                        raise ValueError("No ID token found in token data")
                except Exception as e:
                    logger.error(f"Error exchanging auth code for token: {e}", exc_info=True)
                    raise  # Re-raise to prevent fallback to default user
            else:
                logger.error("No auth_code_obj available or missing external_code attribute")
                raise ValueError("Cannot proceed without valid authorization code")
                
            # Ensure we have a valid user name
            if not user_info['name']:
                logger.error("Failed to extract user identity from token")
                raise ValueError("Failed to extract user identity from token")
            
            # Step 4: Create HTML response
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Authenticated - Redirecting...</title>
                <meta http-equiv="refresh" content="1;url=/" />
                <style>
                    body {{ 
                        font-family: Arial, sans-serif; 
                        text-align: center; 
                        margin-top: 50px;
                        background-color: #f5f5f5;
                    }}
                    .container {{
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 20px;
                        background-color: white;
                        border-radius: 8px;
                        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    }}
                    h1 {{ color: #4CAF50; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Authentication Successful</h1>
                    <p>Welcome, {user_info['name']}! You have been authenticated successfully.</p>
                    <p>Redirecting to the dashboard...</p>
                    <p>If you are not redirected automatically, <a href="/">click here</a>.</p>
                </div>
            </body>
            </html>
            """
            
            # Use HTMLResponse instead of RedirectResponse
            response = HTMLResponse(content=html_content, status_code=200)


            # Step 5: Set up the session cookie
            secret_key = os.environ.get("SECRET_KEY", "insecure-default-key-for-testing-only")
            signer = URLSafeTimedSerializer(secret_key)
            session_cookie_name = "mcp_gateway_session"
            session_max_age = 60 * 60 * 8  # 8 hours
            
            # Create session data with actual username and groups
            session_data = {
                "username": user_info['name'],  # Use the actual username from token claims
                "oauth_code": auth_code,
                "is_oauth": True,
                "email": user_info.get('email', '')
            }
            
            # Store Cognito groups in session if available
            if 'cognito:groups' in id_token_claims and isinstance(id_token_claims['cognito:groups'], list):
                session_data["groups"] = id_token_claims['cognito:groups']
                logger.info(f"Storing Cognito groups in session: {id_token_claims['cognito:groups']}")
            
            # Serialize the session data
            serialized_session = signer.dumps(session_data)
            
            # Set the session cookie
            logger.info(f"Setting session cookie {session_cookie_name} with data length: {len(serialized_session)} for user {user_info['name']}")
            response.set_cookie(
                key=session_cookie_name,
                value=serialized_session,
                max_age=session_max_age,
                httponly=True,
                path="/",  # Ensure the cookie is accessible across all paths
                samesite="lax"
            )
            
            # Log to confirm cookie was set
            logger.info(f"Session cookie set. Response headers: {response.headers}")
            
            return response
            
        except AuthorizeError as ae:
            # Pass through SDK AuthorizeError with proper OAuth error format
            logger.error(f"OAuth authorization error: {ae.error} - {ae.error_description}")
            return RedirectResponse(
                url=f"/login?error={ae.error}&error_description={ae.error_description}",
                status_code=status.HTTP_303_SEE_OTHER
            )
        except TokenError as te:
            # Handle SDK TokenError with proper OAuth error format
            logger.error(f"OAuth token error: {te.error} - {te.error_description}")
            return RedirectResponse(
                url=f"/login?error={te.error}&error_description={te.error_description}",
                status_code=status.HTTP_303_SEE_OTHER
            )
    except Exception as e:
        # Convert generic exceptions to standard OAuth server_error
        logger.error(f"Error handling OAuth callback: {e}")
        return RedirectResponse(
            url=f"/login?error=server_error&error_description={str(e)}",
            status_code=status.HTTP_303_SEE_OTHER
        )


@router.get("/oauth/callback/{provider}")
async def provider_callback(request: Request, provider: str, code: str = None, state: str = None):
    """Handle callbacks for specific providers."""
    # Log detailed information to debug session issues
    logger.info(f"Provider callback received for {provider}. Code length: {len(code) if code else 0}, State: {state[:10] if state else None}")
    logger.info(f"Provider callback URL: {request.url}")
    logger.info(f"Provider callback query params: {request.query_params}")
    
    try:
        # Forward to the main callback handler
        response = await oauth_callback(request, code, state)
        # Log the response details to debug cookie issues
        logger.info(f"Callback completed. Response status: {response.status_code}, Headers: {response.headers}")
        return response
    except Exception as e:
        logger.error(f"Exception in provider callback: {str(e)}", exc_info=True)
        # Return a more detailed error for debugging
        return RedirectResponse(
            url=f"/login?error=callback_error&error_description=Provider+callback+error:+{str(e)}",
            status_code=status.HTTP_303_SEE_OTHER
        )