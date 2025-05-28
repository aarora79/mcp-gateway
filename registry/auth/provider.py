"""
OAuth 2.1 provider adapters for MCP Gateway.

This module implements the OAuthAuthorizationServerProvider interface from
the MCP Python SDK, delegating authentication to external identity providers.
"""
import json
import time
import os
import secrets
import urllib.parse
from typing import Dict, List, Optional, Any, Tuple
import logging
import hashlib
import base64
import httpx
import jwt
from fastapi import Request

from mcp.server.auth.provider import (
    OAuthAuthorizationServerProvider,
    AuthorizationParams,
    AuthorizationCode,
    RefreshToken,
    AccessToken,
    TokenError,
    AuthorizeError,
    RegistrationError
)
from mcp.shared.auth import (
    OAuthClientInformationFull,
    OAuthToken,
)

from .settings import IdPSettings, AuthSettings, ScopeMapping

logger = logging.getLogger(__name__)

def generate_pkce_pair():
    """Generate a PKCE code_verifier and code_challenge pair following SDK standards.
    
    Returns:
        tuple: A tuple containing (code_verifier, code_challenge)
    """
    # Generate a secure random string for the code verifier
    code_verifier = secrets.token_urlsafe(43)  # 43 bytes → ≈ 58 characters
    
    # Create code challenge with S256 method
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip("=")
    
    return code_verifier, code_challenge


def create_authorization_params(
    redirect_uri: str,
    scopes: List[str] = None,
    state: str = None,
    code_challenge_method: str = "S256"
) -> AuthorizationParams:
    """
    Create AuthorizationParams for OAuth flows.
    
    Args:
        redirect_uri: The callback URI for the authorization flow
        scopes: List of requested scopes (optional)
        state: State parameter for the flow (generated if not provided)
        code_challenge_method: PKCE code challenge method
        
    Returns:
        Properly configured AuthorizationParams
    """
    if state is None:
        state = secrets.token_hex(16)
        
    # Generate PKCE code verifier and challenge using SDK-compatible method
    code_verifier, code_challenge = generate_pkce_pair()
    
    # Create parameters object with SDK's expected format
    params = AuthorizationParams(
        redirect_uri=redirect_uri,
        scopes=scopes or [],
        state=state,
        code_challenge=code_challenge,
        redirect_uri_provided_explicitly=True,
    )
    
    # Store code_verifier as a custom attribute
    # We need this later but the SDK doesn't have it on AuthorizationParams
    setattr(params, "code_verifier", code_verifier)
    setattr(params, "code_challenge_method", "S256")  # Always use S256 for security
    
    return params


class MCP_AuthCode(AuthorizationCode):
    """Authorization code for tracking the external IdP code flow."""
    external_code: Optional[str] = None
    state: Optional[str] = None


class MCP_AccessToken(AccessToken):
    """Access token with JWT-specific fields."""
    id_token: Optional[str] = None
    raw_claims: Optional[Dict[str, Any]] = None


class ConfigurableIdPAdapter(OAuthAuthorizationServerProvider[MCP_AuthCode, RefreshToken, MCP_AccessToken]):
    """
    Generic OAuth provider adapter for external identity providers.
    Supports any OAuth 2.1 compliant provider including Cognito, Okta, etc.
    """
    
    def __init__(self, settings: AuthSettings):
        self.settings = settings
        self.idp_settings = settings.idp_settings
        
        # State tracking
        self._state_mapping = {}  # Maps external state to client request details
        self._auth_codes = {}     # Maps MCP auth codes to AuthCode objects
        self._access_tokens = {}  # Maps access tokens to token info
        self._refresh_tokens = {} # Maps refresh tokens to token info
        self._clients = {}        # Maps client IDs to client information
        
    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Generate an authorization URL for the external IdP."""
        if not self.idp_settings:
            raise AuthorizeError(
                error="server_error",
                error_description="Identity provider not configured"
            )
        
        # Generate state for tracking this request
        state = secrets.token_hex(16)
        
        # Generate PKCE code verifier and challenge
        code_verifier, code_challenge = generate_pkce_pair()
        
        # Add logging for the timestamp-modified state from oauth_login
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"OAuth authorize - Original params.state: {params.state[:20] if params.state else None}")
        
        # Store original request details with our state
        self._state_mapping[state] = {
            "client_id": client.client_id,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "scopes": params.scopes or [],
            "state": params.state,  # This includes the timestamp from oauth_login
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "code_verifier": code_verifier,  # Store code verifier for later
            "original_timestamp": int(time.time()),  # Add timestamp for debugging
        }
        
        # Map MCP scopes to IdP scopes if needed
        requested_scopes = params.scopes or []
        idp_scopes = self.idp_settings.scopes.copy()  # Start with default IdP scopes
        
        # Custom scope mapping for specific providers
        if hasattr(self.settings, 'scope_mapping') and self.settings.scope_mapping:
            if hasattr(self.settings.scope_mapping, 'mcp_to_idp'):
                for scope in requested_scopes:
                    mapped = self.settings.scope_mapping.mcp_to_idp.get(scope, [])
                    for mapped_scope in mapped:
                        if mapped_scope not in idp_scopes:
                            idp_scopes.append(mapped_scope)
        
        # Build the authorization URL
        # Use the environment variable for the base URL if available
        callback_uri = self.idp_settings.callback_uri
        base_url = os.environ.get("MCP_AUTH_BASE_URL")
        
        # If base_url is set and callback_uri contains localhost, update it
        if base_url and "localhost" in callback_uri:
            from urllib.parse import urlparse
            parsed_uri = urlparse(callback_uri)
            path = parsed_uri.path
            callback_uri = f"{base_url}{path}"
            logger.info(f"Updated callback URI for authorization: {callback_uri}")
        
        auth_params = {
            "client_id": self.idp_settings.client_id,
            "redirect_uri": callback_uri,
            "response_type": "code",
            "state": state,
            "scope": " ".join(idp_scopes),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256"
        }
        
        if self.idp_settings.audience:
            auth_params["audience"] = self.idp_settings.audience
            
        url = f"{self.idp_settings.authorize_url}?{urllib.parse.urlencode(auth_params)}"
        return url
        
    async def handle_external_callback(
        self, code: str, state: str, request: Request
    ) -> Tuple[str, str]:
        """
        Handle the callback from the external Identity Provider.
        
        This is a custom extension method not part of the OAuthAuthorizationServerProvider 
        Protocol interface. It's used to handle the redirection from the external IdP and 
        create a proper authorization code in our system.
        
        Args:
            code: The authorization code from the external IdP
            state: The state parameter from the external IdP
            request: The FastAPI request object
            
        Returns:
            A tuple of (redirect_url, authorization_code) where:
            - redirect_url: URL to redirect the user back to the client app
            - authorization_code: The generated MCP authorization code
            
        Raises:
            AuthorizeError: If the callback contains invalid parameters
        """
        # Add debug logging
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"handle_external_callback called with state={state[:10] if state else None}")
        logger.info(f"Current state mappings: {list(self._state_mapping.keys())}")
        
        # Verify the state is one we generated
        if state not in self._state_mapping:
            logger.error(f"State '{state[:10] if state else None}' not found in state mapping")
            # Try to find similar state values for debugging
            similar_states = [s for s in self._state_mapping.keys() if state and s.startswith(state[:5])]
            if similar_states:
                logger.info(f"Found similar states: {similar_states}")
                
                # Try using the first similar state as a fallback
                state = similar_states[0]
                logger.info(f"Using similar state as fallback: {state[:10]}")
            else:
                # If we can't find any similar states, return redirect to login page with error
                logger.error("No similar states found, returning auth error")
                raise AuthorizeError(
                    error="invalid_state",
                    error_description="Invalid state parameter - no matching or similar state found"
                )
            
        # Get the original request details
        request_details = self._state_mapping[state]
        
        # Generate a new MCP authorization code
        mcp_code = secrets.token_hex(16)
        
        # Create and store authorization code with external code
        auth_code = MCP_AuthCode(
            code=mcp_code,
            client_id=request_details["client_id"],
            redirect_uri=request_details["redirect_uri"],
            redirect_uri_provided_explicitly=request_details["redirect_uri_provided_explicitly"],
            scopes=request_details["scopes"],
            code_challenge=request_details.get("code_challenge"),
            code_challenge_method=request_details.get("code_challenge_method"),
            expires_at=int(time.time() + 600),  # 10 minute expiry
            external_code=code,
            state=state,  # Store state for accessing code_verifier later
        )
        
        self._auth_codes[mcp_code] = auth_code
        
        # Build redirect back to original client using our own implementation
        # instead of the SDK utility which is causing issues
        from urllib.parse import urlparse, urlencode
        
        # Parse the redirect URI
        parsed_uri = urlparse(request_details["redirect_uri"])
        
        # Create query parameters
        query_params = {
            "code": mcp_code,
            "state": request_details["state"]
        }
        
        # Construct the new URI with query parameters
        scheme = parsed_uri.scheme
        netloc = parsed_uri.netloc
        path = parsed_uri.path
        query = urlencode(query_params)
        
        # Combine all parts to form the redirect URL
        redirect_url = f"{scheme}://{netloc}{path}?{query}"
        
        # Ensure we return a proper tuple
        from typing import Tuple
        
        # Force return as proper tuple with explicit typing
        result: Tuple[str, str] = (redirect_url, mcp_code)
        logger.info(f"Returning callback result as tuple: {result}")
        
        # Return the tuple explicitly to ensure correct unpacking
        return redirect_url, mcp_code
        
    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> Optional[MCP_AuthCode]:
        """Load the authorization code."""
        code = self._auth_codes.get(authorization_code)
        if not code:
            return None
            
        # Verify code belongs to this client
        if code.client_id != client.client_id:
            return None
            
        # Check if expired
        if code.expires_at < time.time():
            if authorization_code in self._auth_codes:
                del self._auth_codes[authorization_code]
            return None
            
        return code
        
    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: MCP_AuthCode
    ) -> OAuthToken:
        """Exchange auth code for tokens, communicating with external IdP."""
        # Get our code with the external_code
        auth_code = self._auth_codes.get(authorization_code.code)
        if not auth_code or not hasattr(auth_code, 'external_code'):
            raise TokenError(
                error="invalid_grant",
                error_description="Invalid authorization code"
            )
            
        # Exchange the external code for tokens with the IdP
        try:
            token_data = await self._exchange_code_with_idp(auth_code.external_code, auth_code)
        except Exception as e:
            raise TokenError(
                error="server_error", 
                error_description=f"Failed to exchange token with IdP: {str(e)}"
            )
            
        # Clean up the used code
        if authorization_code.code in self._auth_codes:
            del self._auth_codes[authorization_code.code]
            
        # Generate local tokens for MCP
        access_token = secrets.token_hex(32)
        refresh_token = secrets.token_hex(32)
        
        # Store the access token with IdP token info
        expires_in = token_data.get("expires_in", 3600)
        expires_at = int(time.time() + expires_in)
        
        # Extract scopes from the token response
        scope_str = token_data.get("scope", "")
        scopes = scope_str.split() if isinstance(scope_str, str) else []
        
        # Add scopes from the authorization code
        if authorization_code.scopes:
            for scope in authorization_code.scopes:
                if scope not in scopes:
                    scopes.append(scope)
        
        token_obj = MCP_AccessToken(
            token=access_token,
            client_id=client.client_id,
            scopes=scopes,
            expires_at=expires_at,
            id_token=token_data.get("id_token"),
            raw_claims={"id_token": token_data.get("id_token"), "access_token": token_data.get("access_token")}
        )
        
        self._access_tokens[access_token] = token_obj
        
        # Store refresh token
        refresh_obj = RefreshToken(
            token=refresh_token,
            client_id=client.client_id,
            scopes=scopes
        )
        
        self._refresh_tokens[refresh_token] = refresh_obj
        
        # Return token response
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=expires_in,
            refresh_token=refresh_token,
            scope=" ".join(scopes)
        )
    
    async def _exchange_code_with_idp(self, code: str, auth_code: MCP_AuthCode = None) -> dict:
        """Exchange authorization code with the IdP."""
        # Use the environment variable for the base URL if available
        callback_uri = self.idp_settings.callback_uri
        base_url = os.environ.get("MCP_AUTH_BASE_URL")
        
        # If base_url is set and callback_uri contains localhost, update it
        if base_url and "localhost" in callback_uri:
            from urllib.parse import urlparse
            parsed_uri = urlparse(callback_uri)
            path = parsed_uri.path
            callback_uri = f"{base_url}{path}"
            logger.info(f"Updated callback URI for token exchange: {callback_uri}")
            
        token_params = {
            "grant_type": "authorization_code",
            "client_id": self.idp_settings.client_id,
            "client_secret": self.idp_settings.client_secret,
            "code": code,
            "redirect_uri": callback_uri
        }
        
        # Get the code verifier for PKCE
        code_verifier = None
        
        # Get from state mapping if available
        if auth_code and auth_code.state and auth_code.state in self._state_mapping:
            state_data = self._state_mapping[auth_code.state]
            if "code_verifier" in state_data and state_data["code_verifier"]:
                code_verifier = state_data["code_verifier"]
                logger.info(f"Using code_verifier from state mapping for PKCE token exchange")
        
        # Add code_verifier if found (required for PKCE with Cognito)
        if code_verifier:
            token_params["code_verifier"] = code_verifier
            logger.info(f"Added code_verifier to token request parameters")
        else:
            logger.warning(f"No code_verifier found for PKCE token exchange")
        
        logger.info(f"Making token request to {self.idp_settings.token_url}")
        
        # Use a reasonably short timeout to prevent delays for users
        # Default is 10 seconds, which is generous but prevents very long hangs
        timeout_seconds = int(os.environ.get("MCP_AUTH_IDP_TIMEOUT", "10"))
        
        logger.info(f"Making token request with {timeout_seconds}s timeout to {self.idp_settings.token_url}")
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    self.idp_settings.token_url,
                    data=token_params,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=timeout_seconds  # Add timeout to prevent delays
                )
                
                # Log response status and headers for debugging
                logger.info(f"Token response status: {response.status_code}")
                
                # Raise for HTTP errors
                response.raise_for_status()
                
                # Parse response JSON
                token_data = response.json()
                logger.info(f"Token response received with keys: {list(token_data.keys())}")
                
                return token_data
            except httpx.HTTPStatusError as e:
                # Log detailed error information
                error_detail = f"HTTP Status {e.response.status_code}"
                try:
                    error_body = e.response.json()
                    error_detail += f" - Error: {error_body.get('error', 'unknown')}"
                    error_detail += f" - Description: {error_body.get('error_description', 'No description')}"
                except Exception:
                    error_detail += f" - Body: {e.response.text[:200]}"
                
                logger.error(f"Token exchange HTTP error: {error_detail}")
                raise TokenError(
                    error="invalid_request",
                    error_description=f"Failed to exchange token with IdP: {error_detail}"
                )
            except httpx.RequestError as e:
                logger.error(f"Token exchange request error: {e}")
                raise TokenError(
                    error="server_error",
                    error_description=f"Connection error during token exchange: {e}"
                )
            except Exception as e:
                logger.error(f"Unexpected error during token exchange: {e}", exc_info=True)
                raise TokenError(
                    error="server_error",
                    error_description=f"Unexpected error during token exchange: {e}"
                )
                raise TokenError(
                    error="invalid_request", 
                    error_description=f"Failed to exchange code with IdP: {response.status_code} - {response.text[:100]}"
                )
                
    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> Optional[RefreshToken]:
        """Load refresh token."""
        token = self._refresh_tokens.get(refresh_token)
        if not token:
            return None
            
        if token.client_id != client.client_id:
            return None
            
        return token
        
    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: List[str]
    ) -> OAuthToken:
        """Exchange refresh token for new tokens."""
        # Remove the old refresh token
        old_token = refresh_token.token
        if old_token in self._refresh_tokens:
            del self._refresh_tokens[old_token]
            
        # Generate new tokens
        access_token = secrets.token_hex(32)
        new_refresh_token = secrets.token_hex(32)
        
        # Store new access token
        expires_in = 3600
        expires_at = int(time.time() + expires_in)
        
        # Use requested scopes or fall back to original
        final_scopes = scopes if scopes else refresh_token.scopes
        
        token_obj = MCP_AccessToken(
            token=access_token,
            client_id=client.client_id,
            scopes=final_scopes,
            expires_at=expires_at
        )
        
        self._access_tokens[access_token] = token_obj
        
        # Store new refresh token
        refresh_obj = RefreshToken(
            token=new_refresh_token,
            client_id=client.client_id,
            scopes=final_scopes
        )
        
        self._refresh_tokens[new_refresh_token] = refresh_obj
        
        # Return token response
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=expires_in,
            refresh_token=new_refresh_token,
            scope=" ".join(final_scopes)
        )
        
    async def load_access_token(self, token: str) -> Optional[MCP_AccessToken]:
        """Load and validate access token."""
        # Check our local token store first
        local_token = self._access_tokens.get(token)
        if local_token:
            # Check if expired
            if local_token.expires_at and local_token.expires_at < time.time():
                if token in self._access_tokens:
                    del self._access_tokens[token]
                return None
                
            return local_token
            
        # If not in our store, it might be a direct JWT from the IdP
        try:
            # Extract provider-specific claims and scopes
            decoded = self._decode_and_validate_jwt(token)
            if not decoded:
                return None
                
            # Extract scopes based on provider type
            scopes = self._extract_scopes_from_claims(decoded)
            
            # Map external scopes to MCP scopes if mappings exist
            mapped_scopes = []
            if hasattr(self.settings, 'scope_mapping') and self.settings.scope_mapping:
                if hasattr(self.settings.scope_mapping, 'idp_to_mcp'):
                    for scope in scopes:
                        mapped = self.settings.scope_mapping.idp_to_mcp.get(scope, [])
                        mapped_scopes.extend(mapped)
            
            # Create token object
            token_obj = MCP_AccessToken(
                token=token,
                client_id=decoded.get("client_id", decoded.get("aud", "unknown")),
                scopes=list(set(scopes + mapped_scopes)),  # Remove duplicates
                expires_at=decoded.get("exp"),
                id_token=token,
                raw_claims=decoded
            )
            
            # Cache the validated token
            self._access_tokens[token] = token_obj
            
            return token_obj
            
        except TokenError as te:
            # Use TokenError if already raised by underlying validation
            logger.warning(f"JWT validation failed: {te.error} - {te.error_description}")
            return None
        except Exception as e:
            # Convert other exceptions to standard format
            logger.warning(f"JWT validation failed: {e}")
            return None
    
    async def _get_jwks(self) -> Optional[Dict[str, Any]]:
        """
        Fetch JWKS (JSON Web Key Set) from the identity provider.
        
        Returns:
            The JWKS data or None if retrieval fails
        """
        if not self.idp_settings.jwks_url:
            logger.warning("No JWKS URL configured for JWT validation")
            return None
            
        try:
            # Use a reasonably short timeout to prevent delays
            timeout_seconds = int(os.environ.get("MCP_AUTH_IDP_TIMEOUT", "10"))
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    self.idp_settings.jwks_url,
                    timeout=timeout_seconds
                )
                response.raise_for_status()
                return response.json()
                
        except Exception as e:
            logger.error(f"Failed to fetch JWKS from {self.idp_settings.jwks_url}: {e}")
            return None

    def _decode_and_validate_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode and validate a JWT token with proper signature verification.
        
        Subclasses can override this method to implement provider-specific validation.
        """
        try:
            # First, decode headers to get key ID
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            
            if not kid:
                logger.warning("JWT token missing key ID (kid) in header")
                raise TokenError(
                    error="invalid_token",
                    error_description="Token missing key ID"
                )
            
            # Get JWKS to find the public key
            import asyncio
            jwks = asyncio.run(self._get_jwks())
            if not jwks:
                logger.error("Unable to retrieve JWKS for token verification")
                raise TokenError(
                    error="invalid_token", 
                    error_description="Unable to verify token signature"
                )
            
            # Find the matching key
            public_key = None
            for key in jwks.get("keys", []):
                if key.get("kid") == kid:
                    # Convert JWK to PEM format for PyJWT
                    from jwt.algorithms import RSAAlgorithm
                    public_key = RSAAlgorithm.from_jwk(key)
                    break
            
            if not public_key:
                logger.warning(f"No matching key found for kid: {kid}")
                raise TokenError(
                    error="invalid_token",
                    error_description="Unable to verify token signature"
                )
            
            # Decode and verify the token with signature verification enabled
            decoded = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],  # Most OAuth providers use RS256
                audience=self.idp_settings.audience,
                issuer=self.idp_settings.issuer,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True if self.idp_settings.audience else False,
                    "verify_iss": True if self.idp_settings.issuer else False
                }
            )
            
            # PyJWT has already validated exp, nbf, iat, aud, and iss claims
            # Return the validated claims
            logger.info("JWT token validated successfully with signature verification")
            return decoded
            
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            raise TokenError(
                error="invalid_token",
                error_description="Token has expired"
            )
        except jwt.InvalidAudienceError:
            logger.warning("JWT token has invalid audience")
            raise TokenError(
                error="invalid_token",
                error_description="Invalid token audience"
            )
        except jwt.InvalidIssuerError:
            logger.warning("JWT token has invalid issuer")
            raise TokenError(
                error="invalid_token",
                error_description="Invalid token issuer"
            )
        except jwt.InvalidSignatureError:
            logger.warning("JWT token has invalid signature")
            raise TokenError(
                error="invalid_token",
                error_description="Invalid token signature"
            )
        except jwt.InvalidTokenError as e:
            logger.warning(f"JWT token is invalid: {e}")
            raise TokenError(
                error="invalid_token",
                error_description="Invalid token"
            )
        except Exception as e:
            logger.error(f"Unexpected error during JWT validation: {e}")
            raise TokenError(
                error="invalid_token",
                error_description="Token validation failed"
            )
            
    def _extract_scopes_from_claims(self, claims: Dict[str, Any]) -> List[str]:
        """
        Extract scopes from JWT claims.
        
        Different providers store scopes in different claim formats.
        Subclasses can override this method for provider-specific scope extraction.
        """
        scopes = []
        
        # Standard 'scope' claim (space-separated string)
        if "scope" in claims:
            if isinstance(claims["scope"], str):
                scopes.extend(claims["scope"].split())
            elif isinstance(claims["scope"], list):
                scopes.extend([s for s in claims["scope"] if isinstance(s, str)])
                
        # OIDC 'scp' claim (array of strings)
        if "scp" in claims and isinstance(claims["scp"], list):
            scopes.extend([s for s in claims["scp"] if isinstance(s, str)])
            
        # Generic handling for groups/roles
        # Handle standard OIDC/OAuth groups claim
        if "groups" in claims and isinstance(claims["groups"], list):
            for group in claims["groups"]:
                if isinstance(group, str) and group.startswith("mcp:"):
                    scopes.append(group)
                    
        # Handle roles claim
        if "roles" in claims and isinstance(claims["roles"], list):
            for role in claims["roles"]:
                if isinstance(role, str) and role.startswith("mcp:"):
                    scopes.append(role)
                    
        return scopes
            
    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        """
        Retrieves client information by client ID.
        
        This implementation supports two client types:
        1. Clients stored in the internal registry via register_client
        2. A default client using the configured IdP client credentials
        
        Args:
            client_id: The ID of the client to retrieve.
            
        Returns:
            The client information, or None if the client does not exist.
        """
        # Return from cache if available
        if client_id in self._clients:
            return self._clients[client_id]
            
        # If we're using a default client from settings, create it
        if self.settings.default_client_id and self.settings.default_client_id == client_id:
            if not self.idp_settings or not self.idp_settings.callback_uri:
                return None
                
            client = OAuthClientInformationFull(
                client_id=client_id,
                client_secret=self.settings.default_client_secret,
                # Use the callback URI from IdP settings as redirect URI
                redirect_uris=[self.idp_settings.callback_uri],
                scope=" ".join(self.idp_settings.scopes) if self.idp_settings.scopes else None,
                token_endpoint_auth_method="client_secret_post",
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                client_name="MCP Gateway"
            )
            # Cache the client
            self._clients[client_id] = client
            return client
            
        # Client not found
        return None
        
    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """
        Saves client information as part of registering it.
        
        Args:
            client_info: The client metadata to register.
            
        Raises:
            RegistrationError: If the client metadata is invalid.
        """
        # Validate client metadata before storing
        if not client_info.redirect_uris or len(client_info.redirect_uris) == 0:
            raise RegistrationError(
                error="invalid_redirect_uri",
                error_description="At least one redirect URI must be provided"
            )
            
        # Validate grant types include authorization_code
        if "authorization_code" not in client_info.grant_types:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="Client must support 'authorization_code' grant type"
            )
            
        # Store the client
        self._clients[client_info.client_id] = client_info
        logger.info(f"Registered client with ID {client_info.client_id}")
    
    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        """Revoke a token."""
        token_str = token.token
        
        if isinstance(token, AccessToken):
            if token_str in self._access_tokens:
                del self._access_tokens[token_str]
        elif isinstance(token, RefreshToken):
            if token_str in self._refresh_tokens:
                del self._refresh_tokens[token_str]


class CognitoOAuthProvider(ConfigurableIdPAdapter):
    """
    AWS Cognito OAuth provider adapter using pycognito for enhanced security.
    
    This implementation leverages the pycognito library to handle:
    - Proper JWT verification and token validation 
    - Secure token exchange with PKCE
    - Automatic token refresh
    
    It maintains compatibility with the MCP Python SDK by implementing the
    OAuthAuthorizationServerProvider protocol.
    """
    
    @classmethod
    def from_user_pool(cls, user_pool_id: str, client_id: str, client_secret: str,
                       callback_uri: str, region: str = "us-east-1",
                       custom_domain: str = None) -> "CognitoOAuthProvider":
        """
        Create a Cognito provider from user pool details.
        
        Args:
            user_pool_id: The Cognito user pool ID
            client_id: The app client ID
            client_secret: The app client secret
            callback_uri: The callback URI for the OAuth flow
            region: AWS region, defaults to us-east-1
            custom_domain: Optional custom domain for Cognito
            
        Returns:
            Configured CognitoOAuthProvider
        """
        # Extract region from the user pool ID (format is region_poolID)
        region_from_id = user_pool_id.split('_')[0]
        pool_id = user_pool_id.split('_')[1]
        
        # Log the parsed values for debugging
        logger.info(f"Parsed user pool ID: region={region_from_id}, pool_id={pool_id}")
        
        # Cognito hosted UI domains
        domain_prefix = f"{region_from_id}-{pool_id}"
        logger.info(f"Using domain prefix: {domain_prefix}")
        
        # Standard Cognito domain formats
        domain = f"cognito-idp.{region}.amazonaws.com/{user_pool_id}"
        
        # Determine the domain to use for authorization and token endpoints
        if custom_domain:
            auth_domain = custom_domain
            logger.info(f"Using custom Cognito domain: {auth_domain}")
        else:
            # Cognito OAuth uses the hosted UI domain, not the API domain
            auth_domain = f"{domain_prefix}.auth.{region}.amazoncognito.com"
            logger.info(f"Using Cognito hosted UI domain: {auth_domain}")
        
        # Build IdP settings for the provider
        idp_settings = IdPSettings(
            provider_type="cognito",
            client_id=client_id,
            client_secret=client_secret,
            authorize_url=f"https://{auth_domain}/oauth2/authorize",
            token_url=f"https://{auth_domain}/oauth2/token",
            jwks_url=f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json",
            callback_uri=callback_uri,
            audience=client_id,
            issuer=f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}",
            scopes=["openid", "email", "profile"]  # Default scopes for Cognito
        )
        
        # Create scope mapping for Cognito groups
        scope_mapping = ScopeMapping(
            idp_to_mcp={
                "admin": ["mcp:registry:admin"],
                "user": ["mcp:registry:read"],
                "cognito:admin": ["mcp:registry:admin"],
                "cognito:user": ["mcp:registry:read"],
            }
        )
        
        # Create auth settings that combine everything
        settings = AuthSettings(
            enabled=True,
            idp_settings=idp_settings,
            scope_mapping=scope_mapping,
            default_client_id=client_id,
            default_client_secret=client_secret
        )
        
        # Initialize the provider with these settings
        return cls(settings)
    
    def __init__(self, settings: AuthSettings):
        """
        Initialize the Cognito provider using pycognito.
        
        Args:
            settings: Authentication settings including Cognito configuration
        """
        super().__init__(settings)
        
        # Import pycognito for Cognito operations
        from pycognito import Cognito
        self.Cognito = Cognito
        
        # Extract Cognito-specific settings for easy access
        self.user_pool_id = None
        self.region = "us-east-1"  # Default region
        
        # Parse user pool ID from issuer URL if available
        if settings.idp_settings and settings.idp_settings.issuer:
            issuer_parts = settings.idp_settings.issuer.split('/')
            for part in issuer_parts:
                if '_' in part:  # User pool IDs contain an underscore
                    self.user_pool_id = part
                    self.region = part.split('_')[0]
                    break
        
        # Create a Cognito client for admin operations
        try:
            self.cognito_client = self.Cognito(
                user_pool_id=self.user_pool_id,
                client_id=settings.idp_settings.client_id,
                client_secret=settings.idp_settings.client_secret,
            )
            logger.info("Initialized pycognito client for Cognito provider")
        except Exception as e:
            logger.warning(f"Error initializing pycognito client: {e}")
        
        logger.info(f"Initialized CognitoOAuthProvider with user pool ID: {self.user_pool_id} in region: {self.region}")
    
    async def _exchange_code_with_idp(self, code: str, auth_code: MCP_AuthCode = None) -> dict:
        """
        Exchange authorization code with Cognito.
        
        Args:
            code: The authorization code from Cognito
            auth_code: The MCP authorization code object
            
        Returns:
            Token response from Cognito
            
        Raises:
            TokenError: If token exchange fails
        """
        # Get the code verifier for PKCE
        code_verifier = None
        
        # Get from state mapping if available
        if auth_code and auth_code.state and auth_code.state in self._state_mapping:
            state_data = self._state_mapping[auth_code.state]
            if "code_verifier" in state_data and state_data["code_verifier"]:
                code_verifier = state_data["code_verifier"]
                logger.info(f"Using code_verifier from state mapping for PKCE token exchange")
        
        # Prepare token exchange parameters
        token_params = {
            "grant_type": "authorization_code",
            "client_id": self.settings.idp_settings.client_id,
            "client_secret": self.settings.idp_settings.client_secret,
            "code": code,
            "redirect_uri": self.settings.idp_settings.callback_uri
        }
        
        # Add code_verifier if found (required for PKCE)
        if code_verifier:
            token_params["code_verifier"] = code_verifier
        
        try:
            # Use HTTPX for token exchange since pycognito doesn't directly support PKCE with code_verifier
            # Use a short timeout to prevent long user-visible delays
            timeout_seconds = int(os.environ.get("MCP_AUTH_IDP_TIMEOUT", "10"))
            logger.info(f"Making Cognito token request with {timeout_seconds}s timeout")
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.settings.idp_settings.token_url,
                    data=token_params,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=timeout_seconds  # Add timeout to prevent delays
                )
                
                if response.status_code != 200:
                    logger.error(f"Cognito token error: {response.status_code} {response.text}")
                    raise TokenError(
                        error="invalid_request", 
                        error_description=f"Failed to exchange code with Cognito: {response.status_code} - {response.text[:100]}"
                    )
                
                token_data = response.json()
                logger.info(f"Successfully exchanged code for tokens with Cognito")
                
                return token_data
                
        except Exception as e:
            if isinstance(e, TokenError):
                raise
            logger.error(f"Error during token exchange: {e}")
            raise TokenError(
                error="server_error",
                error_description=f"Failed to exchange token with Cognito: {str(e)}"
            )
    
    def _decode_and_validate_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode and validate a JWT token using pycognito.
        
        Args:
            token: The JWT token to validate
            
        Returns:
            The validated token claims or None if validation fails
        """
        if not token:
            return None
        
        try:
            # Create a temporary Cognito instance with the token
            cognito = self.Cognito(
                user_pool_id=self.user_pool_id,
                client_id=self.settings.idp_settings.client_id,
                id_token=token
            )
            
            # Verify the token - this will check the signature using JWKS
            cognito.verify_token(token, 'id', cognito.id_token)
            
            # If verification is successful, return the claims
            if hasattr(cognito, 'id_claims'):
                return cognito.id_claims
                
            # If pycognito doesn't provide claims directly, decode the token manually
            return jwt.decode(
                token,
                options={"verify_signature": False}  # Already verified by pycognito
            )
            
        except Exception as e:
            logger.warning(f"JWT validation failed: {e}")
            return None
    
    # The _get_jwks method is no longer needed since we're using pycognito for JWT validation
    # which handles JWKS retrieval internally
    
    def _extract_scopes_from_claims(self, claims: Dict[str, Any]) -> List[str]:
        """
        Extract scopes from Cognito-specific JWT claims.
        
        Args:
            claims: The JWT claims
            
        Returns:
            List of scopes extracted from the claims
        """
        scopes = super()._extract_scopes_from_claims(claims)
        
        # Cognito-specific: extract scopes from Cognito groups
        if "cognito:groups" in claims and isinstance(claims["cognito:groups"], list):
            for group in claims["cognito:groups"]:
                if isinstance(group, str):
                    # Add any group that starts with mcp: directly
                    if group.startswith("mcp:"):
                        scopes.append(group)
                        logger.info(f"Added direct scope from Cognito group: {group}")
                    
                    # Map specific groups to scopes
                    elif group == "mcp-admin" or group == "admin":
                        scopes.append("mcp:registry:admin")
                        logger.info(f"Added admin scope from Cognito group: {group}")
                    elif group == "mcp-user" or group == "user":
                        scopes.append("mcp:registry:read")
                        logger.info(f"Added read scope from Cognito group: {group}")
                    
                    # Server-specific groups
                    elif group.startswith("mcp-server-"):
                        parts = group[len("mcp-server-"):].split("-")
                        
                        # Basic server group (e.g., mcp-server-currenttime)
                        if len(parts) == 1:
                            server_name = parts[0]
                            if server_name:
                                # Add read and execute scopes
                                read_scope = f"{self.settings.server_execute_scope_prefix}{server_name}:read"
                                execute_scope = f"{self.settings.server_execute_scope_prefix}{server_name}{self.settings.server_execute_scope_suffix}"
                                scopes.append(read_scope)
                                scopes.append(execute_scope)
                                logger.info(f"Added read and execute scopes for server {server_name} from group {group}")
                        
                        # Server admin group (e.g., mcp-server-currenttime-admin)
                        elif len(parts) > 1 and parts[-1] == "admin":
                            server_name = "-".join(parts[:-1])
                            if server_name:
                                # Add all server scopes (read, execute, toggle, edit)
                                base_scope = f"{self.settings.server_execute_scope_prefix}{server_name}"
                                scopes.append(f"{base_scope}:read")
                                scopes.append(f"{base_scope}:execute")
                                scopes.append(f"{base_scope}:toggle")
                                scopes.append(f"{base_scope}:edit")
                                logger.info(f"Added all admin scopes for server {server_name} from group {group}")
                        
                        # Server toggle group (e.g., mcp-server-currenttime-toggle)
                        elif len(parts) > 1 and parts[-1] == "toggle":
                            server_name = "-".join(parts[:-1])
                            if server_name:
                                toggle_scope = f"{self.settings.server_execute_scope_prefix}{server_name}:toggle"
                                scopes.append(toggle_scope)
                                logger.info(f"Added toggle scope for server {server_name} from group {group}")
                        
                        # Server edit group (e.g., mcp-server-currenttime-edit)
                        elif len(parts) > 1 and parts[-1] == "edit":
                            server_name = "-".join(parts[:-1])
                            if server_name:
                                edit_scope = f"{self.settings.server_execute_scope_prefix}{server_name}:edit"
                                scopes.append(edit_scope)
                                logger.info(f"Added edit scope for server {server_name} from group {group}")
                        
                        # Tool-specific group (e.g., mcp-server-currenttime-tool-toolname)
                        elif len(parts) > 2 and parts[-2] == "tool":
                            server_name = "-".join(parts[:-2])
                            tool_name = parts[-1]
                            if server_name and tool_name:
                                tool_scope = f"{self.settings.server_execute_scope_prefix}{server_name}:tool:{tool_name}:execute"
                                scopes.append(tool_scope)
                                logger.info(f"Added tool-specific scope for {tool_name} on server {server_name} from group {group}")
        
        # Extract from custom:roles attribute (JSON or comma-separated)
        if "custom:roles" in claims and isinstance(claims["custom:roles"], str):
            try:
                # Try to parse as JSON
                roles = json.loads(claims["custom:roles"])
                if isinstance(roles, list):
                    for role in roles:
                        if isinstance(role, str) and role.startswith("mcp:"):
                            scopes.append(role)
                            logger.info(f"Added scope from custom:roles JSON: {role}")
            except json.JSONDecodeError:
                # If not JSON, treat as comma-separated string
                for role in claims["custom:roles"].split(","):
                    role = role.strip()
                    if role.startswith("mcp:"):
                        scopes.append(role)
                        logger.info(f"Added scope from custom:roles string: {role}")
        
        return scopes

    async def load_access_token(self, token: str) -> Optional[MCP_AccessToken]:
        """
        Load and validate access token using pycognito.
        
        Args:
            token: The access token to validate
            
        Returns:
            Token object or None if validation fails
        """
        # Check our local token store first
        local_token = self._access_tokens.get(token)
        if local_token:
            # Check if expired
            if local_token.expires_at and local_token.expires_at < time.time():
                if token in self._access_tokens:
                    del self._access_tokens[token]
                return None
                
            return local_token
            
        # If not in our store, validate the JWT token with pycognito
        try:
            # Extract and validate claims using pycognito
            decoded = self._decode_and_validate_jwt(token)
            if not decoded:
                return None
                
            # Extract scopes based on provider type
            scopes = self._extract_scopes_from_claims(decoded)
            
            # Map external scopes to MCP scopes if mappings exist
            mapped_scopes = []
            if hasattr(self.settings, 'scope_mapping') and self.settings.scope_mapping:
                if hasattr(self.settings.scope_mapping, 'idp_to_mcp'):
                    for scope in scopes:
                        mapped = self.settings.scope_mapping.idp_to_mcp.get(scope, [])
                        mapped_scopes.extend(mapped)
            
            # Create token object
            token_obj = MCP_AccessToken(
                token=token,
                client_id=decoded.get("client_id", decoded.get("aud", "unknown")),
                scopes=list(set(scopes + mapped_scopes)),  # Remove duplicates
                expires_at=decoded.get("exp"),
                id_token=token,
                raw_claims=decoded
            )
            
            # Cache the validated token
            self._access_tokens[token] = token_obj
            
            return token_obj
            
        except Exception as e:
            # Handle any validation errors
            logger.warning(f"JWT validation failed: {e}")
            return None


class OktaOAuthProvider(ConfigurableIdPAdapter):
    """Okta-specific OAuth provider adapter."""
    
    @classmethod
    def from_tenant(cls, tenant_url: str, client_id: str, client_secret: str,
                   callback_uri: str) -> "OktaOAuthProvider":
        """
        Create an Okta provider from tenant details.
        
        Args:
            tenant_url: The Okta tenant URL (https://your-org.okta.com)
            client_id: The app client ID
            client_secret: The app client secret
            callback_uri: The callback URI for the OAuth flow
            
        Returns:
            Configured OktaOAuthProvider
        """
        # Remove trailing slash if present
        tenant_url = tenant_url.rstrip('/')
        
        idp_settings = IdPSettings(
            provider_type="okta",
            client_id=client_id,
            client_secret=client_secret,
            authorize_url=f"{tenant_url}/oauth2/v1/authorize",
            token_url=f"{tenant_url}/oauth2/v1/token",
            jwks_url=f"{tenant_url}/oauth2/v1/keys",
            callback_uri=callback_uri,
            audience="api://default",
            issuer=tenant_url
        )
        
        # Create scope mapping
        scope_mapping = ScopeMapping(
            idp_to_mcp={
                "admin": ["mcp:registry:admin"],
                "user": ["mcp:registry:read"],
                "mcp-admin": ["mcp:registry:admin"],
                "mcp-user": ["mcp:registry:read"],
            }
        )
        
        settings = AuthSettings(
            enabled=True,
            idp_settings=idp_settings,
            scope_mapping=scope_mapping,
            default_client_id=client_id,
            default_client_secret=client_secret
        )
        
        return cls(settings)
    
    def _extract_scopes_from_claims(self, claims: Dict[str, Any]) -> List[str]:
        """Extract scopes from Okta-specific JWT claims."""
        scopes = super()._extract_scopes_from_claims(claims)
        
        # Okta-specific: groups claim
        if "groups" in claims and isinstance(claims["groups"], list):
            for group in claims["groups"]:
                if isinstance(group, str):
                    # Add mcp: prefix to Okta groups that match our naming convention
                    if group.startswith("mcp-"):
                        scopes.append(f"mcp:{group[4:]}")
                    # Add direct matches for groups already prefixed
                    elif group.startswith("mcp:"):
                        scopes.append(group)
        
        return scopes