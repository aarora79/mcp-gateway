import asyncio
import secrets
import hashlib
import base64
import httpx
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from urllib.parse import urlencode, parse_qs, urlparse, urljoin
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)

@dataclass
class DynamicClientRegistration:
    """Dynamic client registration response"""
    client_id: str
    client_secret: Optional[str] = None
    registration_access_token: Optional[str] = None
    registration_client_uri: Optional[str] = None
    client_id_issued_at: Optional[int] = None
    client_secret_expires_at: Optional[int] = None

@dataclass
class OAuthConfig:
    """OAuth configuration for an MCP server"""
    client_id: str
    client_secret: Optional[str] = None
    authorization_url: str = ""
    token_url: str = ""
    redirect_uri: str = "http://localhost:80/oauth/callback/"
    scope: str = "read"
    grant_type: str = "client_credentials"  # or "authorization_code"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'OAuthConfig':
        """Create from dictionary"""
        return cls(**data)

@dataclass
class TokenInfo:
    """OAuth token information"""
    access_token: str
    token_type: str = "Bearer"
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    expires_at: Optional[datetime] = None
    
    def is_expired(self, buffer_minutes: int = 5) -> bool:
        """Check if token is expired (with buffer)"""
        if not self.expires_at:
            return True
        return datetime.now() + timedelta(minutes=buffer_minutes) >= self.expires_at
    
class OAuthDiscovery:
    """Discovers OAuth endpoints using standard discovery methods"""
    
    @staticmethod
    async def discover_oauth_endpoints(base_url: str) -> Dict[str, str]:
        """
        Discover OAuth endpoints for a given base URL using standard methods:
        1. .well-known/oauth-authorization-server
        2. .well-known/openid_configuration  
        3. Common endpoint patterns
        
        Returns a dict with discovered endpoints: token_url, authorization_url, etc.
        """
        logger.info(f"Starting OAuth endpoint discovery for {base_url}")
        
        # Normalize base URL
        base_url = base_url.rstrip('/')
        parsed_url = urlparse(base_url)
        
        discovered_endpoints = {}
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Method 1: Try .well-known/oauth-authorization-server (RFC 8414)
            try:
                well_known_url = urljoin(base_url, '/.well-known/oauth-authorization-server')
                logger.info(f"Trying OAuth authorization server discovery: {well_known_url}")
                
                response = await client.get(well_known_url)
                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"Found OAuth authorization server metadata: {list(data.keys())}")
                    
                    # Extract standard OAuth endpoints
                    if 'token_endpoint' in data:
                        discovered_endpoints['token_url'] = data['token_endpoint']
                    if 'authorization_endpoint' in data:
                        discovered_endpoints['authorization_url'] = data['authorization_endpoint']
                    if 'introspection_endpoint' in data:
                        discovered_endpoints['introspection_url'] = data['introspection_endpoint']
                    if 'revocation_endpoint' in data:
                        discovered_endpoints['revocation_url'] = data['revocation_endpoint']
                    if 'registration_endpoint' in data:
                        discovered_endpoints['registration_endpoint'] = data['registration_endpoint']
                    
                    # Extract supported features
                    if 'grant_types_supported' in data:
                        discovered_endpoints['supported_grant_types'] = data['grant_types_supported']
                    if 'scopes_supported' in data:
                        discovered_endpoints['supported_scopes'] = data['scopes_supported']
                    
                    logger.info(f"OAuth server discovery successful: {discovered_endpoints}")
                    return discovered_endpoints
                        
            except Exception as e:
                logger.debug(f"OAuth authorization server discovery failed: {e}")
            
            # Method 2: Try .well-known/openid-configuration (OpenID Connect)
            try:
                openid_url = urljoin(base_url, '/.well-known/openid-configuration')
                logger.info(f"Trying OpenID Connect discovery: {openid_url}")
                
                response = await client.get(openid_url)
                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"Found OpenID Connect metadata: {list(data.keys())}")
                    
                    # Extract OAuth endpoints from OpenID Connect metadata
                    if 'token_endpoint' in data:
                        discovered_endpoints['token_url'] = data['token_endpoint']
                    if 'authorization_endpoint' in data:
                        discovered_endpoints['authorization_url'] = data['authorization_endpoint']
                    if 'userinfo_endpoint' in data:
                        discovered_endpoints['userinfo_url'] = data['userinfo_endpoint']
                    if 'introspection_endpoint' in data:
                        discovered_endpoints['introspection_url'] = data['introspection_endpoint']
                    if 'revocation_endpoint' in data:
                        discovered_endpoints['revocation_url'] = data['revocation_endpoint']
                    if 'registration_endpoint' in data:
                        discovered_endpoints['registration_endpoint'] = data['registration_endpoint']
                    
                    # Extract supported features
                    if 'grant_types_supported' in data:
                        discovered_endpoints['supported_grant_types'] = data['grant_types_supported']
                    if 'scopes_supported' in data:
                        discovered_endpoints['supported_scopes'] = data['scopes_supported']
                    
                    logger.info(f"OpenID Connect discovery successful: {discovered_endpoints}")
                    return discovered_endpoints
                        
            except Exception as e:
                logger.debug(f"OpenID Connect discovery failed: {e}")
            
            # Method 3: Try common OAuth endpoint patterns
            logger.info("Trying common OAuth endpoint patterns...")
            common_patterns = [
                # Standard patterns
                {'token': '/oauth/token', 'auth': '/oauth/authorize'},
                {'token': '/oauth/access_token', 'auth': '/oauth/authorize'},
                {'token': '/token', 'auth': '/authorize'},
                {'token': '/auth/token', 'auth': '/auth/authorize'},
                {'token': '/api/oauth/token', 'auth': '/api/oauth/authorize'},
                # Service-specific patterns
                {'token': '/oauth2/token', 'auth': '/oauth2/authorize'},
                {'token': '/v1/oauth/token', 'auth': '/v1/oauth/authorize'},
                {'token': '/auth/oauth/token', 'auth': '/auth/oauth/authorize'},
            ]
            
            for pattern in common_patterns:
                try:
                    token_url = urljoin(base_url, pattern['token'])
                    auth_url = urljoin(base_url, pattern['auth'])
                    
                    # Test if token endpoint exists (try OPTIONS or HEAD first)
                    logger.debug(f"Testing token endpoint: {token_url}")
                    
                    # Try OPTIONS first (most OAuth servers support this)
                    try:
                        response = await client.options(token_url)
                        if response.status_code in [200, 204]:
                            # Check if it accepts POST (required for OAuth)
                            allow_header = response.headers.get('Allow', '').upper()
                            if 'POST' in allow_header:
                                discovered_endpoints['token_url'] = token_url
                                discovered_endpoints['authorization_url'] = auth_url
                                logger.info(f"Found OAuth endpoints via pattern matching: token={token_url}, auth={auth_url}")
                                return discovered_endpoints
                    except:
                        # OPTIONS failed, try HEAD
                        response = await client.head(token_url)
                        if response.status_code in [200, 405]:  # 405 is OK - means endpoint exists but doesn't support HEAD
                            discovered_endpoints['token_url'] = token_url
                            discovered_endpoints['authorization_url'] = auth_url
                            logger.info(f"Found OAuth endpoints via pattern matching: token={token_url}, auth={auth_url}")
                            return discovered_endpoints
                            
                except Exception as e:
                    logger.debug(f"Pattern {pattern} failed: {e}")
                    continue
            
            # Method 4: Try to find OAuth endpoints in HTML pages or API documentation
            try:
                logger.info("Checking main page for OAuth endpoint hints...")
                response = await client.get(base_url)
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    # Look for common OAuth endpoint references in HTML/JSON
                    import re
                    
                    # Search for token endpoint URLs
                    token_patterns = [
                        r'["\']([^"\']*(?:oauth|auth)[^"\']*(?:token|access_token)[^"\']*)["\']',
                        r'["\']([^"\']*(?:token|access_token)[^"\']*)["\']',
                        r'token[_\s]*(?:url|endpoint)["\s]*:?["\s]*([^"\'>\s]+)',
                    ]
                    
                    for pattern in token_patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if match.startswith('http') or match.startswith('/'):
                                potential_token_url = urljoin(base_url, match)
                                logger.debug(f"Found potential token URL in content: {potential_token_url}")
                                discovered_endpoints['token_url'] = potential_token_url
                                break
                        if 'token_url' in discovered_endpoints:
                            break
                    
                    # Search for authorization endpoint URLs  
                    auth_patterns = [
                        r'["\']([^"\']*(?:oauth|auth)[^"\']*(?:authorize|authorization)[^"\']*)["\']',
                        r'authorization[_\s]*(?:url|endpoint)["\s]*:?["\s]*([^"\'>\s]+)',
                    ]
                    
                    for pattern in auth_patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if match.startswith('http') or match.startswith('/'):
                                potential_auth_url = urljoin(base_url, match)
                                logger.debug(f"Found potential auth URL in content: {potential_auth_url}")
                                discovered_endpoints['authorization_url'] = potential_auth_url
                                break
                        if 'authorization_url' in discovered_endpoints:
                            break
                    
                    if discovered_endpoints:
                        logger.info(f"Found OAuth endpoints in page content: {discovered_endpoints}")
                        return discovered_endpoints
                        
            except Exception as e:
                logger.debug(f"Content scanning failed: {e}")
        
        logger.warning(f"No OAuth endpoints discovered for {base_url}")
        return discovered_endpoints

class OAuthManager:
    """Manages OAuth authentication for multiple MCP servers"""
    
    def __init__(self):
        # server_path -> TokenInfo
        self._tokens: Dict[str, TokenInfo] = {}
        # server_path -> OAuthConfig  
        self._configs: Dict[str, OAuthConfig] = {}
        # For authorization code flow state management
        self._pending_auth: Dict[str, Dict[str, Any]] = {}
    
    def register_server_oauth(self, server_path: str, oauth_config: OAuthConfig) -> None:
        """Register OAuth configuration for a server"""
        self._configs[server_path] = oauth_config
        logger.info(f"Registered OAuth config for server: {server_path}")
    
    def unregister_server(self, server_path: str) -> None:
        """Remove OAuth configuration and tokens for a server"""
        self._configs.pop(server_path, None)
        self._tokens.pop(server_path, None)
        logger.info(f"Unregistered OAuth for server: {server_path}")
    
    def has_oauth_config(self, server_path: str) -> bool:
        """Check if server has OAuth configuration"""
        return server_path in self._configs
    
    def _generate_pkce_challenge(self) -> tuple[str, str]:
        """Generate PKCE code verifier and challenge for OAuth 2.1"""
        # Generate code verifier (43-128 characters)
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        
        # Generate code challenge (SHA256 hash of verifier)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        return code_verifier, code_challenge
    
    async def get_authorization_url(self, server_path: str) -> tuple[str, str]:
        """Get authorization URL for OAuth authorization code flow"""
        if server_path not in self._configs:
            raise ValueError(f"No OAuth config found for server: {server_path}")
        
        config = self._configs[server_path]
        if config.grant_type != "authorization_code":
            raise ValueError(f"Authorization URL only applicable for authorization_code flow")
        
        # Generate state and PKCE parameters
        state = secrets.token_urlsafe(32)
        code_verifier, code_challenge = self._generate_pkce_challenge()
        
        # Store for later verification
        self._pending_auth[state] = {
            "server_path": server_path,
            "code_verifier": code_verifier,
            "timestamp": datetime.now()
        }
        
        # Build authorization URL
        params = {
            "response_type": "code",
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "scope": config.scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256"
        }
        
        auth_url = f"{config.authorization_url}?{urlencode(params)}"
        logger.info(f"Generated authorization URL for {server_path}")
        
        return auth_url, state
    
    async def exchange_code_for_token(self, code: str, state: str) -> str:
        """Exchange authorization code for access token"""
        if state not in self._pending_auth:
            raise ValueError("Invalid or expired state parameter")
        
        auth_info = self._pending_auth.pop(state)
        server_path = auth_info["server_path"]
        code_verifier = auth_info["code_verifier"]
        
        # Check if state is too old (5 minutes)
        if datetime.now() - auth_info["timestamp"] > timedelta(minutes=5):
            raise ValueError("Authorization state expired")
        
        config = self._configs[server_path]
        
        # Prepare token request
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": config.redirect_uri,
            "code_verifier": code_verifier
        }
        
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        
        # Use client authentication
        if config.client_secret:
            credentials = f"{config.client_id}:{config.client_secret}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"Basic {encoded_credentials}"
        else:
            token_data["client_id"] = config.client_id
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                config.token_url,
                data=token_data,
                headers=headers
            )
            
            if response.status_code == 200:
                token_response = response.json()
                token_info = self._parse_token_response(token_response)
                self._tokens[server_path] = token_info
                
                logger.info(f"Successfully obtained access token for {server_path}")
                return server_path
            else:
                logger.error(f"Token exchange failed for {server_path}: {response.status_code} - {response.text}")
                raise RuntimeError(f"Token exchange failed: {response.status_code}")
    
    async def get_client_credentials_token(self, server_path: str) -> TokenInfo:
        """Get token using client credentials flow"""
        if server_path not in self._configs:
            raise ValueError(f"No OAuth config found for server: {server_path}")
        
        config = self._configs[server_path]
        if config.grant_type != "client_credentials":
            raise ValueError(f"Server {server_path} not configured for client_credentials flow")
        
        token_data = {
            "grant_type": "client_credentials",
            "scope": config.scope
        }
        
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        
        # Use client authentication
        if config.client_secret:
            credentials = f"{config.client_id}:{config.client_secret}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"Basic {encoded_credentials}"
        else:
            token_data["client_id"] = config.client_id
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                config.token_url,
                data=token_data,
                headers=headers
            )
            
            if response.status_code == 200:
                token_response = response.json()
                token_info = self._parse_token_response(token_response)
                self._tokens[server_path] = token_info
                
                logger.info(f"Successfully obtained client credentials token for {server_path}")
                return token_info
            else:
                logger.error(f"Client credentials token request failed for {server_path}: {response.status_code} - {response.text}")
                raise RuntimeError(f"Token request failed: {response.status_code}")
    
    async def refresh_token(self, server_path: str) -> TokenInfo:
        """Refresh access token using refresh token"""
        config = self._configs.get(server_path)
        if not config:
            raise ValueError(f"No OAuth config found for server: {server_path}")
        
        # For client_credentials flow, if no token exists, just get a new one
        if config.grant_type == "client_credentials":
            if server_path not in self._tokens:
                logger.info(f"No existing token for {server_path}, getting new client_credentials token")
                return await self.get_client_credentials_token(server_path)
        
        # Check if we have an existing token
        if server_path not in self._tokens:
            raise ValueError(f"No token found for server: {server_path}")
        
        token_info = self._tokens[server_path]
        if not token_info.refresh_token:
            # For client credentials, just get a new token
            if config.grant_type == "client_credentials":
                return await self.get_client_credentials_token(server_path)
            else:
                raise ValueError(f"No refresh token available for {server_path}")
        
        # Rest of the existing refresh logic...
        token_data = {
            "grant_type": "refresh_token",
            "refresh_token": token_info.refresh_token
        }
        
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        
        if config.client_secret:
            credentials = f"{config.client_id}:{config.client_secret}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"Basic {encoded_credentials}"
        else:
            token_data["client_id"] = config.client_id
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                config.token_url,
                data=token_data,
                headers=headers
            )
            
            if response.status_code == 200:
                token_response = response.json()
                new_token_info = self._parse_token_response(token_response)
                
                # Keep existing refresh token if new one not provided
                if not new_token_info.refresh_token and token_info.refresh_token:
                    new_token_info.refresh_token = token_info.refresh_token
                
                self._tokens[server_path] = new_token_info
                logger.info(f"Successfully refreshed token for {server_path}")
                return new_token_info
            else:
                logger.error(f"Token refresh failed for {server_path}: {response.status_code} - {response.text}")
                raise RuntimeError(f"Token refresh failed: {response.status_code}")
    
    def _parse_token_response(self, token_response: Dict[str, Any]) -> TokenInfo:
        """Parse token response into TokenInfo object"""
        expires_at = None
        if token_response.get("expires_in"):
            expires_at = datetime.now() + timedelta(seconds=int(token_response["expires_in"]))
        
        # Ensure token_type is properly capitalized
        token_type = token_response.get("token_type", "Bearer")
        if token_type.lower() == 'bearer':
            token_type = 'Bearer'
        
        return TokenInfo(
            access_token=token_response["access_token"],
            token_type=token_type,  # Use the properly capitalized version
            expires_in=token_response.get("expires_in"),
            refresh_token=token_response.get("refresh_token"),
            scope=token_response.get("scope"),
            expires_at=expires_at
        )
    
    async def get_valid_token(self, server_path: str) -> str:
        """Get a valid access token, refreshing if necessary"""
        if server_path not in self._configs:
            # No OAuth config - not an OAuth-protected server
            return ""
        
        # Check if we have a valid token
        if server_path in self._tokens:
            token_info = self._tokens[server_path]
            if not token_info.is_expired():
                return token_info.access_token
            else:
                # Token expired, try to refresh
                try:
                    refreshed_token = await self.refresh_token(server_path)
                    return refreshed_token.access_token
                except Exception as e:
                    logger.warning(f"Failed to refresh token for {server_path}: {e}")
                    # Fall through to get new token
        
        # No token or refresh failed - get new token
        config = self._configs[server_path]
        if config.grant_type == "client_credentials":
            token_info = await self.get_client_credentials_token(server_path)
            return token_info.access_token
        else:
            # For authorization code flow, we can't automatically get a token
            # This would require user interaction
            raise RuntimeError(f"No valid token for {server_path} and authorization_code flow requires user interaction")
    
    def get_auth_headers(self, server_path: str) -> Dict[str, str]:
        """Get authentication headers for API requests"""
        if server_path not in self._tokens:
            return {}
        
        token_info = self._tokens[server_path]
        # Ensure token_type is properly capitalized
        token_type = token_info.token_type
        if token_type.lower() == 'bearer':
            token_type = 'Bearer'  # Force proper capitalization
        
        return {
            "Authorization": f"{token_type} {token_info.access_token}"
        }
    
    def get_server_oauth_status(self, server_path: str) -> Dict[str, Any]:
        """Get OAuth status information for a server"""
        if server_path not in self._configs:
            return {"has_oauth": False}
        
        config = self._configs[server_path]
        token_info = self._tokens.get(server_path)
        
        status = {
            "has_oauth": True,
            "grant_type": config.grant_type,
            "scope": config.scope,
            "has_token": token_info is not None,
        }
        
        if token_info:
            status.update({
                "token_expires_at": token_info.expires_at.isoformat() if token_info.expires_at else None,
                "is_expired": token_info.is_expired(),
                "has_refresh_token": token_info.refresh_token is not None
            })
        
        return status

    async def register_dynamic_client(self, registration_endpoint: str, 
                                    client_name: str = "MCP Gateway",
                                    redirect_uris: List[str] = None,
                                    grant_types: List[str] = None,
                                    scope: str = "read write") -> DynamicClientRegistration:
        """
        Register a new OAuth client dynamically using RFC 7591
        
        Args:
            registration_endpoint: The client registration endpoint URL
            client_name: Human-readable name for the client
            redirect_uris: List of redirect URIs for the client
            grant_types: List of OAuth grant types the client will use
            scope: Requested scope for the client
            
        Returns:
            DynamicClientRegistration with client credentials
            
        Raises:
            RuntimeError: If registration fails
        """
        if redirect_uris is None:
            redirect_uris = ["http://localhost:80/oauth/callback/"]
        
        if grant_types is None:
            grant_types = ["authorization_code", "refresh_token"]
        
        # Prepare registration request according to RFC 7591
        registration_data = {
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "grant_types": grant_types,
            "response_types": ["code"],  # For authorization code flow
            "application_type": "web",
            "token_endpoint_auth_method": "client_secret_basic",  # HTTP Basic auth
            "scope": scope
        }
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        logger.info(f"Attempting dynamic client registration at {registration_endpoint}")
        logger.info(f"Registration data: {registration_data}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                registration_endpoint,
                json=registration_data,
                headers=headers
            )
            
            if response.status_code in [200, 201]:
                registration_response = response.json()
                logger.info(f"Dynamic client registration successful: {list(registration_response.keys())}")
                
                # Parse the registration response
                return DynamicClientRegistration(
                    client_id=registration_response["client_id"],
                    client_secret=registration_response.get("client_secret"),
                    registration_access_token=registration_response.get("registration_access_token"),
                    registration_client_uri=registration_response.get("registration_client_uri"),
                    client_id_issued_at=registration_response.get("client_id_issued_at"),
                    client_secret_expires_at=registration_response.get("client_secret_expires_at")
                )
            else:
                error_text = response.text
                logger.error(f"Dynamic client registration failed: {response.status_code} - {error_text}")
                
                # Try to parse error response
                try:
                    error_data = response.json()
                    error_description = error_data.get("error_description", error_text)
                    error_code = error_data.get("error", "registration_failed")
                    raise RuntimeError(f"Client registration failed ({error_code}): {error_description}")
                except json.JSONDecodeError:
                    raise RuntimeError(f"Client registration failed: {response.status_code} - {error_text}")

    async def discover_register_and_configure_oauth(self, server_path: str, base_url: str,
                                                  scope: str = "read write") -> OAuthConfig:
        """
        Complete OAuth setup: Discovery -> Dynamic Registration -> Configuration
        
        Args:
            server_path: The server path for registration
            base_url: Base URL of the server
            scope: OAuth scope to request
            
        Returns:
            OAuthConfig object with discovered endpoints and registered client
            
        Raises:
            ValueError: If discovery fails
            RuntimeError: If registration fails
        """
        logger.info(f"Starting complete OAuth setup for {server_path}")
        
        # Step 1: Discover OAuth endpoints
        discovered = await OAuthDiscovery.discover_oauth_endpoints(base_url)
        
        if not discovered.get('token_url'):
            raise ValueError(f"Could not discover OAuth token endpoint for {base_url}")
        
        if not discovered.get('authorization_url'):
            raise ValueError(f"Could not discover OAuth authorization endpoint for {base_url}")
        
        # Step 2: Check if dynamic registration is supported
        registration_endpoint = None
        
        # Try to get registration endpoint from discovery
        if 'registration_endpoint' in discovered:
            registration_endpoint = discovered['registration_endpoint']
        else:
            # Try common registration endpoint patterns
            common_registration_paths = [
                '/register',
                '/oauth/register',
                '/oauth/clients',
                '/clients/register',
                '/auth/register'
            ]
            
            for path in common_registration_paths:
                potential_endpoint = urljoin(base_url, path)
                try:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        # Try OPTIONS to see if endpoint exists
                        response = await client.options(potential_endpoint)
                        if response.status_code in [200, 204, 405]:  # 405 means endpoint exists but doesn't support OPTIONS
                            registration_endpoint = potential_endpoint
                            logger.info(f"Found potential registration endpoint: {registration_endpoint}")
                            break
                except:
                    continue
        
        if not registration_endpoint:
            # Fallback: try the discovered metadata for hints about registration
            logger.warning(f"No registration endpoint found for {base_url}. Trying common patterns...")
            registration_endpoint = urljoin(base_url, '/oauth/register')  # Most common pattern
        
        # Step 3: Attempt dynamic client registration
        try:
            logger.info(f"Attempting dynamic client registration at {registration_endpoint}")
            client_registration = await self.register_dynamic_client(
                registration_endpoint=registration_endpoint,
                client_name=f"MCP Gateway - {server_path}",
                scope=scope
            )
            
            logger.info(f"Dynamic client registration successful for {server_path}")
            logger.info(f"Registered client ID: {client_registration.client_id}")
            
            # Step 4: Create OAuth config with registered client
            oauth_config = OAuthConfig(
                client_id=client_registration.client_id,
                client_secret=client_registration.client_secret,
                authorization_url=discovered['authorization_url'],
                token_url=discovered['token_url'],
                scope=scope,
                grant_type="authorization_code"  # Use authorization code flow
            )
            
            # Step 5: Register with OAuth manager
            self.register_server_oauth(server_path, oauth_config)
            
            logger.info(f"Complete OAuth setup successful for {server_path}")
            logger.info(f"Authorization URL: {oauth_config.authorization_url}")
            logger.info(f"Token URL: {oauth_config.token_url}")
            
            return oauth_config
            
        except Exception as e:
            logger.error(f"Dynamic client registration failed for {server_path}: {e}")
            # Could fall back to manual client credentials here, but for now raise the error
            raise RuntimeError(f"OAuth setup failed: {e}")

    async def discover_and_register_server_oauth(self, server_path: str, base_url: str, 
                                                client_id: str = None, client_secret: str = None,
                                                scope: str = "read", grant_type: str = "authorization_code") -> OAuthConfig:
        """
        Discover OAuth endpoints and register configuration.
        If client_id is not provided, attempts dynamic client registration.
        """
        logger.info(f"Discovering OAuth endpoints for server: {server_path}")
        
        # If no client_id provided, try complete OAuth setup with dynamic registration
        if not client_id:
            logger.info(f"No client_id provided, attempting dynamic client registration for {server_path}")
            return await self.discover_register_and_configure_oauth(server_path, base_url, scope)
        
        # Original logic for when client_id is provided
        discovered = await OAuthDiscovery.discover_oauth_endpoints(base_url)
        
        if not discovered.get('token_url'):
            raise ValueError(f"Could not discover OAuth token endpoint for {base_url}")
        
        oauth_config = OAuthConfig(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=discovered.get('authorization_url', ''),
            token_url=discovered['token_url'],
            scope=scope,
            grant_type=grant_type
        )
        
        self.register_server_oauth(server_path, oauth_config)
        
        logger.info(f"Successfully discovered and registered OAuth config for {server_path}")
        return oauth_config

# Global OAuth manager instance
oauth_manager = OAuthManager()