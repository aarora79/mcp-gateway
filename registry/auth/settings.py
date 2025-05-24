"""
Settings for MCP Gateway authentication.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class IdPSettings:
    """Settings for a specific identity provider."""
    provider_type: str  # "cognito", "okta", etc.
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    jwks_url: str
    callback_uri: str
    scopes: List[str] = field(default_factory=lambda: ["openid", "profile", "email"])
    audience: Optional[str] = None
    issuer: Optional[str] = None


@dataclass
class ScopeMapping:
    """Maps between IdP scopes and MCP Gateway scopes."""
    idp_to_mcp: Dict[str, List[str]] = field(default_factory=dict)
    mcp_to_idp: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class AuthSettings:
    """Main authentication settings for MCP Gateway."""
    enabled: bool = True
    idp_settings: Optional[IdPSettings] = None
    scope_mapping: ScopeMapping = field(default_factory=ScopeMapping)
    registry_admin_scope: str = "mcp:registry:admin"
    registry_read_scope: str = "mcp:registry:read"
    server_execute_scope_prefix: str = "mcp:server:"
    server_execute_scope_suffix: str = ":execute"
    public_routes: List[str] = field(default_factory=lambda: [
        "/login", "/oauth/callback", "/static", "/favicon.ico"
    ])
    # OAuth client ID and secret used by the MCP Gateway with the external IdP
    default_client_id: Optional[str] = None
    default_client_secret: Optional[str] = None
    
    def get_server_execute_scope(self, server_path: str) -> str:
        """Get the scope needed to execute tools on a specific server."""
        # Remove leading slash and replace remaining slashes with underscores
        normalized_path = server_path.lstrip("/").replace("/", "_")
        return f"{self.server_execute_scope_prefix}{normalized_path}{self.server_execute_scope_suffix}"
        
    def get_server_read_scope(self, server_path: str) -> str:
        """Get the read scope for a server."""
        # Remove leading slash and replace remaining slashes with underscores
        normalized_path = server_path.lstrip("/").replace("/", "_")
        return f"{self.server_execute_scope_prefix}{normalized_path}:read"
        
    def get_server_toggle_scope(self, server_path: str) -> str:
        """Get the toggle scope for a server."""
        # Remove leading slash and replace remaining slashes with underscores
        normalized_path = server_path.lstrip("/").replace("/", "_")
        return f"{self.server_execute_scope_prefix}{normalized_path}:toggle"
        
    def get_server_edit_scope(self, server_path: str) -> str:
        """Get the edit scope for a server."""
        # Remove leading slash and replace remaining slashes with underscores
        normalized_path = server_path.lstrip("/").replace("/", "_")
        return f"{self.server_execute_scope_prefix}{normalized_path}:edit"
        
    def get_tool_execute_scope(self, server_path: str, tool_name: str) -> str:
        """Get the execute scope for a specific tool."""
        # Remove leading slash and replace remaining slashes with underscores
        normalized_path = server_path.lstrip("/").replace("/", "_")
        return f"{self.server_execute_scope_prefix}{normalized_path}:tool:{tool_name}:execute"
    
    def load_from_env(self, env_dict: dict) -> "AuthSettings":
        """Load settings from environment variables."""
        self.enabled = env_dict.get("MCP_AUTH_ENABLED", "true").lower() == "true"
        
        if not self.enabled:
            return self
            
        provider_type = env_dict.get("MCP_AUTH_PROVIDER_TYPE", "").lower()
        if not provider_type:
            return self
            
        self.idp_settings = IdPSettings(
            provider_type=provider_type,
            client_id=env_dict.get("MCP_AUTH_CLIENT_ID", ""),
            client_secret=env_dict.get("MCP_AUTH_CLIENT_SECRET", ""),
            authorize_url=env_dict.get("MCP_AUTH_AUTHORIZE_URL", ""),
            token_url=env_dict.get("MCP_AUTH_TOKEN_URL", ""),
            jwks_url=env_dict.get("MCP_AUTH_JWKS_URL", ""),
            callback_uri=env_dict.get("MCP_AUTH_CALLBACK_URI", ""),
            scopes=env_dict.get("MCP_AUTH_SCOPES", "openid profile email").split(),
            audience=env_dict.get("MCP_AUTH_AUDIENCE"),
            issuer=env_dict.get("MCP_AUTH_ISSUER")
        )
        
        # Override default scopes if specified
        registry_admin = env_dict.get("MCP_AUTH_REGISTRY_ADMIN_SCOPE")
        if registry_admin:
            self.registry_admin_scope = registry_admin
            
        registry_read = env_dict.get("MCP_AUTH_REGISTRY_READ_SCOPE")
        if registry_read:
            self.registry_read_scope = registry_read
            
        server_prefix = env_dict.get("MCP_AUTH_SERVER_SCOPE_PREFIX")
        if server_prefix:
            self.server_execute_scope_prefix = server_prefix
            
        server_suffix = env_dict.get("MCP_AUTH_SERVER_SCOPE_SUFFIX")
        if server_suffix:
            self.server_execute_scope_suffix = server_suffix
            
        return self