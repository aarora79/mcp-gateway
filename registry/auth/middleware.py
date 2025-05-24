"""
Authentication middleware for MCP Gateway.

This module implements middleware for JWT verification and scope-based
access control using the MCP SDK's authentication components.
"""
import logging
from typing import List, Dict, Any, Union

from fastapi import Request, HTTPException, status
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.authentication import BaseUser

logger = logging.getLogger(__name__)

from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend
from mcp.server.auth.middleware.auth_context import AuthContextMiddleware

from .provider import ConfigurableIdPAdapter
from .settings import AuthSettings

from .provider import ConfigurableIdPAdapter
from .settings import AuthSettings

logger = logging.getLogger(__name__)


class MCPUser(BaseUser):
    """User with MCP-specific attributes."""
    
    def __init__(self, client_id: str, scopes: List[str], claims: Dict[str, Any]):
        self.client_id = client_id
        self.scopes = set(scopes)
        self.claims = claims
        
    @property
    def is_authenticated(self) -> bool:
        return True
        
    @property
    def display_name(self) -> str:
        return self.claims.get("name", self.claims.get("email", self.client_id))
        
    def has_scope(self, scope: Union[str, List[str]]) -> bool:
        """Check if the user has the specified scope(s)."""
        if isinstance(scope, str):
            return scope in self.scopes
        return all(s in self.scopes for s in scope)


class SessionUser(BaseUser):
    """User authenticated via session cookie."""
    
    def __init__(self, username: str, groups: List[str] = None):
        self.username = username
        self.groups = groups or []
        
        # Extract scopes from groups using the same logic as in provider.py
        self.scopes = set()
        for group in self.groups:
            if isinstance(group, str):
                # Add any group that starts with mcp: directly
                if group.startswith("mcp:"):
                    self.scopes.add(group)
                # Map specific groups to scopes
                elif group == "mcp-admin":
                    self.scopes.add("mcp:registry:admin")
                elif group == "mcp-user":
                    self.scopes.add("mcp:registry:read")
                # Add server-specific scopes based on group names
                elif group.startswith("mcp-server-"):
                    auth_settings = AuthSettings()
                    
                    # Process more specific scopes first
                    if "-toggle" in group:
                        # Extract server name (e.g., "mcp-server-currenttime-toggle" -> "currenttime")
                        server_name = group[len("mcp-server-"):group.find("-toggle")]
                        if server_name:
                            toggle_scope = f"{auth_settings.server_execute_scope_prefix}{server_name}:toggle"
                            self.scopes.add(toggle_scope)
                            # Also add read access with toggle permission
                            read_scope = f"{auth_settings.server_execute_scope_prefix}{server_name}:read"
                            self.scopes.add(read_scope)
                            # Log the scope mapping for debugging
                            logger.info(f"Group '{group}' mapped to scopes: {toggle_scope}, {read_scope}")
                    elif "-edit" in group:
                        # Extract server name (e.g., "mcp-server-currenttime-edit" -> "currenttime")
                        server_name = group[len("mcp-server-"):group.find("-edit")]
                        if server_name:
                            edit_scope = f"{auth_settings.server_execute_scope_prefix}{server_name}:edit"
                            self.scopes.add(edit_scope)
                            # Also add read access with edit permission
                            read_scope = f"{auth_settings.server_execute_scope_prefix}{server_name}:read"
                            self.scopes.add(read_scope)
                    elif "-tool-" in group:
                        # Handle tool-specific groups (e.g., "mcp-server-currenttime-tool-xyz")
                        parts = group.split("-tool-")
                        if len(parts) == 2:
                            server_part = parts[0]
                            tool_part = parts[1]
                            server_name = server_part[len("mcp-server-"):]
                            tool_scope = f"{auth_settings.server_execute_scope_prefix}{server_name}:tool:{tool_part}:execute"
                            self.scopes.add(tool_scope)
                    else:
                        # Extract server name from group (e.g., "mcp-server-currenttime" -> "currenttime")
                        server_name = group[len("mcp-server-"):]
                        if server_name:
                            # Create the server execute scope
                            server_scope = f"{auth_settings.server_execute_scope_prefix}{server_name}{auth_settings.server_execute_scope_suffix}"
                            self.scopes.add(server_scope)
                            # Also add read access for the server
                            read_scope = f"{auth_settings.server_execute_scope_prefix}{server_name}:read"
                            self.scopes.add(read_scope)
        
    @property
    def is_authenticated(self) -> bool:
        return True
        
    @property
    def display_name(self) -> str:
        return self.username
        
    def has_scope(self, scope: Union[str, List[str]]) -> bool:
        """Check if the user has the specified scope(s)."""
        if isinstance(scope, str):
            return scope in self.scopes
        return all(s in self.scopes for s in scope)

class MCPAuthBackend(BearerAuthBackend):
    """Authentication backend for MCP Gateway extending the SDK BearerAuthBackend."""
    
    def __init__(self, provider: ConfigurableIdPAdapter, settings: AuthSettings):
        super().__init__(provider)
        self.settings = settings
        
    async def authenticate(self, request: Request):
        """Authenticate the request using JWT."""
        # Skip authentication for public routes
        path = request.url.path
        if any(path.startswith(public_path) for public_path in self.settings.public_routes):
            # Return anonymous user with no credentials
            return None
            
        # Use the SDK's authenticate method for JWT validation
        credentials = await super().authenticate(request)
        
        if not credentials:
            return None
            
        auth_credentials, auth_user = credentials
        
        # Convert the SDK's AuthenticatedUser to our MCPUser
        claims = getattr(auth_user.access_token, 'raw_claims', {}) or {}
        user = MCPUser(
            client_id=auth_user.username,
            scopes=auth_user.scopes,
            claims=claims
        )
        
        # Return the auth credentials and user
        return auth_credentials, user


def setup_auth_middleware(app, provider: ConfigurableIdPAdapter, settings: AuthSettings):
    """
    Set up authentication middleware for the application.
    
    Args:
        app: The FastAPI application
        provider: The OAuth provider adapter
        settings: Authentication settings
    """
    # Add the authentication middleware
    app.add_middleware(
        AuthenticationMiddleware,
        backend=MCPAuthBackend(provider, settings)
    )
    
    # Add the auth context middleware
    app.add_middleware(AuthContextMiddleware)
    
    
def requires_scope(scope: Union[str, List[str]]):
    """
    Dependency for requiring a specific scope or scopes.
    
    Args:
        scope: The scope or list of scopes required
        
    Returns:
        A dependency function that checks if the user has the required scope(s)
    """
    def dependency(request: Request):
        # Check for user in request.state instead of directly on request
        if not hasattr(request.state, "user") or not hasattr(request.state.user, "has_scope"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        if not request.state.user.has_scope(scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scope: {scope}",
            )
            
        return True
        
    return dependency


def requires_server_access(server_path: str):
    """
    Dependency for requiring access to a specific server.
    
    Args:
        server_path: The path of the server (e.g., "/currenttime")
        
    Returns:
        A dependency function that checks if the user has access to the server
    """
    auth_settings = AuthSettings()
    required_scope = auth_settings.get_server_read_scope(server_path)
    execute_scope = auth_settings.get_server_execute_scope(server_path)
    
    def dependency(request: Request):
        # Check if user has admin scope (grants access to all servers)
        if hasattr(request.state, "user") and hasattr(request.state.user, "has_scope"):
            if request.state.user.has_scope(auth_settings.registry_admin_scope):
                logger.info(f"User {request.state.user.display_name} granted access to {server_path} via admin scope")
                return True
                
            # Check if user has the specific read scope
            if request.state.user.has_scope(required_scope):
                logger.info(f"User {request.state.user.display_name} granted access to {server_path} via read scope")
                return True
                
            # Check if user has the execute scope (which implies read access)
            if request.state.user.has_scope(execute_scope):
                logger.info(f"User {request.state.user.display_name} granted access to {server_path} via execute scope")
                return True
                
            # User doesn't have the required scope
            logger.warning(f"User {request.state.user.display_name} denied access to {server_path} - missing scope: {required_scope}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scope for server access: {required_scope}",
            )
        
        # User is not authenticated
        logger.warning(f"Unauthenticated user denied access to {server_path}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    return dependency


def requires_server_toggle(server_path: str):
    """
    Dependency for requiring toggle permission for a specific server.
    
    Args:
        server_path: The path of the server (e.g., "/currenttime")
        
    Returns:
        A dependency function that checks if the user has toggle permission
    """
    
    auth_settings = AuthSettings()
    base_scope = auth_settings.server_execute_scope_prefix + server_path.lstrip("/")
    toggle_scope = f"{base_scope}:toggle"
    
    def dependency(request: Request):
        # Check if user has admin scope (grants access to all servers)
        if hasattr(request.state, "user") and hasattr(request.state.user, "has_scope"):
            if request.state.user.has_scope(auth_settings.registry_admin_scope):
                logger.info(f"User {request.state.user.display_name} granted toggle access to {server_path} via admin scope")
                return True
                
            # Check if user has the specific toggle scope
            if request.state.user.has_scope(toggle_scope):
                logger.info(f"User {request.state.user.display_name} granted toggle access to {server_path} via toggle scope")
                return True
                
            # User doesn't have the required scope
            logger.warning(f"User {request.state.user.display_name} denied toggle access to {server_path} - missing scope: {toggle_scope}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scope for server toggle: {toggle_scope}",
            )
        
        # User is not authenticated
        logger.warning(f"Unauthenticated user denied toggle access to {server_path}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    return dependency


def requires_server_edit(server_path: str):
    """
    Dependency for requiring edit permission for a specific server.
    
    Args:
        server_path: The path of the server (e.g., "/currenttime")
        
    Returns:
        A dependency function that checks if the user has edit permission
    """
    
    auth_settings = AuthSettings()
    base_scope = auth_settings.server_execute_scope_prefix + server_path.lstrip("/")
    edit_scope = f"{base_scope}:edit"
    
    def dependency(request: Request):
        # Check if user has admin scope (grants access to all servers)
        if hasattr(request.state, "user") and hasattr(request.state.user, "has_scope"):
            if request.state.user.has_scope(auth_settings.registry_admin_scope):
                logger.info(f"User {request.state.user.display_name} granted edit access to {server_path} via admin scope")
                return True
                
            # Check if user has the specific edit scope
            if request.state.user.has_scope(edit_scope):
                logger.info(f"User {request.state.user.display_name} granted edit access to {server_path} via edit scope")
                return True
                
            # User doesn't have the required scope
            logger.warning(f"User {request.state.user.display_name} denied edit access to {server_path} - missing scope: {edit_scope}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scope for server edit: {edit_scope}",
            )
        
        # User is not authenticated
        logger.warning(f"Unauthenticated user denied edit access to {server_path}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    return dependency
# Helper functions for route-specific dependencies
def require_toggle_for_path(service_path: str):
    """
    Dependency function for requiring toggle permission for a specific path.
    
    Args:
        service_path: The path parameter from the route
        
    Returns:
        A dependency function that checks if the user has toggle permission
    """
    def dependency(request: Request):
        return requires_server_toggle(service_path)(request)
    return dependency

def require_edit_for_path(service_path: str):
    """
    Dependency function for requiring edit permission for a specific path.
    
    Args:
        service_path: The path parameter from the route
        
    Returns:
        A dependency function that checks if the user has edit permission
    """
    def dependency(request: Request):
        return requires_server_edit(service_path)(request)
    return dependency

def require_access_for_path(service_path: str):
    """
    Dependency function for requiring access permission for a specific path.
    
    Args:
        service_path: The path parameter from the route
        
    Returns:
        A dependency function that checks if the user has access permission
    """
    def dependency(request: Request):
        return requires_server_access(service_path)(request)
    return dependency
def check_admin_scope():
    """Dependency function for requiring admin scope."""
    def dependency(request: Request):
        auth_settings = AuthSettings()
        
        if not hasattr(request.state, "user") or not hasattr(request.state.user, "has_scope"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        if not request.state.user.has_scope(auth_settings.registry_admin_scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scope: {auth_settings.registry_admin_scope}",
            )
            
        return True
        
    return dependency

def require_registry_admin():
    """Dependency function for requiring registry admin scope."""
    return requires_scope("mcp:registry:admin")
