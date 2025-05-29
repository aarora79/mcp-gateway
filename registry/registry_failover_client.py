"""
MCP Registry Failover Client

This module provides automatic failover capabilities when interacting with
external MCP registries, ensuring high availability and resilience.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

import aiohttp

from .registry_health_monitor import (
    RegistryHealthMonitor, 
    RegistryConfig, 
    RegistryStatus,
    HealthCheckResult
)

logger = logging.getLogger(__name__)


@dataclass
class FailoverResult:
    """Result of a failover operation"""
    success: bool
    registry_used: Optional[str]
    response_data: Optional[Any]
    error: Optional[str]
    attempts: List[Tuple[str, str]]  # [(registry_name, error), ...]
    response_time_ms: Optional[float]


class RegistryFailoverClient:
    """
    Client that automatically handles failover between multiple MCP registries
    """
    
    def __init__(self, health_monitor: RegistryHealthMonitor):
        self.health_monitor = health_monitor
        self.session: Optional[aiohttp.ClientSession] = None
        self.default_timeout = 30
        self.max_retries_per_registry = 2
        self.backoff_delay = 1.0  # seconds
        
        # Circuit breaker settings
        self.circuit_breaker_timeout = 60  # seconds to wait before retrying failed registry
        self.circuit_breaker_state: Dict[str, datetime] = {}
    
    async def initialize(self):
        """Initialize the failover client"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.default_timeout)
        )
        logger.info("Registry failover client initialized")
    
    async def cleanup(self):
        """Clean up resources"""
        if self.session:
            await self.session.close()
        logger.info("Registry failover client cleaned up")
    
    def _is_circuit_open(self, registry_name: str) -> bool:
        """Check if circuit breaker is open for a registry"""
        if registry_name not in self.circuit_breaker_state:
            return False
        
        circuit_time = self.circuit_breaker_state[registry_name]
        now = datetime.now(timezone.utc)
        return (now - circuit_time).total_seconds() < self.circuit_breaker_timeout
    
    def _open_circuit(self, registry_name: str):
        """Open circuit breaker for a registry"""
        self.circuit_breaker_state[registry_name] = datetime.now(timezone.utc)
        logger.warning(f"Opened circuit breaker for registry '{registry_name}'")
    
    def _close_circuit(self, registry_name: str):
        """Close circuit breaker for a registry"""
        if registry_name in self.circuit_breaker_state:
            del self.circuit_breaker_state[registry_name]
            logger.info(f"Closed circuit breaker for registry '{registry_name}'")
    
    async def _make_request(
        self, 
        registry_name: str, 
        method: str, 
        path: str, 
        **kwargs
    ) -> Tuple[bool, Any, Optional[str]]:
        """
        Make a request to a specific registry
        
        Returns:
            (success, response_data, error_message)
        """
        config = self.health_monitor.registries.get(registry_name)
        if not config:
            return False, None, f"Registry '{registry_name}' not configured"
        
        if not config.enabled:
            return False, None, f"Registry '{registry_name}' is disabled"
        
        # Check circuit breaker
        if self._is_circuit_open(registry_name):
            return False, None, f"Circuit breaker open for '{registry_name}'"
        
        url = f"{config.url.rstrip('/')}/{path.lstrip('/')}"
        
        # Prepare headers
        headers = config.headers.copy() if config.headers else {}
        if config.api_key:
            headers['Authorization'] = f'Bearer {config.api_key}'
        
        # Add any additional headers from kwargs
        if 'headers' in kwargs:
            headers.update(kwargs.pop('headers'))
        
        # Set timeout
        timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)
        
        try:
            async with self.session.request(
                method, 
                url, 
                headers=headers, 
                timeout=timeout, 
                **kwargs
            ) as response:
                
                if response.status >= 200 and response.status < 300:
                    try:
                        data = await response.json()
                        self._close_circuit(registry_name)  # Success, close circuit if open
                        return True, data, None
                    except json.JSONDecodeError:
                        # If not JSON, return text
                        text = await response.text()
                        self._close_circuit(registry_name)
                        return True, text, None
                else:
                    error_msg = f"HTTP {response.status}"
                    try:
                        error_text = await response.text()
                        if error_text:
                            error_msg += f": {error_text}"
                    except:
                        pass
                    
                    # Open circuit on server errors
                    if response.status >= 500:
                        self._open_circuit(registry_name)
                    
                    return False, None, error_msg
        
        except asyncio.TimeoutError:
            self._open_circuit(registry_name)
            return False, None, "Request timeout"
        except aiohttp.ClientError as e:
            self._open_circuit(registry_name)
            return False, None, f"Connection error: {str(e)}"
        except Exception as e:
            self._open_circuit(registry_name)
            return False, None, f"Unexpected error: {str(e)}"
    
    async def make_request_with_failover(
        self, 
        method: str, 
        path: str, 
        use_primary_only: bool = False,
        **kwargs
    ) -> FailoverResult:
        """
        Make a request with automatic failover to backup registries
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: API path to request
            use_primary_only: If True, only try the primary registry
            **kwargs: Additional arguments for the request
        
        Returns:
            FailoverResult with success status and details
        """
        start_time = asyncio.get_event_loop().time()
        attempts = []
        
        # Get registries to try
        if use_primary_only:
            primary = self.health_monitor.get_primary_registry()
            registries_to_try = [primary] if primary else []
        else:
            registries_to_try = self.health_monitor.get_healthy_registries()
        
        if not registries_to_try:
            return FailoverResult(
                success=False,
                registry_used=None,
                response_data=None,
                error="No healthy registries available",
                attempts=[],
                response_time_ms=None
            )
        
        # Try each registry with retries
        for registry_name in registries_to_try:
            for retry in range(self.max_retries_per_registry):
                success, response_data, error = await self._make_request(
                    registry_name, method, path, **kwargs
                )
                
                if success:
                    end_time = asyncio.get_event_loop().time()
                    response_time_ms = (end_time - start_time) * 1000
                    
                    logger.info(f"Request successful using registry '{registry_name}' "
                              f"(attempt {retry + 1}/{self.max_retries_per_registry})")
                    
                    return FailoverResult(
                        success=True,
                        registry_used=registry_name,
                        response_data=response_data,
                        error=None,
                        attempts=attempts + [(registry_name, "success")],
                        response_time_ms=response_time_ms
                    )
                else:
                    attempts.append((registry_name, error))
                    logger.warning(f"Request failed for registry '{registry_name}' "
                                 f"(attempt {retry + 1}/{self.max_retries_per_registry}): {error}")
                    
                    # Wait before retry (except on last attempt)
                    if retry < self.max_retries_per_registry - 1:
                        await asyncio.sleep(self.backoff_delay * (retry + 1))
        
        # All registries failed
        return FailoverResult(
            success=False,
            registry_used=None,
            response_data=None,
            error="All registries failed",
            attempts=attempts,
            response_time_ms=None
        )
    
    async def get_servers(
        self, 
        query: Optional[str] = None,
        tags: Optional[List[str]] = None,
        limit: Optional[int] = None
    ) -> FailoverResult:
        """Get servers from registries with failover"""
        params = {}
        if query:
            params['q'] = query
        if tags:
            params['tags'] = ','.join(tags)
        if limit:
            params['limit'] = limit
        
        return await self.make_request_with_failover(
            'GET', 
            '/api/servers',
            params=params
        )
    
    async def get_server_details(self, server_id: str) -> FailoverResult:
        """Get server details with failover"""
        return await self.make_request_with_failover(
            'GET', 
            f'/api/servers/{server_id}'
        )
    
    async def search_tools(
        self, 
        query: str,
        limit: Optional[int] = None
    ) -> FailoverResult:
        """Search tools across registries with failover"""
        params = {'q': query}
        if limit:
            params['limit'] = limit
        
        return await self.make_request_with_failover(
            'GET', 
            '/api/tools/search',
            params=params
        )
    
    async def get_registry_status(self) -> FailoverResult:
        """Get registry status information"""
        return await self.make_request_with_failover(
            'GET', 
            '/api/status'
        )
    
    async def register_server(self, server_data: Dict[str, Any]) -> FailoverResult:
        """Register a server with failover (tries primary registry only)"""
        return await self.make_request_with_failover(
            'POST', 
            '/api/servers',
            json=server_data,
            use_primary_only=True  # Only use primary for write operations
        )
    
    async def update_server(self, server_id: str, server_data: Dict[str, Any]) -> FailoverResult:
        """Update a server with failover (tries primary registry only)"""
        return await self.make_request_with_failover(
            'PUT', 
            f'/api/servers/{server_id}',
            json=server_data,
            use_primary_only=True
        )
    
    async def delete_server(self, server_id: str) -> FailoverResult:
        """Delete a server with failover (tries primary registry only)"""
        return await self.make_request_with_failover(
            'DELETE', 
            f'/api/servers/{server_id}',
            use_primary_only=True
        )
    
    async def bulk_import_servers(
        self, 
        source_registry: Optional[str] = None
    ) -> FailoverResult:
        """
        Bulk import servers from a backup registry to primary
        
        This is useful for disaster recovery scenarios
        """
        primary = self.health_monitor.get_primary_registry()
        if not primary:
            return FailoverResult(
                success=False,
                registry_used=None,
                response_data=None,
                error="No primary registry available for import",
                attempts=[],
                response_time_ms=None
            )
        
        # Get source registry (use first backup if not specified)
        if not source_registry:
            backups = self.health_monitor.get_backup_registries()
            if not backups:
                return FailoverResult(
                    success=False,
                    registry_used=None,
                    response_data=None,
                    error="No backup registries available for import",
                    attempts=[],
                    response_time_ms=None
                )
            source_registry = backups[0]
        
        # Get servers from source registry
        source_result = await self.make_request_with_failover(
            'GET', '/api/servers'
        )
        
        if not source_result.success:
            return FailoverResult(
                success=False,
                registry_used=None,
                response_data=None,
                error=f"Failed to get servers from source registry: {source_result.error}",
                attempts=source_result.attempts,
                response_time_ms=None
            )
        
        servers = source_result.response_data.get('servers', [])
        imported_count = 0
        failed_count = 0
        
        # Import each server to primary registry
        for server in servers:
            import_result = await self.register_server(server)
            if import_result.success:
                imported_count += 1
            else:
                failed_count += 1
                logger.warning(f"Failed to import server {server.get('name', 'unknown')}: {import_result.error}")
        
        return FailoverResult(
            success=True,
            registry_used=primary,
            response_data={
                "imported_count": imported_count,
                "failed_count": failed_count,
                "total_servers": len(servers),
                "source_registry": source_registry
            },
            error=None,
            attempts=[],
            response_time_ms=None
        )
    
    def get_failover_stats(self) -> Dict[str, Any]:
        """Get failover statistics and current state"""
        healthy_registries = self.health_monitor.get_healthy_registries()
        primary = self.health_monitor.get_primary_registry()
        backup_count = len(self.health_monitor.get_backup_registries())
        
        circuit_breaker_info = {}
        now = datetime.now(timezone.utc)
        for registry_name, circuit_time in self.circuit_breaker_state.items():
            remaining_seconds = self.circuit_breaker_timeout - (now - circuit_time).total_seconds()
            circuit_breaker_info[registry_name] = {
                "open_since": circuit_time.isoformat(),
                "remaining_seconds": max(0, remaining_seconds)
            }
        
        return {
            "healthy_registries_count": len(healthy_registries),
            "primary_registry": primary,
            "backup_registries_count": backup_count,
            "circuit_breakers_open": len(circuit_breaker_info),
            "circuit_breaker_details": circuit_breaker_info,
            "failover_available": backup_count > 0,
            "system_status": "healthy" if primary else "degraded"
        }