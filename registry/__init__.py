"""
MCP Registry Package

This package provides registry functionality for MCP (Model Context Protocol) servers,
including health monitoring, failover capabilities, and server discovery.
"""

from .registry_health_monitor import (
    RegistryHealthMonitor,
    RegistryConfig,
    RegistryStatus,
    RegistryHealthMetrics,
    HealthCheckResult
)

from .registry_failover_client import (
    RegistryFailoverClient,
    FailoverResult
)

__version__ = "0.1.0"
__all__ = [
    "RegistryHealthMonitor",
    "RegistryConfig", 
    "RegistryStatus",
    "RegistryHealthMetrics",
    "HealthCheckResult",
    "RegistryFailoverClient",
    "FailoverResult"
]