"""
MCP Registry Health Monitoring and Failover System

This module provides comprehensive health monitoring and failover capabilities
for external MCP registries, ensuring high availability and resilience.
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

import aiohttp
import aiofiles

logger = logging.getLogger(__name__)


class RegistryStatus(Enum):
    """Registry health status enumeration"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"
    MAINTENANCE = "maintenance"


@dataclass
class RegistryConfig:
    """Configuration for an external MCP registry"""
    name: str
    url: str
    priority: int = 1  # Lower number = higher priority
    timeout_seconds: int = 10
    retry_attempts: int = 3
    retry_delay_seconds: int = 5
    health_check_interval_seconds: int = 30
    enabled: bool = True
    api_key: Optional[str] = None
    headers: Optional[Dict[str, str]] = None


@dataclass
class RegistryHealthMetrics:
    """Health metrics for a registry"""
    status: RegistryStatus
    last_check_time: datetime
    response_time_ms: Optional[float]
    success_rate: float  # Percentage over last N checks
    consecutive_failures: int
    last_error: Optional[str]
    uptime_percentage: float  # Over last 24 hours
    total_requests: int
    successful_requests: int


@dataclass
class HealthCheckResult:
    """Result of a single health check"""
    registry_name: str
    status: RegistryStatus
    response_time_ms: Optional[float]
    error: Optional[str]
    timestamp: datetime
    details: Optional[Dict[str, Any]] = None


class RegistryHealthMonitor:
    """
    Monitors health of multiple MCP registries and provides failover capabilities
    """
    
    def __init__(self, config_file_path: Optional[Path] = None):
        self.registries: Dict[str, RegistryConfig] = {}
        self.health_metrics: Dict[str, RegistryHealthMetrics] = {}
        self.health_history: Dict[str, List[HealthCheckResult]] = {}
        self.config_file_path = config_file_path
        self.monitoring_task: Optional[asyncio.Task] = None
        self.is_monitoring = False
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Failover configuration
        self.max_history_size = 1000
        self.health_check_timeout = 30
        self.circuit_breaker_threshold = 5  # Consecutive failures before marking unhealthy
        
        # Callbacks for status changes
        self.status_change_callbacks: List[callable] = []
    
    async def initialize(self):
        """Initialize the health monitor"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.health_check_timeout)
        )
        
        if self.config_file_path and self.config_file_path.exists():
            await self.load_config()
        
        logger.info("Registry health monitor initialized")
    
    async def cleanup(self):
        """Clean up resources"""
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        if self.session:
            await self.session.close()
        
        logger.info("Registry health monitor cleaned up")
    
    async def load_config(self):
        """Load registry configurations from file"""
        try:
            async with aiofiles.open(self.config_file_path, 'r') as f:
                content = await f.read()
                config_data = json.loads(content)
                
                for registry_data in config_data.get("registries", []):
                    config = RegistryConfig(**registry_data)
                    await self.add_registry(config)
                    
            logger.info(f"Loaded {len(self.registries)} registry configurations")
        except Exception as e:
            logger.error(f"Failed to load registry config: {e}")
    
    async def save_config(self):
        """Save current registry configurations to file"""
        if not self.config_file_path:
            return
            
        try:
            config_data = {
                "registries": [asdict(config) for config in self.registries.values()],
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Ensure directory exists
            self.config_file_path.parent.mkdir(parents=True, exist_ok=True)
            
            async with aiofiles.open(self.config_file_path, 'w') as f:
                await f.write(json.dumps(config_data, indent=2))
                
            logger.info("Registry configuration saved")
        except Exception as e:
            logger.error(f"Failed to save registry config: {e}")
    
    async def add_registry(self, config: RegistryConfig):
        """Add a new registry to monitor"""
        self.registries[config.name] = config
        
        # Initialize health metrics
        self.health_metrics[config.name] = RegistryHealthMetrics(
            status=RegistryStatus.UNKNOWN,
            last_check_time=datetime.now(timezone.utc),
            response_time_ms=None,
            success_rate=0.0,
            consecutive_failures=0,
            last_error=None,
            uptime_percentage=0.0,
            total_requests=0,
            successful_requests=0
        )
        
        self.health_history[config.name] = []
        
        # Perform initial health check
        await self.check_registry_health(config.name)
        
        # Save configuration
        await self.save_config()
        
        logger.info(f"Added registry '{config.name}' for monitoring")
    
    async def remove_registry(self, registry_name: str):
        """Remove a registry from monitoring"""
        if registry_name in self.registries:
            del self.registries[registry_name]
            del self.health_metrics[registry_name]
            del self.health_history[registry_name]
            
            await self.save_config()
            logger.info(f"Removed registry '{registry_name}' from monitoring")
    
    async def start_monitoring(self):
        """Start continuous health monitoring"""
        if self.is_monitoring:
            return
            
        self.is_monitoring = True
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Started registry health monitoring")
    
    async def stop_monitoring(self):
        """Stop health monitoring"""
        self.is_monitoring = False
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        logger.info("Stopped registry health monitoring")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                # Check all enabled registries
                check_tasks = []
                for name, config in self.registries.items():
                    if config.enabled:
                        check_tasks.append(self.check_registry_health(name))
                
                if check_tasks:
                    await asyncio.gather(*check_tasks, return_exceptions=True)
                
                # Wait for the shortest interval among all registries
                min_interval = min(
                    config.health_check_interval_seconds 
                    for config in self.registries.values() 
                    if config.enabled
                ) if self.registries else 60
                
                await asyncio.sleep(min_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(10)  # Back off on error
    
    async def check_registry_health(self, registry_name: str) -> HealthCheckResult:
        """Perform health check on a specific registry"""
        config = self.registries.get(registry_name)
        if not config:
            raise ValueError(f"Registry '{registry_name}' not found")
        
        start_time = time.time()
        result = HealthCheckResult(
            registry_name=registry_name,
            status=RegistryStatus.UNKNOWN,
            response_time_ms=None,
            error=None,
            timestamp=datetime.now(timezone.utc)
        )
        
        try:
            # Prepare headers
            headers = config.headers.copy() if config.headers else {}
            if config.api_key:
                headers['Authorization'] = f'Bearer {config.api_key}'
            
            # Perform health check request
            health_url = f"{config.url.rstrip('/')}/health"
            
            timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)
            async with self.session.get(health_url, headers=headers, timeout=timeout) as response:
                response_time = (time.time() - start_time) * 1000
                result.response_time_ms = response_time
                
                if response.status == 200:
                    result.status = RegistryStatus.HEALTHY
                    
                    # Try to parse response for additional details
                    try:
                        data = await response.json()
                        result.details = data
                    except:
                        pass
                        
                elif response.status in [502, 503, 504]:
                    result.status = RegistryStatus.DEGRADED
                    result.error = f"HTTP {response.status}"
                else:
                    result.status = RegistryStatus.UNHEALTHY
                    result.error = f"HTTP {response.status}"
        
        except asyncio.TimeoutError:
            result.status = RegistryStatus.UNHEALTHY
            result.error = "Timeout"
        except aiohttp.ClientError as e:
            result.status = RegistryStatus.UNHEALTHY
            result.error = f"Connection error: {str(e)}"
        except Exception as e:
            result.status = RegistryStatus.UNHEALTHY
            result.error = f"Unexpected error: {str(e)}"
        
        # Update metrics
        await self._update_health_metrics(result)
        
        return result
    
    async def _update_health_metrics(self, result: HealthCheckResult):
        """Update health metrics based on check result"""
        metrics = self.health_metrics[result.registry_name]
        
        # Update basic metrics
        metrics.last_check_time = result.timestamp
        metrics.response_time_ms = result.response_time_ms
        metrics.last_error = result.error
        metrics.total_requests += 1
        
        # Update success tracking
        if result.status == RegistryStatus.HEALTHY:
            metrics.successful_requests += 1
            metrics.consecutive_failures = 0
        else:
            metrics.consecutive_failures += 1
        
        # Calculate success rate
        metrics.success_rate = (metrics.successful_requests / metrics.total_requests) * 100
        
        # Update status with circuit breaker logic
        old_status = metrics.status
        if metrics.consecutive_failures >= self.circuit_breaker_threshold:
            metrics.status = RegistryStatus.UNHEALTHY
        else:
            metrics.status = result.status
        
        # Calculate uptime percentage (last 24 hours)
        await self._calculate_uptime(result.registry_name)
        
        # Store in history
        self.health_history[result.registry_name].append(result)
        
        # Trim history to max size
        if len(self.health_history[result.registry_name]) > self.max_history_size:
            self.health_history[result.registry_name] = \
                self.health_history[result.registry_name][-self.max_history_size:]
        
        # Notify status change
        if old_status != metrics.status:
            await self._notify_status_change(result.registry_name, old_status, metrics.status)
    
    async def _calculate_uptime(self, registry_name: str):
        """Calculate uptime percentage for the last 24 hours"""
        now = datetime.now(timezone.utc)
        since = now - timedelta(hours=24)
        
        history = self.health_history[registry_name]
        recent_checks = [
            check for check in history 
            if check.timestamp >= since
        ]
        
        if not recent_checks:
            return
        
        healthy_checks = len([
            check for check in recent_checks 
            if check.status == RegistryStatus.HEALTHY
        ])
        
        uptime_percentage = (healthy_checks / len(recent_checks)) * 100
        self.health_metrics[registry_name].uptime_percentage = uptime_percentage
    
    async def _notify_status_change(self, registry_name: str, old_status: RegistryStatus, new_status: RegistryStatus):
        """Notify registered callbacks about status changes"""
        logger.info(f"Registry '{registry_name}' status changed: {old_status.value} -> {new_status.value}")
        
        for callback in self.status_change_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(registry_name, old_status, new_status)
                else:
                    callback(registry_name, old_status, new_status)
            except Exception as e:
                logger.error(f"Error in status change callback: {e}")
    
    def add_status_change_callback(self, callback: callable):
        """Add a callback for status change notifications"""
        self.status_change_callbacks.append(callback)
    
    def remove_status_change_callback(self, callback: callable):
        """Remove a status change callback"""
        if callback in self.status_change_callbacks:
            self.status_change_callbacks.remove(callback)
    
    def get_healthy_registries(self) -> List[str]:
        """Get list of currently healthy registries, ordered by priority"""
        healthy = []
        for name, metrics in self.health_metrics.items():
            if (metrics.status == RegistryStatus.HEALTHY and 
                self.registries[name].enabled):
                healthy.append(name)
        
        # Sort by priority (lower number = higher priority)
        healthy.sort(key=lambda name: self.registries[name].priority)
        return healthy
    
    def get_primary_registry(self) -> Optional[str]:
        """Get the primary (highest priority, healthy) registry"""
        healthy = self.get_healthy_registries()
        return healthy[0] if healthy else None
    
    def get_backup_registries(self) -> List[str]:
        """Get backup registries (healthy but not primary)"""
        healthy = self.get_healthy_registries()
        return healthy[1:] if len(healthy) > 1 else []
    
    def get_registry_metrics(self, registry_name: Optional[str] = None) -> Dict[str, RegistryHealthMetrics]:
        """Get health metrics for specific registry or all registries"""
        if registry_name:
            return {registry_name: self.health_metrics.get(registry_name)}
        return self.health_metrics.copy()
    
    def get_registry_history(self, registry_name: str, limit: Optional[int] = None) -> List[HealthCheckResult]:
        """Get health check history for a registry"""
        history = self.health_history.get(registry_name, [])
        if limit:
            return history[-limit:]
        return history.copy()
    
    async def force_health_check(self, registry_name: Optional[str] = None):
        """Force immediate health check for one or all registries"""
        if registry_name:
            if registry_name in self.registries:
                await self.check_registry_health(registry_name)
        else:
            check_tasks = [
                self.check_registry_health(name) 
                for name in self.registries.keys()
            ]
            await asyncio.gather(*check_tasks, return_exceptions=True)
    
    async def update_registry_config(self, registry_name: str, updates: Dict[str, Any]):
        """Update configuration for a registry"""
        if registry_name not in self.registries:
            raise ValueError(f"Registry '{registry_name}' not found")
        
        config = self.registries[registry_name]
        
        # Update configuration
        for key, value in updates.items():
            if hasattr(config, key):
                setattr(config, key, value)
        
        await self.save_config()
        logger.info(f"Updated configuration for registry '{registry_name}'")
    
    def get_system_health_summary(self) -> Dict[str, Any]:
        """Get overall system health summary"""
        total_registries = len(self.registries)
        enabled_registries = len([r for r in self.registries.values() if r.enabled])
        healthy_registries = len([
            name for name, metrics in self.health_metrics.items()
            if metrics.status == RegistryStatus.HEALTHY and self.registries[name].enabled
        ])
        
        primary_registry = self.get_primary_registry()
        backup_count = len(self.get_backup_registries())
        
        overall_status = "healthy"
        if healthy_registries == 0:
            overall_status = "critical"
        elif healthy_registries < enabled_registries * 0.5:
            overall_status = "degraded"
        
        return {
            "overall_status": overall_status,
            "total_registries": total_registries,
            "enabled_registries": enabled_registries,
            "healthy_registries": healthy_registries,
            "primary_registry": primary_registry,
            "backup_registries_count": backup_count,
            "monitoring_active": self.is_monitoring,
            "last_update": datetime.now(timezone.utc).isoformat()
        }