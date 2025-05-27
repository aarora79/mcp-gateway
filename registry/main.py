import os
import json
import secrets
import asyncio
import subprocess
import urllib.parse
import httpx

# argparse removed as we're using environment variables instead
from contextlib import asynccontextmanager
from pathlib import Path as PathLib  # Rename Path import to avoid conflict
from typing import Annotated, List, Set, Dict, Any, Union, Callable, Awaitable
from datetime import datetime, timezone
import re
from registry.auth.settings import AuthSettings
from itsdangerous import URLSafeTimedSerializer
import uvicorn
import time

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer


from mcp import ClientSession
from mcp.client.sse import sse_client


# Get configuration from environment variables
EMBEDDINGS_MODEL_NAME = os.environ.get('EMBEDDINGS_MODEL_NAME', 'all-MiniLM-L6-v2')
EMBEDDINGS_MODEL_DIMENSIONS = int(os.environ.get('EMBEDDINGS_MODEL_DIMENSIONS', '384'))

from fastapi import (
    FastAPI,
    Request,
    Depends,
    HTTPException,
    Form,
    status,
    Cookie,
    WebSocket,
    WebSocketDisconnect,
    Response,
    File, 
    UploadFile, 
    Query,
)
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Custom exception for redirecting to login
class RedirectToLogin(Exception):
    """Exception raised when user needs to be redirected to login page."""
    pass
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from dotenv import load_dotenv
import logging

# Import OAuth integration
from registry.auth.integration import integrate_oauth

# Lightweight session invalidation using session timestamps
# Instead of storing all invalidated sessions, we track logout times
SESSION_LOGOUT_TIMES: Dict[str, float] = {}
MAX_LOGOUT_ENTRIES = 1000  # Keep only recent logout times

# Cache for SECRET_KEY validation to avoid repeated validation
_SECRET_KEY_VALIDATED = False
_LAST_VALIDATED_SECRET_KEY = None

# --- OAuth 2.1 Integration --- START
from registry.auth.middleware import SessionUser

from registry.auth.integration import integrate_oauth
from registry.auth.middleware import (
    requires_scope, requires_server_access, requires_server_toggle, requires_server_edit,
    require_toggle_for_path, require_edit_for_path, require_access_for_path, 
    check_admin_scope, require_registry_admin
)
from fastapi import Path, Depends, Form, Request, HTTPException, status, WebSocket, WebSocketDisconnect
# --- OAuth 2.1 Integration --- END

# --- Define paths based on container structure --- START
CONTAINER_APP_DIR = PathLib("/app")
CONTAINER_REGISTRY_DIR = CONTAINER_APP_DIR / "registry"
CONTAINER_LOG_DIR = CONTAINER_APP_DIR / "logs"
EMBEDDINGS_MODEL_DIR = CONTAINER_REGISTRY_DIR / "models" / EMBEDDINGS_MODEL_NAME
# --- Define paths based on container structure --- END

# Helper function to run async dependencies
async def run_async_dependency(dependency, kwargs):
    """Run an async dependency with the given kwargs."""
    if asyncio.iscoroutinefunction(dependency):
        return await dependency(**kwargs)
    return dependency(**kwargs)

# Determine the base directory of this script (registry folder)
# BASE_DIR = PathLib(__file__).resolve().parent # Less relevant inside container

# --- Load .env if it exists in the expected location relative to the app --- START
# Assumes .env might be mounted at /app/.env or similar
# DOTENV_PATH = BASE_DIR / ".env"
DOTENV_PATH = CONTAINER_REGISTRY_DIR / ".env" # Use container path
if DOTENV_PATH.exists():
    load_dotenv(dotenv_path=DOTENV_PATH)
    print(f"Loaded environment variables from {DOTENV_PATH}")
else:
    print(f"Warning: .env file not found at {DOTENV_PATH}")
# --- Load .env if it exists in the expected location relative to the app --- END

# --- Configuration & State (Paths relative to container structure) ---
# Assumes nginx config might be placed alongside registry code
# NGINX_CONFIG_PATH = (
#     CONTAINER_REGISTRY_DIR / "nginx_mcp_revproxy.conf"
# )
NGINX_CONFIG_PATH = PathLib("/etc/nginx/conf.d/nginx_rev_proxy.conf") # Target the actual Nginx config file

# Force dev mode to be enabled for easier startup
os.environ["MCP_GATEWAY_DEV_MODE"] = "true"
# Use the mounted volume path for server definitions
SERVERS_DIR = CONTAINER_REGISTRY_DIR / "servers"
STATIC_DIR = CONTAINER_REGISTRY_DIR / "static"
TEMPLATES_DIR = CONTAINER_REGISTRY_DIR / "templates"
# NGINX_TEMPLATE_PATH = CONTAINER_REGISTRY_DIR / "nginx_template.conf"
# Use the mounted volume path for state file, keep it with servers
STATE_FILE_PATH = SERVERS_DIR / "server_state.json"
# Define log file path
# LOG_FILE_PATH = BASE_DIR / "registry.log"
LOG_FILE_PATH = CONTAINER_LOG_DIR / "registry.log"

# --- FAISS Vector DB Configuration --- START
FAISS_INDEX_PATH = SERVERS_DIR / "service_index.faiss"
FAISS_METADATA_PATH = SERVERS_DIR / "service_index_metadata.json"
EMBEDDING_MODEL_DIMENSION = EMBEDDINGS_MODEL_DIMENSIONS  # Use env var, default is 384 for all-MiniLM-L6-v2
# EMBEDDINGS_MODEL_NAME is already defined above
EMBEDDINGS_MODEL_PATH = EMBEDDINGS_MODEL_DIR  # Path derived from model name
embedding_model = None # Will be loaded in lifespan
faiss_index = None     # Will be loaded/created in lifespan
# Stores: { service_path: {"id": faiss_internal_id, "text_for_embedding": "...", "full_server_info": { ... }} }
# faiss_internal_id is the ID used with faiss_index.add_with_ids()
faiss_metadata_store = {}
next_faiss_id_counter = 0
# --- FAISS Vector DB Configuration --- END

# --- Define logger at module level (unconfigured initially) --- START
# Configure logging with process ID, filename, line number, and millisecond precision
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d - PID:%(process)d - %(filename)s:%(lineno)d - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)
# --- Define logger at module level (unconfigured initially) --- END

# In-memory state store
REGISTERED_SERVERS = {}
MOCK_SERVICE_STATE = {}
SERVER_HEALTH_STATUS = {} # Added for health check status: path -> 'healthy' | 'unhealthy' | 'checking' | 'error: <msg>'
HEALTH_CHECK_INTERVAL_SECONDS = 300 # Check every 5 minutes (restored)
HEALTH_CHECK_TIMEOUT_SECONDS = 10  # Timeout for each curl check (Increased to 10)
SERVER_LAST_CHECK_TIME = {} # path -> datetime of last check attempt (UTC)

# Force all servers to healthy status in development mode
def dev_mode_mark_servers_healthy():
    """Mark all servers as healthy in development mode."""
    if os.environ.get("MCP_GATEWAY_DEV_MODE", "").lower() in ("1", "true", "yes"):
        logger.info("Development mode enabled - marking all servers as healthy")
        for path in REGISTERED_SERVERS:
            SERVER_HEALTH_STATUS[path] = "healthy"
            SERVER_LAST_CHECK_TIME[path] = datetime.now(timezone.utc)
            
            # Get service info for this path
            service_info = REGISTERED_SERVERS[path]
            
            # Set real tools for known servers in dev mode
            server_name = path.lstrip("/")
            server_path = os.path.join(os.environ.get("SERVER_DIR", "/Users/aaronbw/Documents/DEV/v1/mcp-gateway/servers"), server_name)
            server_py_path = os.path.join(server_path, "server.py")
            
            # Check if this server has a server.py file and we haven't set tools yet
            if os.path.exists(server_py_path) and not service_info.get("real_tools_set"):
                # Try to automatically extract tools from server.py
                extracted_tools = try_extract_tools_from_server_py(server_py_path)
                
                if extracted_tools:
                    # Only set tools if we successfully extracted them
                    service_info["num_tools"] = len(extracted_tools)
                    service_info["tool_list"] = extracted_tools
                    logger.info(f"Using {len(extracted_tools)} automatically extracted tools for {path}")
                else:
                    # If extraction failed, leave tools as-is - don't show anything until the real tools are available
                    logger.warning(f"Failed to extract tools from {path}, no tools will be shown in dev mode")
                    # Make sure we don't have any old placeholder values by explicitly setting to empty
                    service_info["num_tools"] = 0
                    service_info["tool_list"] = []
                
                # Mark that we've set real tools for this server
                service_info["real_tools_set"] = True
                REGISTERED_SERVERS[path] = service_info
                logger.info(f"Set real tools for {path} in dev mode")
            # Never use placeholder tools - if we don't have real tools, set an empty list
            elif not service_info.get("tool_list"):
                service_info["num_tools"] = 0
                service_info["tool_list"] = []
                REGISTERED_SERVERS[path] = service_info
                logger.info(f"No tools set for {path} - waiting for real tools")

# --- WebSocket Connection Management ---
active_connections: Set[WebSocket] = set()

# --- Helper for extracting tools from server.py files --- START
def try_extract_tools_from_server_py(server_py_path: str) -> list:
    """
    Attempts to extract tool definitions from a server.py file.
    This is used in dev mode to provide realistic tool definitions without having to query the server.
    
    Args:
        server_py_path: Path to the server.py file
        
    Returns:
        List of tool definitions if successful, empty list otherwise
    """
    try:
        # Check if the file exists
        if not os.path.exists(server_py_path):
            logger.warning(f"Server.py file not found at {server_py_path}")
            return []
            
        # Read the file
        with open(server_py_path, "r") as f:
            content = f.read()
            
        # Look for @mcp.tool() decorated functions
        tool_pattern = r'@mcp\.tool\(\).*?def\s+(\w+)\(([^)]*)\)'
        param_pattern = r'(\w+)\s*:\s*Annotated\[(\w+),\s*Field\(\s*(?:[^)]*?description\s*=\s*"([^"]*)")?(?:[^)]*?default\s*=\s*"?([^",\)]*)"?)?'
        
        tools = []
        matches = re.finditer(tool_pattern, content, re.DOTALL)
        
        for match in matches:
            try:
                func_name = match.group(1)
                params_str = match.group(2)
                
                # Try to extract docstring for description
                func_block = content[match.end():].split('\n\n')[0]
                desc_match = re.search(r'"""(.*?)"""', func_block, re.DOTALL)
                description = desc_match.group(1).strip() if desc_match else f"Function {func_name}"
                
                # Short description (first sentence)
                short_desc = description.split('.')[0].strip()
                
                # Extract parameters
                parameters = {
                    "type": "object",
                    "properties": {}
                }
                
                param_matches = re.finditer(param_pattern, params_str, re.DOTALL)
                for param_match in param_matches:
                    param_name = param_match.group(1)
                    param_type = param_match.group(2).lower()
                    param_desc = param_match.group(3) if param_match.group(3) else f"Parameter {param_name}"
                    param_default = param_match.group(4) if param_match.group(4) else None
                    
                    param_info = {
                        "type": "string" if param_type == "str" else 
                               "number" if param_type in ["int", "float"] else 
                               "boolean" if param_type == "bool" else 
                               "string",
                        "description": param_desc
                    }
                    
                    if param_default:
                        if param_type == "str":
                            param_info["default"] = param_default
                        elif param_type == "int":
                            try:
                                param_info["default"] = int(param_default)
                            except:
                                pass
                        elif param_type == "float":
                            try:
                                param_info["default"] = float(param_default)
                            except:
                                pass
                        elif param_type == "bool":
                            param_info["default"] = param_default.lower() in ["true", "1", "yes"]
                    
                    parameters["properties"][param_name] = param_info
                
                tools.append({
                    "name": func_name,
                    "description": short_desc,
                    "parameters": parameters
                })
                
            except Exception as e:
                logger.warning(f"Error extracting tool info for {match.group(1)}: {e}")
                continue
                
        logger.info(f"Successfully extracted {len(tools)} tools from {server_py_path}")
        return tools
        
    except Exception as e:
        logger.warning(f"Failed to extract tools from {server_py_path}: {e}")
        return []
# --- Helper for extracting tools from server.py files --- END

# --- FAISS Helper Functions --- START

def _get_text_for_embedding(server_info: dict) -> str:
    """Prepares a consistent text string from server info for embedding."""
    name = server_info.get("server_name", "")
    description = server_info.get("description", "")
    tags = server_info.get("tags", [])
    tag_string = ", ".join(tags)
    return f"Name: {name}\\nDescription: {description}\\nTags: {tag_string}"

def load_faiss_data():
    global faiss_index, faiss_metadata_store, embedding_model, next_faiss_id_counter, CONTAINER_REGISTRY_DIR, SERVERS_DIR
    logger.info("Loading FAISS data and embedding model...")

    SERVERS_DIR.mkdir(parents=True, exist_ok=True)
    

    try:
        model_cache_path = CONTAINER_REGISTRY_DIR / ".cache"
        model_cache_path.mkdir(parents=True, exist_ok=True)
        
        # Set SENTENCE_TRANSFORMERS_HOME to use the defined cache path
        original_st_home = os.environ.get('SENTENCE_TRANSFORMERS_HOME')
        os.environ['SENTENCE_TRANSFORMERS_HOME'] = str(model_cache_path)
        
        # Check if the model path exists and is not empty
        model_path = PathLib(EMBEDDINGS_MODEL_PATH)
        model_exists = model_path.exists() and any(model_path.iterdir()) if model_path.exists() else False
        
        if model_exists:
            logger.info(f"Loading SentenceTransformer model from local path: {EMBEDDINGS_MODEL_PATH}")
            embedding_model = SentenceTransformer(str(EMBEDDINGS_MODEL_PATH))
        else:
            logger.info(f"Local model not found at {EMBEDDINGS_MODEL_PATH}, downloading from Hugging Face")
            embedding_model = SentenceTransformer(str(EMBEDDINGS_MODEL_NAME))
        
        # Restore original environment variable if it was set
        if original_st_home:
            os.environ['SENTENCE_TRANSFORMERS_HOME'] = original_st_home
        else:
            del os.environ['SENTENCE_TRANSFORMERS_HOME'] # Remove if not originally set
            
        logger.info("SentenceTransformer model loaded successfully.")
    except Exception as e:
        logger.error(f"Failed to load SentenceTransformer model: {e}", exc_info=True)
        embedding_model = None 

    if FAISS_INDEX_PATH.exists() and FAISS_METADATA_PATH.exists():
        try:
            logger.info(f"Loading FAISS index from {FAISS_INDEX_PATH}")
            faiss_index = faiss.read_index(str(FAISS_INDEX_PATH))
            logger.info(f"Loading FAISS metadata from {FAISS_METADATA_PATH}")
            with open(FAISS_METADATA_PATH, "r") as f:
                loaded_metadata = json.load(f)
                faiss_metadata_store = loaded_metadata.get("metadata", {})
                next_faiss_id_counter = loaded_metadata.get("next_id", 0)
            logger.info(f"FAISS data loaded. Index size: {faiss_index.ntotal if faiss_index else 0}. Next ID: {next_faiss_id_counter}")
            if faiss_index and faiss_index.d != EMBEDDING_MODEL_DIMENSION:
                logger.warning(f"Loaded FAISS index dimension ({faiss_index.d}) differs from expected ({EMBEDDING_MODEL_DIMENSION}). Re-initializing.")
                faiss_index = faiss.IndexIDMap(faiss.IndexFlatL2(EMBEDDING_MODEL_DIMENSION))
                faiss_metadata_store = {}
                next_faiss_id_counter = 0
        except Exception as e:
            logger.error(f"Error loading FAISS data: {e}. Re-initializing.", exc_info=True)
            faiss_index = faiss.IndexIDMap(faiss.IndexFlatL2(EMBEDDING_MODEL_DIMENSION))
            faiss_metadata_store = {}
            next_faiss_id_counter = 0
    else:
        logger.info("FAISS index or metadata not found. Initializing new.")
        faiss_index = faiss.IndexIDMap(faiss.IndexFlatL2(EMBEDDING_MODEL_DIMENSION))
        faiss_metadata_store = {}
        next_faiss_id_counter = 0

def save_faiss_data():
    global faiss_index, faiss_metadata_store, next_faiss_id_counter
    if faiss_index is None:
        logger.error("FAISS index is not initialized. Cannot save.")
        return
    try:
        SERVERS_DIR.mkdir(parents=True, exist_ok=True) # Ensure directory exists
        logger.info(f"Saving FAISS index to {FAISS_INDEX_PATH} (Size: {faiss_index.ntotal})")
        faiss.write_index(faiss_index, str(FAISS_INDEX_PATH))
        logger.info(f"Saving FAISS metadata to {FAISS_METADATA_PATH}")
        with open(FAISS_METADATA_PATH, "w") as f:
            json.dump({"metadata": faiss_metadata_store, "next_id": next_faiss_id_counter}, f, indent=2)
        logger.info("FAISS data saved successfully.")
    except Exception as e:
        logger.error(f"Error saving FAISS data: {e}", exc_info=True)

async def add_or_update_service_in_faiss(service_path: str, server_info: dict):
    global faiss_index, faiss_metadata_store, embedding_model, next_faiss_id_counter

    if embedding_model is None or faiss_index is None:
        logger.error("Embedding model or FAISS index not initialized. Cannot add/update service in FAISS.")
        return

    logger.info(f"Attempting to add/update service '{service_path}' in FAISS.")
    text_to_embed = _get_text_for_embedding(server_info)
    
    current_faiss_id = -1
    needs_new_embedding = True # Assume new embedding is needed

    existing_entry = faiss_metadata_store.get(service_path)

    if existing_entry:
        current_faiss_id = existing_entry["id"]
        if existing_entry.get("text_for_embedding") == text_to_embed:
            needs_new_embedding = False
            logger.info(f"Text for embedding for '{service_path}' has not changed. Will update metadata store only if server_info differs.")
        else:
            logger.info(f"Text for embedding for '{service_path}' has changed. Re-embedding required.")
    else: # New service
        current_faiss_id = next_faiss_id_counter
        next_faiss_id_counter += 1
        logger.info(f"New service '{service_path}'. Assigning new FAISS ID: {current_faiss_id}.")
        needs_new_embedding = True # Definitely needs embedding

    if needs_new_embedding:
        try:
            # Run model encoding in a separate thread to avoid blocking asyncio event loop
            embedding = await asyncio.to_thread(embedding_model.encode, [text_to_embed])
            embedding_np = np.array([embedding[0]], dtype=np.float32)
            
            ids_to_remove = np.array([current_faiss_id])
            if existing_entry: # Only attempt removal if it was an existing entry
                try:
                    # remove_ids returns number of vectors removed.
                    # It's okay if the ID isn't found (returns 0).
                    num_removed = faiss_index.remove_ids(ids_to_remove)
                    if num_removed > 0:
                        logger.info(f"Removed {num_removed} old vector(s) for FAISS ID {current_faiss_id} ({service_path}).")
                    else:
                        logger.info(f"No old vector found for FAISS ID {current_faiss_id} ({service_path}) during update, or ID not in index.")
                except Exception as e_remove: # Should be rare with IndexIDMap if ID was valid type
                    logger.warning(f"Issue removing FAISS ID {current_faiss_id} for {service_path}: {e_remove}. Proceeding to add.")
            
            faiss_index.add_with_ids(embedding_np, np.array([current_faiss_id]))
            logger.info(f"Added/Updated vector for '{service_path}' with FAISS ID {current_faiss_id}.")
        except Exception as e:
            logger.error(f"Error encoding or adding embedding for '{service_path}': {e}", exc_info=True)
            return # Don't update metadata or save if embedding failed

    # Update metadata store if new, or if text changed, or if full_server_info changed
    # --- Enrich server_info with is_enabled status before storing --- START
    enriched_server_info = server_info.copy()
    enriched_server_info["is_enabled"] = MOCK_SERVICE_STATE.get(service_path, False) # Default to False if not found
    # --- Enrich server_info with is_enabled status before storing --- END

    if existing_entry is None or needs_new_embedding or existing_entry.get("full_server_info") != enriched_server_info:
        faiss_metadata_store[service_path] = {
            "id": current_faiss_id,
            "text_for_embedding": text_to_embed,
            "full_server_info": enriched_server_info # Store the enriched server_info
        }
        logger.debug(f"Updated faiss_metadata_store for '{service_path}'.")
        await asyncio.to_thread(save_faiss_data) # Persist changes in a thread
    else:
        logger.debug(f"No changes to FAISS vector or enriched full_server_info for '{service_path}'. Skipping save.")

# --- FAISS Helper Functions --- END

async def broadcast_health_status():
    """Sends the current health status to all connected WebSocket clients."""
    if active_connections:
        logger.info(f"Broadcasting health status to {len(active_connections)} clients...")

        # Construct data payload with status and ISO timestamp string
        data_to_send = {}
        for path, status in SERVER_HEALTH_STATUS.items():
            last_checked_dt = SERVER_LAST_CHECK_TIME.get(path)
            # Send ISO string or None
            last_checked_iso = last_checked_dt.isoformat() if last_checked_dt else None
            # Get the current tool count from REGISTERED_SERVERS
            num_tools = REGISTERED_SERVERS.get(path, {}).get("num_tools", 0) # Default to 0 if not found

            data_to_send[path] = {
                "status": status,
                "last_checked_iso": last_checked_iso, # Changed key
                "num_tools": num_tools # --- Add num_tools --- START
            }
            # --- Add num_tools --- END

        message = json.dumps(data_to_send)
        disconnected_clients = set()

        # Concurrent sending
        current_connections = list(active_connections) # Make a copy of current set
        send_tasks = []

        # Schedule all send operations
        for connection in current_connections:
            # Store connection and task together for easier error handling
            send_tasks.append((connection, connection.send_text(message)))

        # Wait for all to complete
        results = await asyncio.gather(*(task for _, task in send_tasks), return_exceptions=True)

        # Process results
        for i, result in enumerate(results):
            conn, _ = send_tasks[i]
            if isinstance(result, Exception):
                logger.warning(f"Error sending status update to WebSocket client {conn.client}: {result}. Marking for removal.")
                disconnected_clients.add(conn)

        # Remove any disconnected clients
        if disconnected_clients:
            logger.info(f"Removing {len(disconnected_clients)} disconnected clients after broadcast.")
            for conn in disconnected_clients:
                if conn in active_connections:
                    active_connections.remove(conn)

# --- Setup FastAPI Application ---

# Session management configuration
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    # Generate a secure random key (32 bytes = 256 bits of entropy)
    SECRET_KEY = secrets.token_hex(32)
    logger.warning("No SECRET_KEY environment variable found. Using a randomly generated key. "
                   "While this is more secure than a hardcoded default, it will change on restart. "
                   "Set a permanent SECRET_KEY environment variable for production.")
SESSION_COOKIE_NAME = "mcp_gateway_session"
signer = URLSafeTimedSerializer(SECRET_KEY)
SESSION_MAX_AGE_SECONDS = 60 * 60 * 8  # 8 hours

# Lifespan handler to initialize and cleanup resources
@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Startup Code ---
    logger.info("Application startup. Initializing...")
    
    # Create paths if they don't exist
    # --- Ensure Directories Exist --- START
    CONTAINER_LOG_DIR.mkdir(parents=True, exist_ok=True)
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    SERVERS_DIR.mkdir(parents=True, exist_ok=True)
    # --- Ensure Directories Exist --- END

    # --- Load FAISS data and model --- START
    logger.info("Pre-loading FAISS data and model...")
    try:
        # We do this in a thread to not block
        await asyncio.to_thread(load_faiss_data)
    except Exception as e:
        logger.error(f"Error pre-loading FAISS: {e}", exc_info=True)
    # --- Load FAISS data and model --- END
    
    # --- Load server state --- START
    if STATE_FILE_PATH.exists():
        try:
            with open(STATE_FILE_PATH, "r") as f:
                MOCK_SERVICE_STATE.update(json.load(f))
            logger.info(f"Loaded server state from {STATE_FILE_PATH} with {len(MOCK_SERVICE_STATE)} entries")
        except Exception as e:
            logger.error(f"Error loading server state: {e}")
    else:
        logger.info(f"No server state file found at {STATE_FILE_PATH}. Starting with empty state.")
    # --- Load server state --- END
    
    # --- Load existing server JSON files --- START
    logger.info(f"Loading server definitions from {SERVERS_DIR}...")
    if SERVERS_DIR.exists() and SERVERS_DIR.is_dir():
        json_server_files = list(SERVERS_DIR.glob("*.json"))
        logger.info(f"Found {len(json_server_files)} JSON files in {SERVERS_DIR}")
        
        for server_file in json_server_files:
            try:
                # Skip _metadata and _index, these aren't service files
                if server_file.name.startswith("service_index_"):
                    continue
                    
                with open(server_file, "r") as f:
                    server_data = json.load(f)
                
                # Check if this is a server definition (has path, server_name, proxy_pass_url)
                if "path" in server_data and "server_name" in server_data and "proxy_pass_url" in server_data:
                    path = server_data["path"]
                    # Register the service in memory
                    REGISTERED_SERVERS[path] = server_data
                    # Mark it as either enabled or disabled, defaulting to disabled if not in state
                    is_enabled = MOCK_SERVICE_STATE.get(path, False)
                    MOCK_SERVICE_STATE[path] = is_enabled
                    # Initialize health status for this service
                    SERVER_HEALTH_STATUS[path] = "unknown"
                    logger.info(f"Loaded server definition for {server_data['server_name']} at {path} (enabled={is_enabled})")
                else:
                    logger.warning(f"Skipping incomplete server definition in {server_file}")
            except Exception as e:
                logger.error(f"Error loading server definition from {server_file}: {e}")
    else:
        logger.warning(f"Servers directory not found or not a directory: {SERVERS_DIR}")
    # --- Load existing server JSON files --- END
    
    # --- Mark servers as healthy in dev mode --- START
    dev_mode_mark_servers_healthy()
    # --- Mark servers as healthy in dev mode --- END
    
    # --- Generate initial Nginx config --- START
    logger.info("Generating initial Nginx configuration...")
    regenerate_nginx_config()
    # --- Generate initial Nginx config --- END
    
    # --- Start Health Check Background Task --- START
    # Start the background health check task
    logger.info("Starting health check background task...")
    asyncio.create_task(run_health_checks())
    # --- Start Health Check Background Task --- END
    
    logger.info("Application initialization complete. Ready to serve requests.")
    
    yield  # Application runs here
    
    # --- Cleanup Code ---
    logger.info("Application shutdown. Cleaning up...")
    
    # Ensure latest service state is saved
    try:
        with open(STATE_FILE_PATH, "w") as f:
            json.dump(MOCK_SERVICE_STATE, f, indent=2)
        logger.info(f"Saved server state to {STATE_FILE_PATH} with {len(MOCK_SERVICE_STATE)} entries")
    except Exception as e:
        logger.error(f"Error saving server state: {e}")
    
    # Any other cleanup goes here...
    logger.info("Cleanup complete. Application shutting down.")

# Create FastAPI application
app = FastAPI(
    title="MCP Gateway Registry Service",
    description="Registry service for MCP Gateway to manage server registrations",
    lifespan=lifespan,
)

# Add exception handler for RedirectToLogin
@app.exception_handler(RedirectToLogin)
async def redirect_to_login_handler(request: Request, exc: RedirectToLogin):
    """Handle RedirectToLogin exception by redirecting to login page."""
    logger.info(f"Redirecting unauthenticated user to login page from {request.url.path}")
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

# Mount static files directory
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Set up templates
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# --- Set up OAuth 2.1 integration --- START
# Call our integration function to set up OAuth 2.1 with the app
oauth_provider = integrate_oauth(app, templates)
logger.info(f"OAuth 2.1 integration setup: {'ENABLED' if oauth_provider else 'DISABLED'}")
# --- Set up OAuth 2.1 integration --- END

# -- Authentication Helper Functions --

def get_session_fingerprint(session_data: dict) -> str:
    """Generate a unique session fingerprint using session_id."""
    username = session_data.get("username", "")
    session_id = session_data.get("session_id", "")
    return f"{username}:{session_id}"

def cleanup_logout_times():
    """Clean up old logout times to prevent memory leaks."""
    global SESSION_LOGOUT_TIMES
    if len(SESSION_LOGOUT_TIMES) > MAX_LOGOUT_ENTRIES:
        # Keep only the most recent entries
        sorted_items = sorted(SESSION_LOGOUT_TIMES.items(), key=lambda x: x[1])
        SESSION_LOGOUT_TIMES = dict(sorted_items[-MAX_LOGOUT_ENTRIES//2:])

def is_session_logged_out(session_data: dict) -> bool:
    """Check if session was logged out after its creation time."""
    fingerprint = get_session_fingerprint(session_data)
    logout_time = SESSION_LOGOUT_TIMES.get(fingerprint)
    
    if logout_time is None:
        return False
    
    # Parse session login time
    login_time_str = session_data.get("login_time", "")
    if not login_time_str:
        return False
    
    try:
        from datetime import datetime
        login_time = datetime.fromisoformat(login_time_str.replace('Z', '+00:00'))
        login_timestamp = login_time.timestamp()
        return logout_time > login_timestamp
    except (ValueError, AttributeError):
        return False

def handle_auth_failure(request: Request, detail: str):
    """Handle authentication failure by redirecting browser requests or raising HTTPException for API requests."""
    accept_header = request.headers.get("accept", "")
    is_browser_request = "text/html" in accept_header
    
    if is_browser_request:
        logger.info(f"Browser request detected, redirecting to login page. Reason: {detail}")
        raise RedirectToLogin()
    else:
        logger.info(f"API request detected, returning 401. Reason: {detail}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )

def validate_secret_key(secret_key: str) -> None:
    """
    Validate that the SECRET_KEY meets security requirements.
    
    Args:
        secret_key: The secret key to validate
        
    Raises:
        ValueError: If the secret key is weak or insecure
    """
    global _SECRET_KEY_VALIDATED, _LAST_VALIDATED_SECRET_KEY
    
    # Use cache to avoid repeated validation of the same key
    if _SECRET_KEY_VALIDATED and _LAST_VALIDATED_SECRET_KEY == secret_key:
        return
    
    import re
    
    # Check minimum length (should be at least 32 characters for good entropy)
    if len(secret_key) < 32:
        raise ValueError(f"SECRET_KEY must be at least 32 characters long. Current length: {len(secret_key)}")
    
    # Check for sufficient complexity (should contain different character types)
    has_upper = bool(re.search(r'[A-Z]', secret_key))
    has_lower = bool(re.search(r'[a-z]', secret_key))
    has_digit = bool(re.search(r'[0-9]', secret_key))
    has_special = bool(re.search(r'[^A-Za-z0-9]', secret_key))
    
    complexity_score = sum([has_upper, has_lower, has_digit, has_special])
    
    # For randomly generated hex keys, require at least 2 character types (numbers + letters)
    # For other keys, require at least 3 character types for good complexity
    min_complexity = 2 if all(c in '0123456789abcdefABCDEF' for c in secret_key) else 3
    
    if complexity_score < min_complexity:
        if min_complexity == 2:
            raise ValueError(
                "SECRET_KEY lacks sufficient complexity. For hex keys, ensure both letters and numbers are present."
            )
        else:
            raise ValueError(
                "SECRET_KEY lacks sufficient complexity. It should contain at least 3 of: "
                "uppercase letters, lowercase letters, digits, special characters"
            )
    
    # Check for obvious patterns
    if secret_key.lower() in secret_key or secret_key == secret_key[::-1]:
        # Additional pattern checks could be added here
        pass
    
    # Mark as validated and cache the key
    _SECRET_KEY_VALIDATED = True
    _LAST_VALIDATED_SECRET_KEY = secret_key
    logger.info("SECRET_KEY validation passed - key meets security requirements")

def get_current_user(request: Request, session: str = Cookie(None)) -> str:
    """Get the current user from session cookie, or redirect to login for browser requests."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "insecure-default-key-for-testing-only")
    
    # Validate SECRET_KEY strength before using it for authentication
    try:
        validate_secret_key(SECRET_KEY)
    except ValueError as e:
        logger.error(f"SECRET_KEY validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: Invalid SECRET_KEY. Please configure a strong secret key."
        )
    
    session_cookie_name = "mcp_gateway_session"
    default_session_expr = 3600  # Default: 1 hour
    USERNAME_ENV = os.environ.get("ADMIN_USER", "admin")
    PASSWORD_ENV = os.environ.get("ADMIN_PASSWORD", "password")

    # Log detailed debugging information
    logger.info(f"Authentication check - Path: {request.url.path}, Host: {request.headers.get('host')}")
    logger.info(f"Request cookies: {request.cookies}")
    
    # DEBUG: Always consider the user as authenticated during testing
    disable_auth_env = os.environ.get("MCP_GATEWAY_DISABLE_AUTH", "").lower()
    if disable_auth_env in ("1", "true", "yes"):
        logger.warning("AUTH DISABLED: Using automatic admin access")
        # Add admin user to request context for RBAC
        # Create the user object but don't try to set it directly on request
        user = SessionUser(USERNAME_ENV, ["mcp-admin"])
        # Store the user in request.state which is designed for this purpose
        request.state.user = user
        return USERNAME_ENV

    # Check for session in cookies directly if Cookie dependency didn't work
    if not session and session_cookie_name in request.cookies:
        session = request.cookies[session_cookie_name]
        logger.info(f"Using session from request.cookies: {session[:20]}...")
        
    # No session? Use helper function to handle browser vs API requests
    if not session:
        logger.warning("No session cookie found.")
        handle_auth_failure(request, "Not authenticated")

    # Unsign the cookie
    try:
        s = URLSafeTimedSerializer(SECRET_KEY)
        MAX_AGE = int(os.environ.get("SESSION_EXPIRATION_SECONDS", default_session_expr))
        data = s.loads(session, max_age=MAX_AGE)
        
        # Check if this session has been logged out
        if is_session_logged_out(data):
            fingerprint = get_session_fingerprint(data)
            logger.warning(f"Session {fingerprint} was logged out after creation")
            handle_auth_failure(request, "Session has been logged out")
        
        # If OAuth session
        if data.get("is_oauth", False):
            logger.info("Validated OAuth session.")
            
            # Extract groups from session if available
            groups = data.get("groups", [])
            username = data.get("username", "oauth_user")
            
            # Create SessionUser and attach to request
            if groups:
                logger.info(f"Session contains groups: {groups}")
                # Create the user object but don't try to set it directly on request
                # Since FastAPI's Request object doesn't support attribute setting
                user = SessionUser(username, groups)
                # Store the user in request.state which is designed for this purpose
                request.state.user = user
                # Log mapped scopes for debugging
                if hasattr(user, "scopes"):
                    logger.info(f"User {username} groups mapped to scopes: {user.scopes}")
                
            return username
        
        # Check if regular session data looks valid
        username = data.get("username")
        is_authenticated = data.get("authenticated", False)
        
        if username and is_authenticated:
            logger.debug(f"Validated session for {username}")
            # Create a standard user with admin permissions for non-OAuth sessions
            # Create the user object but don't try to set it directly on request
            user = SessionUser(username, ["mcp-admin"])
            # Store the user in request.state which is designed for this purpose
            request.state.user = user
            return username
            
        logger.warning(f"Session found but invalid structure: {data}")
        handle_auth_failure(request, "Invalid session")
    except SignatureExpired:
        logger.warning("Session expired")
        handle_auth_failure(request, "Session expired")
    except BadSignature:
        logger.warning("Invalid session signature")
        handle_auth_failure(request, "Invalid session")
    except Exception as e:
        logger.error(f"Error validating session: {e}")
        handle_auth_failure(request, "Authentication error")


def api_auth(request: Request, session: str = Cookie(None)) -> str:
    """Similar to get_current_user but returns UnauthorizedResponse instead of redirects."""
    try:
        username = get_current_user(request, session)
        
        # Log the user's scopes for debugging
        if hasattr(request.state, "user") and hasattr(request.state.user, "scopes"):
            scopes = request.state.user.scopes
            logger.info(f"API Auth - User {username} has scopes: {scopes}")
        else:
            logger.warning(f"API Auth - User {username} has no scopes attribute")
            
        return username
    except HTTPException as http_exc:
        # Log authentication failures
        logger.warning(f"API Auth failed: {http_exc.detail}")
        
        # Convert HTTPException to JSON response
        return JSONResponse(
            status_code=http_exc.status_code,
            content={"detail": http_exc.detail}
        )

# --- Authentication Routes ---

@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    """Handle login form submission."""
    USERNAME_ENV = os.environ.get("ADMIN_USER", "admin")
    PASSWORD_ENV = os.environ.get("ADMIN_PASSWORD", "password")
    SECRET_KEY = os.environ.get("SECRET_KEY", "insecure-default-key-for-testing-only")
    
    # Validate SECRET_KEY strength before using it for session creation
    try:
        validate_secret_key(SECRET_KEY)
    except ValueError as e:
        logger.error(f"SECRET_KEY validation failed during login: {e}")
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Server configuration error. Please contact administrator.",
                "user_has_toggle_scope": lambda server_path: user_has_toggle_scope(request, server_path),
                "user_has_edit_scope": lambda server_path: user_has_edit_scope(request, server_path),
                "user_has_admin_scope": lambda: user_has_admin_scope(request)
            }
        )
    
    session_cookie_name = "mcp_gateway_session"
    session_max_age = 60 * 60 * 8  # 8 hours

    # Check credentials
    if username == USERNAME_ENV and password == PASSWORD_ENV:
        # Create session data
        s = URLSafeTimedSerializer(SECRET_KEY)
        session_data = {
            "username": username,
            "authenticated": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "session_id": secrets.token_hex(16),
        }
        session_cookie = s.dumps(session_data)
        
        # Redirect to home with session cookie
        response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            key=session_cookie_name,
            value=session_cookie,
            max_age=session_max_age,
            httponly=True,
        )
        return response
    else:
        # Show login form with error
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Invalid username or password",
                "user_has_toggle_scope": lambda server_path: user_has_toggle_scope(request, server_path),
                "user_has_edit_scope": lambda server_path: user_has_edit_scope(request, server_path),
                "user_has_admin_scope": lambda: user_has_admin_scope(request)
            },
        )


def get_idp_logout_url_fast(provider_type: str, request: Request) -> str:
    """Generate IdP logout URL in a provider-agnostic way (optimized for speed)."""
    try:
        # Quick check for Cognito without heavy AuthSettings initialization
        if provider_type == "cognito":
            cognito_domain = os.environ.get("MCP_AUTH_COGNITO_DOMAIN")
            client_id = os.environ.get("MCP_AUTH_CLIENT_ID")
            
            if cognito_domain and client_id:
                timestamp = int(datetime.now(timezone.utc).timestamp())
                scheme = request.url.scheme or "http"
                host = request.headers.get('host', 'localhost:7860')
                return_uri = f"{scheme}://{host}/login?t={timestamp}&signed_out=true&complete=true"
                logout_url = f"https://{cognito_domain}/logout?client_id={client_id}&logout_uri={urllib.parse.quote(return_uri)}"
                return logout_url
        
        # For other providers, fall back to the original function if needed
        # but for now, just return None to avoid blocking
        return None
        
    except Exception:
        # Fail silently to avoid blocking logout
        return None

def get_idp_logout_url_fast(provider_type: str, request: Request) -> str:
    """Generate IdP logout URL in a provider-agnostic way (optimized for speed)."""
    try:
        # Quick check for Cognito without heavy AuthSettings initialization
        if provider_type == "cognito":
            cognito_domain = os.environ.get("MCP_AUTH_COGNITO_DOMAIN")
            client_id = os.environ.get("MCP_AUTH_CLIENT_ID")
            
            if cognito_domain and client_id:
                timestamp = int(datetime.now(timezone.utc).timestamp())
                scheme = request.url.scheme or "http"
                host = request.headers.get('host', 'localhost:7860')
                return_uri = f"{scheme}://{host}/login?t={timestamp}&signed_out=true&complete=true"
                logout_url = f"https://{cognito_domain}/logout?client_id={client_id}&logout_uri={urllib.parse.quote(return_uri)}"
                return logout_url
        
        # For other providers, fall back to the original function if needed
        # but for now, just return None to avoid blocking
        return None
        
    except Exception:
        # Fail silently to avoid blocking logout
        return None

def get_idp_logout_url(provider_type: str, request: Request) -> str:
    """Generate IdP logout URL in a provider-agnostic way."""
    logger.info(f"Generating IdP logout URL for provider: {provider_type}")
    try:
        auth_settings = AuthSettings()
        logger.info(f"Auth settings - enabled: {auth_settings.enabled}, has idp_settings: {auth_settings.idp_settings is not None}")
        
        if not (auth_settings.enabled and auth_settings.idp_settings):
            logger.warning("Auth not enabled or no IdP settings available")
            return None
            
        timestamp = int(datetime.now(timezone.utc).timestamp())
        scheme = request.url.scheme or "http"
        host = request.headers.get('host', 'localhost:7860')
        return_uri = f"{scheme}://{host}/login?t={timestamp}&signed_out=true&complete=true"
        logger.info(f"Generated return URI: {return_uri}")
        
        if provider_type == "cognito":
            client_id = auth_settings.idp_settings.client_id
            cognito_domain = os.environ.get("MCP_AUTH_COGNITO_DOMAIN")
            logger.info(f"Cognito config - client_id: {client_id is not None}, domain: {cognito_domain}")
            if cognito_domain and client_id:
                logout_url = f"https://{cognito_domain}/logout?client_id={client_id}&logout_uri={urllib.parse.quote(return_uri)}"
                logger.info(f"Generated Cognito logout URL: {logout_url}")
                return logout_url
            else:
                logger.warning("Missing Cognito client_id or domain")
        # Add other IdP logout URL generation here
        elif provider_type == "azure":
            # return azure_logout_url(auth_settings, return_uri)
            pass
        elif provider_type == "auth0":
            # return auth0_logout_url(auth_settings, return_uri)  
            pass
        
    except Exception as e:
        logger.error(f"Error generating IdP logout URL for {provider_type}: {e}")
    
    logger.warning(f"No logout URL generated for provider: {provider_type}")
    return None

@app.get("/logout")
async def logout_get(request: Request):
    """
    Log out by clearing the session cookie and invalidating the session server-side.
    Provides IdP logout URLs when available.
    """
    session_cookie_name = "mcp_gateway_session"
    SECRET_KEY = os.environ.get("SECRET_KEY", "insecure-default-key-for-testing-only")
    
    # Extract session cookie manually (same approach as get_current_user)
    session = request.cookies.get(session_cookie_name)
    
    # Decode session and invalidate server-side
    provider_type = None
    username = None
    session_invalidated = False
    
    if session:
        try:
            s = URLSafeTimedSerializer(SECRET_KEY)
            session_data = s.loads(session, max_age=None)  # Don't check expiry for logout
            provider_type = session_data.get("provider_type")
            username = session_data.get("username")
            
            # Invalidate session server-side using lightweight approach
            fingerprint = get_session_fingerprint(session_data)
            SESSION_LOGOUT_TIMES[fingerprint] = time.time()
            session_invalidated = True
            
            # Only cleanup if we have too many entries (avoid unnecessary work)
            if len(SESSION_LOGOUT_TIMES) > MAX_LOGOUT_ENTRIES:
                cleanup_logout_times()
            
        except Exception as e:
            logger.warning(f"Error decoding session during logout: {e}")
    
    # Create base logout response
    timestamp = int(datetime.now(timezone.utc).timestamp())
    logout_url = f"/login?t={timestamp}&signed_out=true"
    
    # Add IdP logout URL if available (but don't block on it)
    if provider_type:
        try:
            idp_logout_url = get_idp_logout_url_fast(provider_type, request)
            if idp_logout_url:
                logout_url += f"&idp_logout={urllib.parse.quote(idp_logout_url)}"
            logout_url += f"&provider_type={provider_type}"
        except Exception:
            # Don't let IdP logout URL generation block the logout - fail silently
            pass
    
    response = RedirectResponse(url=logout_url, status_code=status.HTTP_303_SEE_OTHER)
    
    # Clear session cookie and add cache control headers
    response.delete_cookie(key=session_cookie_name, path="/", httponly=True)
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    # Removed Clear-Site-Data header to improve logout performance
    
    # Log completion with minimal info
    if username:
        logger.debug(f"Logout completed for user: {username}")
    
    return response

@app.post("/logout")
async def logout_post(request: Request):
    """Handle POST logout requests."""
    return await logout_get(request)


# --- Main Routes ---

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, username: Annotated[str, Depends(get_current_user)]):
    """Render the main index page. Requires authentication."""
    # Directly pass services to the template as in the original implementation
    service_data = []
    sorted_server_paths = sorted(
        REGISTERED_SERVERS.keys(), key=lambda p: REGISTERED_SERVERS[p]["server_name"]
    )
    
    # Get user's scopes if authenticated with OAuth 2.1
    user_scopes = set()
    has_admin_scope = False
    
    # Check if the user has OAuth-based authentication with scopes
    user_scopes = set()
    
    if hasattr(request.state, "user") and hasattr(request.state.user, "scopes"):
        user_scopes = set(request.state.user.scopes)
        # Check for admin scope which grants access to all servers
        auth_settings = AuthSettings()
        has_admin_scope = auth_settings.registry_admin_scope in user_scopes
        logger.info(f"User {request.state.user.display_name} has scopes: {user_scopes}, Admin: {has_admin_scope}")
    else:
        # Check if we have a session cookie with groups
        session_cookie = request.cookies.get("mcp_gateway_session")
        if session_cookie:
            try:
                # Use the environment variable for SECRET_KEY
                secret_key = os.environ.get("SECRET_KEY", "insecure-default-key-for-testing-only")
                s = URLSafeTimedSerializer(secret_key)
                data = s.loads(session_cookie)
                
                # Extract groups from session if available
                groups = data.get("groups", [])
                if groups:
                    # Create a SessionUser to extract scopes from groups
                    session_user = SessionUser(data.get("username", "unknown"), groups)
                    user_scopes = session_user.scopes
                    
                    # Check for admin scope
                    auth_settings = AuthSettings()
                    has_admin_scope = auth_settings.registry_admin_scope in user_scopes
                    
                    logger.info(f"User {data.get('username')} from session has groups: {groups}")
                    logger.info(f"Extracted scopes: {user_scopes}, Admin: {has_admin_scope}")
                else:
                    logger.info("No groups found in session cookie")
                    has_admin_scope = False
            except Exception as e:
                logger.error(f"Error processing session cookie: {e}")
                has_admin_scope = False
        else:
            # No scopes available - rely entirely on IdP for authorization
            has_admin_scope = False
            logger.info(f"No scopes available for user - access will be restricted")
    
    for path in sorted_server_paths:
        server_info = REGISTERED_SERVERS[path]
        server_name = server_info["server_name"]
        
        # Filter servers based on user's OAuth scopes
        if not has_admin_scope:
            # Get the required scope for this server
            auth_settings = AuthSettings()
            required_scope = auth_settings.get_server_execute_scope(path)
            
            # Skip this server if user doesn't have the required scope
            if required_scope not in user_scopes:
                logger.info(f"Skipping server {path} - user lacks required scope: {required_scope}")
                continue
        
        # Pass all required fields to the template
        service_data.append(
            {
                "display_name": server_name,
                "path": path,
                "description": server_info.get("description", ""),
                "is_enabled": MOCK_SERVICE_STATE.get(path, False),
                "tags": server_info.get("tags", []),
                "num_tools": server_info.get("num_tools", 0),
                "num_stars": server_info.get("num_stars", 0),
                "is_python": server_info.get("is_python", False),
                "license": server_info.get("license", "N/A"),
                "health_status": SERVER_HEALTH_STATUS.get(path, "unknown"),
                "last_checked_iso": SERVER_LAST_CHECK_TIME.get(path).isoformat() if SERVER_LAST_CHECK_TIME.get(path) else None
            }
        )
    
    return templates.TemplateResponse(
        "index.html", {
            "request": request,
            "services": service_data,
            "username": username,
            "user_has_toggle_scope": lambda server_path: user_has_toggle_scope(request, server_path),
            "user_has_edit_scope": lambda server_path: user_has_edit_scope(request, server_path),
            "user_has_admin_scope": lambda: user_has_admin_scope(request)
        }
    )

@app.get("/debug", response_class=HTMLResponse)
async def debug_index(request: Request, username: Annotated[str, Depends(get_current_user)]):
    """Render the debug page for diagnostic purposes."""
    return templates.TemplateResponse(
        "debug_index.html", {
            "request": request,
            "username": username,
            "user_has_toggle_scope": lambda server_path: user_has_toggle_scope(request, server_path),
            "user_has_edit_scope": lambda server_path: user_has_edit_scope(request, server_path),
            "user_has_admin_scope": lambda: user_has_admin_scope(request)
        }
    )


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, error: str = None):
    """Render the login form."""
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error,
        "user_has_toggle_scope": lambda server_path: user_has_toggle_scope(request, server_path),
        "user_has_edit_scope": lambda server_path: user_has_edit_scope(request, server_path),
        "user_has_admin_scope": lambda: user_has_admin_scope(request)
    })


@app.get("/api/servers")
async def list_servers(
    request: Request,
    username: Annotated[str, Depends(api_auth)]
):
    """Get all registered servers with their state."""
    servers_list = []
    for path, server_info in REGISTERED_SERVERS.items():
        # Create a copy of the server info and add its enabled status
        server_data = server_info.copy()
        server_data["is_enabled"] = MOCK_SERVICE_STATE.get(path, False)
        server_data["health_status"] = SERVER_HEALTH_STATUS.get(path, "unknown")
        last_checked = SERVER_LAST_CHECK_TIME.get(path)
        server_data["last_checked"] = last_checked.isoformat() if last_checked else None
        servers_list.append(server_data)
    return servers_list


# --- Function to regenerate Nginx configuration ---
def regenerate_nginx_config():
    """
    Regenerate the Nginx configuration file to include all enabled services.
    Updates both HTTP (port 80) and HTTPS (port 443) server blocks.
    Returns True if successful, False otherwise.
    """
    # Load the existing config file to preserve non-dynamic parts
    existing_config = ""
    if NGINX_CONFIG_PATH.exists():
        try:
            with open(NGINX_CONFIG_PATH, "r") as f:
                existing_config = f.read()
        except Exception as e:
            logger.error(f"Failed to read existing Nginx config: {e}")
            return False

    # Extract parts before and after the dynamic locations
    start_marker = "# DYNAMIC_LOCATIONS_START"
    end_marker = "# DYNAMIC_LOCATIONS_END"
    
    # Add error handling blocks and auth endpoints for MCP tool execution
    error_locations = """
    # Error handling locations for MCP tool execution
    location @error401 {
        return 401 '{"error":"Unauthorized","detail":"Authentication failed or insufficient permissions"}';
    }
    
    location @error404 {
        return 404 '{"error":"Not Found","detail":"The requested resource was not found"}';
    }
    
    location @error5xx {
        return 500 '{"error":"Server Error","detail":"An unexpected server error occurred"}';
    }
    
    # Common auth endpoint for tool execution - internal use only
    location ~ ^/api/tool_auth/(.+)$ {
        internal;  # Only for internal use by auth_request
        proxy_pass http://localhost:7860/api/tool_auth/$1;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # Pass through authentication cookies
        proxy_set_header Cookie $http_cookie;
    }
"""
    
    # Build configuration for each enabled service
    dynamic_locations = []
    dynamic_locations.append(start_marker)
    
    # Add error locations at the top
    dynamic_locations.append(error_locations)
    
    for path, enabled in MOCK_SERVICE_STATE.items():
        if not enabled:
            logger.info(f"Skipping disabled service: {path}")
            continue
            
        service_info = REGISTERED_SERVERS.get(path)
        if not service_info:
            logger.warning(f"Service {path} is enabled but not found in REGISTERED_SERVERS")
            continue
            
        proxy_url = service_info.get("proxy_pass_url")
        if not proxy_url:
            logger.warning(f"Service {path} has no proxy_pass_url defined")
            continue
            
        # Add health check status info
        service_health = SERVER_HEALTH_STATUS.get(path, "unknown")
        
        # Check for dev mode flag to include all enabled servers regardless of health
        dev_mode = os.environ.get("MCP_GATEWAY_DEV_MODE", "").lower() in ("1", "true", "yes")
        
        # In dev mode, include all enabled services; otherwise only include healthy ones
        if not dev_mode and service_health != "healthy":
            logger.warning(f"Skipping unhealthy service: {path} (status: {service_health})")
            continue
            
        logger.info(f"Adding service to nginx config: {path} (status: {service_health})")
        
        # Create location entry for this service
        # Remove leading slash from path for safer path building
        safe_path = path.lstrip("/")
        
        # 1. Regular location block for the service path
        nginx_location = f"""
    location /{safe_path}/ {{
        proxy_pass {proxy_url.rstrip('/')}/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Pass through authentication headers for service-specific tokens
        proxy_pass_request_headers on;
        # Preserve headers prefixed with X-Service-Auth-
        proxy_set_header X-Service-Auth-Github $http_x_service_auth_github;
        proxy_set_header X-Service-Auth-AWS $http_x_service_auth_aws;
        proxy_set_header X-Service-Auth-Token $http_x_service_auth_token;
    }}"""
        dynamic_locations.append(nginx_location)
        
        # No nginx proxy configuration needed for tool execution

    # Add the end marker
    dynamic_locations.append(end_marker)
    
    # Generate the dynamic content as a string
    dynamic_content = "\n".join(dynamic_locations)
    
    # Generate the dynamic content as a string
    dynamic_content = "\n".join(dynamic_locations)
    
    # Find all occurrences of start and end markers
    start_positions = []
    end_positions = []
    start_pos = 0
    
    # Find all start markers
    while True:
        start_pos = existing_config.find(start_marker, start_pos)
        if start_pos == -1:
            break
        start_positions.append(start_pos)
        start_pos += len(start_marker)
    
    # Find all end markers
    end_pos = 0
    while True:
        end_pos = existing_config.find(end_marker, end_pos)
        if end_pos == -1:
            break
        end_positions.append(end_pos + len(end_marker))
        end_pos += len(end_marker)
    
    # Verify we have matching pairs of markers
    if len(start_positions) != len(end_positions) or len(start_positions) == 0:
        logger.error(f"Mismatched or missing markers: {len(start_positions)} starts, {len(end_positions)} ends")
        return False
    
    # Sort positions to ensure correct order
    start_positions.sort()
    end_positions.sort()
    
    # Build new config by replacing each section
    new_config = existing_config
    
    # Replace sections in reverse order to avoid position shifts
    for i in range(len(start_positions) - 1, -1, -1):
        start_pos = start_positions[i]
        end_pos = end_positions[i]
        
        # Replace this section with dynamic content
        new_config = new_config[:start_pos] + dynamic_content + new_config[end_pos:]
    
    logger.info(f"Updated {len(start_positions)} dynamic sections in Nginx config")
    
    # Write the new configuration
    try:
        with open(NGINX_CONFIG_PATH, "w") as f:
            f.write(new_config)
        logger.info(f"Nginx configuration updated at {NGINX_CONFIG_PATH}")
        
        # Reload Nginx if possible
        try:
            logger.info("Attempting to reload Nginx configuration...")
            result = subprocess.run(['/usr/sbin/nginx', '-s', 'reload'], capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"Nginx reload successful. stdout: {result.stdout.strip()}")
                return True
            else:
                logger.error(f"Failed to reload Nginx configuration. Return code: {result.returncode}")
                logger.error(f"Nginx reload stderr: {result.stderr.strip()}")
                logger.error(f"Nginx reload stdout: {result.stdout.strip()}")
                return False
        except FileNotFoundError:
            logger.error("'nginx' command not found. Cannot reload configuration.")
            return False
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to reload Nginx configuration. Return code: {e.returncode}")
            logger.error(f"Nginx reload stderr: {e.stderr.strip()}")
            logger.error(f"Nginx reload stdout: {e.stdout.strip()}")
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred during Nginx reload: {e}", exc_info=True)
            return False

    except FileNotFoundError:
        logger.error(f"Target Nginx config file not found at {NGINX_CONFIG_PATH}. Cannot regenerate.")
        return False
    except Exception as e:
        logger.error(f"Failed to modify Nginx config at {NGINX_CONFIG_PATH}: {e}", exc_info=True)
        return False

COMMENTED_LOCATION_BLOCK_TEMPLATE = """
#    location {path}/ {{
#        proxy_pass {proxy_pass_url};
#        proxy_http_version 1.1;
#        proxy_set_header Host $host;
#        proxy_set_header X-Real-IP $remote_addr;
#        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#        proxy_set_header X-Forwarded-Proto $scheme;
#    }}
"""


# --- Helper function to normalize a path to a filename ---
def path_to_filename(path):
    # Remove leading slash and replace remaining slashes with underscores
    normalized = path.lstrip("/").replace("/", "_")
    # Append .json extension if not present
    if not normalized.endswith(".json"):
        normalized += ".json"
    return normalized


# --- Data Loading ---
def load_registered_servers_and_state():
    global REGISTERED_SERVERS, MOCK_SERVICE_STATE
    logger.info(f"Loading server definitions from {SERVERS_DIR}...")

    # Create servers directory if it doesn't exist
    SERVERS_DIR.mkdir(parents=True, exist_ok=True) # Added parents=True

    temp_servers = {}
    server_files = list(SERVERS_DIR.glob("**/*.json"))
    logger.info(f"Found {len(server_files)} JSON files in {SERVERS_DIR} and its subdirectories")
    for file in server_files:
        logger.info(f"[DEBUG] - {file.relative_to(SERVERS_DIR)}")

    if not server_files:
        logger.warning(f"No server definition files found in {SERVERS_DIR}. Initializing empty registry.")
        REGISTERED_SERVERS = {}
        # Don't return yet, need to load state file
        # return

    for server_file in server_files:
        if server_file.name == STATE_FILE_PATH.name: # Skip the state file itself
            continue
        try:
            with open(server_file, "r") as f:
                server_info = json.load(f)

                if (
                    isinstance(server_info, dict)
                    and "path" in server_info
                    and "server_name" in server_info
                ):
                    server_path = server_info["path"]
                    if server_path in temp_servers:
                        logger.warning(f"Duplicate server path found in {server_file}: {server_path}. Overwriting previous definition.")

                    # Add new fields with defaults
                    server_info["description"] = server_info.get("description", "")
                    server_info["tags"] = server_info.get("tags", [])
                    server_info["num_tools"] = server_info.get("num_tools", 0)
                    server_info["num_stars"] = server_info.get("num_stars", 0)
                    server_info["is_python"] = server_info.get("is_python", False)
                    server_info["license"] = server_info.get("license", "N/A")
                    server_info["proxy_pass_url"] = server_info.get("proxy_pass_url", None)
                    server_info["tool_list"] = server_info.get("tool_list", []) # Initialize tool_list if missing

                    temp_servers[server_path] = server_info
                else:
                    logger.warning(f"Invalid server entry format found in {server_file}. Skipping.")
        except FileNotFoundError:
            logger.error(f"Server definition file {server_file} reported by glob not found.")
        except json.JSONDecodeError as e:
            logger.error(f"Could not parse JSON from {server_file}: {e}.")
        except Exception as e:
            logger.error(f"An unexpected error occurred loading {server_file}: {e}", exc_info=True)

    REGISTERED_SERVERS = temp_servers
    logger.info(f"Successfully loaded {len(REGISTERED_SERVERS)} server definitions.")

    # --- Load persisted mock service state --- START
    logger.info(f"Attempting to load persisted state from {STATE_FILE_PATH}...")
    loaded_state = {}
    try:
        if STATE_FILE_PATH.exists():
            with open(STATE_FILE_PATH, "r") as f:
                loaded_state = json.load(f)
            if not isinstance(loaded_state, dict):
                logger.warning(f"Invalid state format in {STATE_FILE_PATH}. Expected a dictionary. Resetting state.")
                loaded_state = {} # Reset if format is wrong
            else:
                logger.info(f"Loaded state for {len(loaded_state)} services.")
        else:
            logger.info(f"No state file found at {STATE_FILE_PATH}. Starting with empty state.")
    except json.JSONDecodeError:
        logger.warning(f"Could not parse JSON from {STATE_FILE_PATH}. Resetting state.")
    except Exception as e:
        logger.error(f"Error loading state file: {e}", exc_info=True)
    
    # Initialize state for all registered servers
    for path in REGISTERED_SERVERS:
        if path not in MOCK_SERVICE_STATE:
            # Default to enabled for new services
            MOCK_SERVICE_STATE[path] = loaded_state.get(path, True)
    
    logger.info(f"Service state initialized with {len(MOCK_SERVICE_STATE)} entries.")
    # --- Load persisted mock service state --- END

# --- Check function to test if a service is healthy ---
async def perform_single_health_check(path: str):
    """
    Perform a health check for a single service.
    Updates SERVER_HEALTH_STATUS and SERVER_LAST_CHECK_TIME.
    
    In development/test mode, we're more tolerant of health check failures to ensure
    services remain visible in the UI even if the backend services are not running.
    """
    # Update status to checking
    SERVER_HEALTH_STATUS[path] = "checking"
    SERVER_LAST_CHECK_TIME[path] = datetime.now(timezone.utc)
    
    # Get info about the service
    service_info = REGISTERED_SERVERS.get(path)
    if not service_info:
        error_msg = f"Service not found in registry: {path}"
        SERVER_HEALTH_STATUS[path] = f"error: {error_msg}"
        await broadcast_health_status()
        return
        
    # Service must be enabled for health check
    if not MOCK_SERVICE_STATE.get(path, False):
        error_msg = "Service is disabled"
        SERVER_HEALTH_STATUS[path] = f"error: {error_msg}"
        await broadcast_health_status()
        return
        
    # Get the proxy pass URL
    proxy_url = service_info.get("proxy_pass_url")
    if not proxy_url:
        error_msg = "No proxy_pass_url defined"
        SERVER_HEALTH_STATUS[path] = f"error: {error_msg}"
        await broadcast_health_status()
        return
    
    # Check for dev mode flag to bypass actual health checks
    dev_mode = os.environ.get("MCP_GATEWAY_DEV_MODE", "").lower() in ("1", "true", "yes")
    if dev_mode:
        logger.info(f"Dev mode enabled - marking {path} as healthy without checking")
        SERVER_HEALTH_STATUS[path] = "healthy"
        
        # Set real tools for known servers in dev mode
        server_name = path.lstrip("/")
        server_path = os.path.join(os.environ.get("SERVER_DIR", "/Users/aaronbw/Documents/DEV/v1/mcp-gateway/servers"), server_name)
        server_py_path = os.path.join(server_path, "server.py")
        
        # Check if this server has a server.py file and we haven't set tools yet
        if os.path.exists(server_py_path) and not service_info.get("real_tools_set"):
            # Try to automatically extract tools from server.py
            extracted_tools = try_extract_tools_from_server_py(server_py_path)
            
            if extracted_tools:
                # Only set tools if we successfully extracted them
                service_info["num_tools"] = len(extracted_tools)
                service_info["tool_list"] = extracted_tools
                logger.info(f"Using {len(extracted_tools)} automatically extracted tools for {path}")
            else:
                # If extraction failed, leave tools as-is - don't show anything until the real tools are available
                logger.warning(f"Failed to extract tools from {path}, no tools will be shown in dev mode")
                # Make sure we don't have any old placeholder values by explicitly setting to empty
                service_info["num_tools"] = 0
                service_info["tool_list"] = []
            
            # Mark that we've set real tools for this server
            service_info["real_tools_set"] = True
            REGISTERED_SERVERS[path] = service_info
            logger.info(f"Set real tools for {path} in dev mode")
        # Never use placeholder tools - if we don't have real tools, set an empty list
        elif not service_info.get("tool_list"):
            service_info["num_tools"] = 0
            service_info["tool_list"] = []
            REGISTERED_SERVERS[path] = service_info
            logger.info(f"No tools set for {path} - waiting for real tools")
            
        SERVER_LAST_CHECK_TIME[path] = datetime.now(timezone.utc)
        await broadcast_health_status()
        regenerate_nginx_config()
        return
        
    # Form the health check URL - this will be the /tools endpoint
    health_url = proxy_url.rstrip("/") + "/tools"
    
    # Use curl for health check since it's installed in the container
    try:
        # Perform the health check using curl command
        cmd = ["curl", "-s", "-m", str(HEALTH_CHECK_TIMEOUT_SECONDS), "-w", "%{http_code}", health_url]
        logger.info(f"Running health check: {' '.join(cmd)}")
        
        # Run curl in a subprocess
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        # Process return code and output
        return_code = process.returncode
        response = stdout.decode().strip()
        error_output = stderr.decode().strip()
        
        if return_code != 0:
            # curl command failed
            error_msg = f"Health check failed (curl error): {error_output or 'unknown error'}"
            SERVER_HEALTH_STATUS[path] = f"unhealthy"
            logger.warning(f"Health check for {path} failed: {error_msg}")
        else:
            # Check response code
            try:
                # Try to parse JSON from the first part of the response
                # The response format is <json_content><status_code>
                status_code = response[-3:]  # Last 3 chars should be status code
                json_content = response[:-3]  # Everything before status code
                
                if status_code.isdigit() and 200 <= int(status_code) < 300:
                    try:
                        tools_data = json.loads(json_content)
                        # Update tool count in server info
                        tool_list = tools_data.get("tools", [])
                        service_info["num_tools"] = len(tool_list)
                        # Store the tools list
                        service_info["tool_list"] = tool_list
                        REGISTERED_SERVERS[path] = service_info
                        # Update status
                        SERVER_HEALTH_STATUS[path] = "healthy"
                        logger.info(f"Health check for {path} succeeded: {len(tool_list)} tools found")
                    except json.JSONDecodeError:
                        # Couldn't parse JSON, consider failed
                        SERVER_HEALTH_STATUS[path] = "unhealthy"
                        logger.warning(f"Health check for {path} failed: Invalid JSON response")
                else:
                    # Status code not 2xx
                    SERVER_HEALTH_STATUS[path] = "unhealthy"
                    logger.warning(f"Health check for {path} failed: HTTP {status_code}")
            except Exception as e:
                SERVER_HEALTH_STATUS[path] = "unhealthy"
                logger.warning(f"Health check for {path} failed to parse response: {e}")
                
    except Exception as e:
        SERVER_HEALTH_STATUS[path] = "unhealthy"
        logger.error(f"Error performing health check for {path}: {e}")
    
    # Update last check time
    SERVER_LAST_CHECK_TIME[path] = datetime.now(timezone.utc)
    
    # Broadcast status update
    await broadcast_health_status()
    
    # Trigger Nginx config regeneration if status changed
    regenerate_nginx_config()

# --- Background task to run health checks periodically ---
async def run_health_checks():
    """
    Background task that periodically runs health checks for all enabled services.
    """
    logger.info("Health check background task started.")
    
    try:
        while True:
            # Check all enabled services
            enabled_services = [path for path, enabled in MOCK_SERVICE_STATE.items() if enabled]
            logger.info(f"Running health checks for {len(enabled_services)} enabled services...")
            
            for path in enabled_services:
                try:
                    # Check if we need to do a health check
                    last_check = SERVER_LAST_CHECK_TIME.get(path)
                    now = datetime.now(timezone.utc)
                    
                    # Never checked, or it's been longer than the interval
                    if last_check is None or (now - last_check).total_seconds() >= HEALTH_CHECK_INTERVAL_SECONDS:
                        logger.info(f"Running health check for {path}")
                        await perform_single_health_check(path)
                    else:
                        time_since = (now - last_check).total_seconds()
                        logger.debug(f"Skipping health check for {path} (checked {time_since:.1f}s ago)")
                except Exception as e:
                    logger.error(f"Error in health check for {path}: {e}")
            
            # Sleep a short interval before checking again
            await asyncio.sleep(30)  # Check every 30 seconds if any service needs checking
                
    except asyncio.CancelledError:
        logger.info("Health check background task cancelled.")
    except Exception as e:
        logger.error(f"Error in health check task: {e}")
        
    logger.info("Health check background task ended.")


# --- Handle disabled services --- START
@app.post("/api/services/{service_path:path}/toggle", response_model=None)
async def toggle_service_api(
    request: Request,
    service_path: str,
    username: Annotated[str, Depends(api_auth)],
    enabled: bool = Form(False),
):
    """
    Toggle a service on or off through the API.
    Requires the mcp:server:{service_path}:toggle scope or mcp:registry:admin scope.
    """
    # Check authorization
    auth_dependency = require_toggle_for_path(service_path)
    await run_async_dependency(auth_dependency, {"request": request})
    # Normalize the path
    if not service_path.startswith('/'):
        service_path = '/' + service_path
    
    # Check if the service exists
    if service_path not in REGISTERED_SERVERS:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Update the service status
    logger.info(f"User '{username}' toggling service {service_path} to {'enabled' if enabled else 'disabled'}")
    MOCK_SERVICE_STATE[service_path] = enabled
    
    # Save the updated state
    try:
        with open(STATE_FILE_PATH, "w") as f:
            json.dump(MOCK_SERVICE_STATE, f, indent=2)
        logger.info(f"Updated service state saved to {STATE_FILE_PATH}")
    except Exception as e:
        logger.error(f"Failed to save service state: {e}")
    
    # Handle enabled/disabled services differently
    if enabled:
        # If enabling, update its health status
        logger.info(f"Service {service_path} enabled. Running health check...")
        # Run the health check and broadcast in that function
        try:
            # Update status and time as the check starts
            SERVER_HEALTH_STATUS[service_path] = "checking"
            SERVER_LAST_CHECK_TIME[service_path] = datetime.now(timezone.utc)
            
            # Broadcast the "checking" state first
            await broadcast_health_status()
            
            # Then run the actual check (which will broadcast again)
            await perform_single_health_check(service_path)
        except Exception as e:
            logger.error(f"Error during health check of newly enabled service: {e}")
            # Mark as unhealthy if the check fails with an exception
            SERVER_HEALTH_STATUS[service_path] = "unhealthy"
            SERVER_LAST_CHECK_TIME[service_path] = datetime.now(timezone.utc)
            # And make sure to broadcast
            await broadcast_health_status()
    else:
        # If disabling, just mark it as disabled
        logger.info(f"Service {service_path} disabled. Removing from configuration...")
        SERVER_HEALTH_STATUS[service_path] = "disabled"
        SERVER_LAST_CHECK_TIME[service_path] = datetime.now(timezone.utc)
        
        # Broadcast the disabled state
        await broadcast_health_status()
        
        # Regenerate the Nginx config
        regenerate_nginx_config()
    
    # Return success with the new state
    return {
        "service_path": service_path,
        "enabled": MOCK_SERVICE_STATE[service_path],
        "health_status": SERVER_HEALTH_STATUS.get(service_path, "unknown")
    }
# --- Handle disabled services --- END

# --- Frontend Toggle Handler --- START
@app.post("/toggle/{service_path:path}")
async def toggle_service_frontend(
    request: Request,
    service_path: str,
    username: Annotated[str, Depends(get_current_user)],
    enabled: bool = Form(False),
):
    """
    Toggle a service on or off via the frontend form.
    Requires the mcp:server:{service_path}:toggle scope or mcp:registry:admin scope.
    """
    # Check authorization
    auth_dependency = require_toggle_for_path(service_path)
    await run_async_dependency(auth_dependency, {"request": request})
    
    # Normalize the path
    if not service_path.startswith('/'):
        service_path = '/' + service_path
    
    # Check if the service exists
    if service_path not in REGISTERED_SERVERS:
        raise HTTPException(status_code=404, detail="Service not found")
    
    # Update the service status
    logger.info(f"User '{username}' toggling service {service_path} to {'enabled' if enabled else 'disabled'}")
    MOCK_SERVICE_STATE[service_path] = enabled
    
    # Save the updated state
    try:
        with open(STATE_FILE_PATH, "w") as f:
            json.dump(MOCK_SERVICE_STATE, f, indent=2)
        logger.info(f"Updated service state saved to {STATE_FILE_PATH}")
    except Exception as e:
        logger.error(f"Failed to save service state: {e}")
    
    # Handle enabled/disabled services differently
    if enabled:
        # If enabling, update its health status
        logger.info(f"Service {service_path} enabled. Running health check...")
        # Run the health check and broadcast in that function
        try:
            # Update status and time as the check starts
            SERVER_HEALTH_STATUS[service_path] = "checking"
            SERVER_LAST_CHECK_TIME[service_path] = datetime.now(timezone.utc)
            
            # Broadcast the "checking" state first
            await broadcast_health_status()
            
            # Then run the actual check (which will broadcast again)
            await perform_single_health_check(service_path)
        except Exception as e:
            logger.error(f"Error during health check of newly enabled service: {e}")
            # Mark as unhealthy if the check fails with an exception
            SERVER_HEALTH_STATUS[service_path] = "unhealthy"
            SERVER_LAST_CHECK_TIME[service_path] = datetime.now(timezone.utc)
            # And make sure to broadcast
            await broadcast_health_status()
    else:
        # If disabling, just mark it as disabled
        logger.info(f"Service {service_path} disabled. Removing from configuration...")
        SERVER_HEALTH_STATUS[service_path] = "disabled"
        SERVER_LAST_CHECK_TIME[service_path] = datetime.now(timezone.utc)
        
        # Broadcast the disabled state
        await broadcast_health_status()
        
        # Regenerate the Nginx config
        regenerate_nginx_config()
    
    # Return a JSON response instead of the default dictionary
    # The frontend expects a JSON response format
    return JSONResponse(content={
        "service_path": service_path,
        "enabled": MOCK_SERVICE_STATE[service_path],
        "health_status": SERVER_HEALTH_STATUS.get(service_path, "unknown")
    })
# --- Frontend Toggle Handler --- END

# --- Service Search --- START
@app.get("/api/search")
async def search_services(
    query: str,
    username: Annotated[str, Depends(api_auth)],
    filter_enabled: bool = False
):
    """
    Search for services based on text query using FAISS.
    
    Args:
        query: Search query text
        filter_enabled: Only return enabled services (default: False)
        
    Returns:
        List of matching services with scores
    """
    global embedding_model, faiss_index, faiss_metadata_store
    
    # Handle empty query
    if not query or query.strip() == "":
        logger.info("Empty search query. Returning all services.")
        
        # Just return all services instead
        all_services = []
        for path, server_info in REGISTERED_SERVERS.items():
            is_enabled = MOCK_SERVICE_STATE.get(path, False)
            
            # Apply enabled filter if requested
            if filter_enabled and not is_enabled:
                continue
                
            service_copy = server_info.copy()
            service_copy["is_enabled"] = is_enabled
            service_copy["relevance_score"] = 0.0  # No relevance score for unranked results
            service_copy["health_status"] = SERVER_HEALTH_STATUS.get(path, "unknown")
            all_services.append(service_copy)
            
        # Sort alphabetically by name as fallback
        all_services.sort(key=lambda x: x.get("server_name", "").lower())
        return all_services
    
    # Check if search is ready
    if embedding_model is None or faiss_index is None:
        logger.warning("FAISS search not ready (model or index not loaded)")
        raise HTTPException(
            status_code=503,
            detail="Search functionality not available yet. Please try again later."
        )
        
    try:
        # Encode the query
        query_embedding = await asyncio.to_thread(embedding_model.encode, [query.strip()])
        query_embedding_np = np.array([query_embedding[0]], dtype=np.float32)
        
        # Configure search (number of results, etc)
        k = min(50, faiss_index.ntotal)  # Return up to 50 results, or fewer if index is smaller
        if k == 0:
            logger.info("No services in search index.")
            return []
        
        # Search the index
        distances, indices = faiss_index.search(query_embedding_np, k)
        
        # Process search results
        results = []
        seen_paths = set()
        
        for i, (distance, idx) in enumerate(zip(distances[0], indices[0])):
            if idx == -1:  # -1 means no more matches
                break
            
            # Find the service path for this index
            service_path = None
            server_info = None
            
            for path, metadata in faiss_metadata_store.items():
                if metadata.get("id") == idx:
                    service_path = path
                    server_info = metadata.get("full_server_info", {})
                    break
                    
            if not service_path or not server_info:
                logger.warning(f"Found result with idx {idx} but no matching service in metadata store")
                continue
                
            # Skip if we've already seen this service
            if service_path in seen_paths:
                continue
            seen_paths.add(service_path)
            
            # Get enabled status
            is_enabled = MOCK_SERVICE_STATE.get(service_path, False)
            
            # Apply enabled filter if requested
            if filter_enabled and not is_enabled:
                continue
                
            # Compute a relevance score (invert the distance)
            # L2 distance might be arbitrarily large, so we apply a transformation
            # to get a score between 0 and 1 (closer to 1 is better)
            # This formula gives reasonable distribution for sentence transformer embeddings
            relevance_score = 1.0 / (1.0 + distance/10)

            # Add to results
            health_status = SERVER_HEALTH_STATUS.get(service_path, "unknown")
            result = server_info.copy()  # Start with the server info
            result["is_enabled"] = is_enabled
            result["relevance_score"] = relevance_score
            result["health_status"] = health_status
            results.append(result)
            
        # Sort by relevance score
        results.sort(key=lambda x: x["relevance_score"], reverse=True)
        
        logger.info(f"Search for '{query}' returned {len(results)} results")
        return results
        
    except Exception as e:
        logger.error(f"Error performing search: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Search failed: {str(e)}"
        )
# --- Service Search --- END

# --- Save Service Helper Function ---
def save_server_to_file(server_entry) -> bool:
    """
    Save a server entry to disk as JSON.
    
    Args:
        server_entry: Dictionary with server information
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not server_entry or "path" not in server_entry:
        logger.error("Invalid server entry to save, missing path")
        return False
        
    # Create safe filename from path (replace slashes and some other chars)
    path = server_entry["path"]
    safe_name = path.lstrip('/').replace('/', '_').replace(':', '_')
    
    if not safe_name:
        safe_name = "root"  # In case path is just "/"
    
    filename = SERVERS_DIR / f"{safe_name}.json"
    
    try:
        SERVERS_DIR.mkdir(parents=True, exist_ok=True)
        with open(filename, "w") as f:
            json.dump(server_entry, f, indent=2)
        logger.info(f"Saved server info to {filename}")
        return True
    except Exception as e:
        logger.error(f"Error saving server info to {filename}: {e}")
        return False

# --- Register a new service --- START
@app.post("/api/register", response_model=None)
async def register_service(
    request: Request,
    username: Annotated[str, Depends(api_auth)],
    name: Annotated[str, Form()],
    path: Annotated[str, Form()],
    proxy_pass_url: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
    tags: Annotated[str, Form()] = "",
    num_tools: Annotated[int, Form()] = 0,
    num_stars: Annotated[int, Form()] = 0,
    is_python: Annotated[bool | None, Form()] = False,
    license_str: Annotated[str, Form(alias="license")] = "N/A",
):
    """Register a new service with the gateway."""
    # Check authorization
    auth_dependency = require_registry_admin()
    await run_async_dependency(auth_dependency, {"request": request})
    # Ensure path starts with a slash
    if not path.startswith('/'):
        path = '/' + path
    
    # Check if path already exists
    if path in REGISTERED_SERVERS:
        raise HTTPException(status_code=400, detail="Service path already registered")
    
    # Process tags
    tag_list = [tag.strip() for tag in tags.split(',') if tag.strip()]

    # Create server entry
    server_entry = {
        "server_name": name,
        "description": description,
        "path": path,
        "proxy_pass_url": proxy_pass_url,
        "tags": tag_list,
        "num_tools": num_tools,
        "num_stars": num_stars,
        "is_python": bool(is_python), # Convert checkbox value
        "license": license_str,
    }
    
    # Save to disk storage
    success = save_server_to_file(server_entry)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to save server information")
    
    # Add to in-memory registry
    REGISTERED_SERVERS[path] = server_entry
    
    # Set up default state (disabled by default)
    MOCK_SERVICE_STATE[path] = False
    
    # Initialize health status
    SERVER_HEALTH_STATUS[path] = "unknown"
    SERVER_LAST_CHECK_TIME[path] = None
    
    # --- Add to FAISS Index --- START
    logger.info(f"[DEBUG] Adding service '{path}' to FAISS index...")
    if embedding_model is not None and faiss_index is not None:
        await add_or_update_service_in_faiss(path, server_entry) # server_entry is the new service info
        logger.info(f"[DEBUG] Service '{path}' processed for FAISS index.")
    else:
        logger.warning(f"[DEBUG] Skipped FAISS update for '{path}': model or index not ready.")
    # --- Add to FAISS Index --- END

    logger.info(f"[INFO] New service registered: '{name}' at path '{path}' by user '{username}'")

    # --- Persist the updated state after registration --- START
    try:
        logger.info(f"[DEBUG] Attempting to persist state to {STATE_FILE_PATH}...")
        with open(STATE_FILE_PATH, "w") as f:
            json.dump(MOCK_SERVICE_STATE, f, indent=2)
        logger.info(f"[DEBUG] Successfully persisted state to {STATE_FILE_PATH}")
    except Exception as e:
        logger.error(f"[ERROR] Failed to persist state to {STATE_FILE_PATH}: {str(e)}")
    # --- Persist the updated state after registration --- END

    # Broadcast the updated status after registration
    logger.info("[DEBUG] Creating task to broadcast health status...")
    asyncio.create_task(broadcast_health_status())

    logger.info("[DEBUG] Registration complete, returning success response")
    return JSONResponse(
        status_code=201,
        content={
            "message": "Service registered successfully",
            "service": server_entry,
        },
    )

@app.get("/api/server_details/{service_path:path}", response_model=None)
async def get_server_details(
    request: Request,
    service_path: str,
    username: Annotated[str, Depends(api_auth)],
):
    """
    Get detailed information about a server.
    Requires the mcp:server:{service_path}:edit scope or mcp:registry:admin scope.
    """
    # Check authorization
    if service_path != 'all':
        auth_dependency = require_edit_for_path(service_path)
        await run_async_dependency(auth_dependency, {"request": request})
    else:
        auth_dependency = check_admin_scope()
        await run_async_dependency(auth_dependency, {"request": request})
        
    # Normalize the path to ensure it starts with '/'
    if not service_path.startswith('/'):
        service_path = '/' + service_path
    
    # Special case: if path is 'all' or '/all', return details for all servers
    if service_path == '/all':
        # Return a dictionary of all registered servers
        return REGISTERED_SERVERS
    
    # Regular case: return details for a specific server
    server_info = REGISTERED_SERVERS.get(service_path)
    if not server_info:
        raise HTTPException(status_code=404, detail="Service path not registered")
    
    # Return the full server info, including proxy_pass_url
    return server_info


# --- API endpoint for Tool Execution via SSE Transport --- START
@app.post("/api/execute/{service_path:path}", response_model=None)
async def execute_tool(
    request: Request,
    service_path: str,
    username: Annotated[str, Depends(api_auth)],
):
    """
    Execute a tool on a specific service using MCP client with SSE transport.
    
    endpoint acts as an MCP client to backend servers, providing OAuth-protected
    access to tools while maintaining proper MCP protocol compliance.
    
    Transport: Server-Sent Events (SSE)
    Auth required: mcp:server:{service_path}:execute scope or mcp:registry:admin scope
    
    Flow:
    1. Authenticate and authorize the request 
    2. Validate service exists and is enabled
    3. Establish MCP client session with backend server
    4. Execute tool via proper MCP protocol
    5. Return JSON-RPC compliant response
    """
    try:
        # Normalize the service path
        if not service_path.startswith('/'):
            service_path = '/' + service_path
        
        # Check for authenticated user in request.state
        if not hasattr(request.state, "user") or not request.state.user or not getattr(request.state.user, "is_authenticated", False):
            logger.warning(f"Unauthorized attempt to execute tool on '{service_path}': No valid authentication")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Check if the service exists and is enabled
        if service_path not in REGISTERED_SERVERS:
            logger.warning(f"Service not found for tool execution: '{service_path}'")
            raise HTTPException(status_code=404, detail=f"Service '{service_path}' not found")
        
        if not MOCK_SERVICE_STATE.get(service_path, False):
            logger.warning(f"Service disabled for tool execution: '{service_path}'")
            raise HTTPException(status_code=403, detail=f"Service '{service_path}' is disabled")
        
        # Get service info and determine port
        service_info = REGISTERED_SERVERS.get(service_path)
        proxy_url = service_info.get("proxy_pass_url")
        
        if not proxy_url:
            logger.error(f"No proxy URL configured for service '{service_path}'")
            raise HTTPException(status_code=500, detail=f"No proxy URL configured for service '{service_path}'")
        
        # Check required scopes
        auth_settings = AuthSettings()
        execute_scope = auth_settings.get_server_execute_scope(service_path)
        
        if not (request.state.user.has_scope(auth_settings.registry_admin_scope) or 
                request.state.user.has_scope(execute_scope)):
            logger.warning(f"User '{username}' denied access to execute tool on '{service_path}' - missing scope: {execute_scope}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scope for service access: {execute_scope}",
            )
        
        # Parse JSON-RPC request
        try:
            body = await request.json()
            if not all(key in body for key in ["jsonrpc", "method", "params", "id"]):
                raise ValueError("Invalid JSON-RPC format")
            
            tool_name = body["params"]["name"]
            tool_arguments = body["params"]["arguments"]
            request_id = body["id"]
            
            logger.info(f"Tool execution: '{tool_name}' on '{service_path}' by '{username}' with args: {tool_arguments}")
        except Exception as e:
            logger.error(f"Failed to parse JSON-RPC request: {e}")
            raise HTTPException(status_code=400, detail="Invalid JSON-RPC request format")
        
        # Establish MCP client session and execute tool
        # Route through nginx to handle mount_path properly
        # Nginx strips the service path prefix when proxying to backend
        nginx_base = f"http://localhost{service_path}"  # e.g., http://localhost/currenttime
        
        # Try SSE endpoint through nginx
        sse_endpoints = [
            f"{nginx_base}/sse",  # e.g., http://localhost/currenttime/sse -> proxied to backend
        ]
        
        last_error = None
        for sse_url in sse_endpoints:
            try:
                logger.info(f"Attempting SSE connection to: {sse_url}")
                # Connect to MCP server with timeout
                async with sse_client(sse_url, timeout=10.0) as (read_stream, write_stream):
                    async with ClientSession(read_stream, write_stream) as session:
                        # Initialize the session
                        await asyncio.wait_for(session.initialize(), timeout=5.0)
                        
                        # Execute the tool
                        result = await asyncio.wait_for(
                            session.call_tool(tool_name, tool_arguments),
                            timeout=30.0
                        )
                    
                    # Extract content from MCP result and ensure it's serializable
                    if hasattr(result, 'content'):
                        if hasattr(result.content, 'text'):
                            # Handle TextContent objects
                            result_content = result.content.text
                        elif isinstance(result.content, list):
                            # Handle list of content objects
                            result_content = []
                            for item in result.content:
                                if hasattr(item, 'text'):
                                    result_content.append(item.text)
                                else:
                                    result_content.append(str(item))
                        else:
                            result_content = str(result.content)
                    else:
                        result_content = str(result)
                    
                    # Return JSON-RPC response
                    # Ensure result is always an array for consistency
                    if isinstance(result_content, list):
                        result_array = result_content
                    else:
                        result_array = [result_content] if result_content else []
                    
                    return JSONResponse(
                        content={
                            "jsonrpc": "2.0",
                            "result": result_array,
                            "id": request_id
                        },
                        headers={
                            "Cache-Control": "no-cache, no-store, must-revalidate",
                            "Pragma": "no-cache",
                            "Expires": "0"
                        }
                    )
                        
            except asyncio.TimeoutError as e:
                logger.warning(f"Timeout connecting to MCP server at {sse_url}")
                last_error = e
                continue  # Try next endpoint
            except Exception as e:
                logger.warning(f"Error connecting to {sse_url}: {e}")
                last_error = e
                continue  # Try next endpoint
        
        # If we've tried all endpoints and none worked, raise the last error
        if last_error:
            if isinstance(last_error, asyncio.TimeoutError):
                raise HTTPException(status_code=504, detail=f"Timeout connecting to service '{service_path}'")
            else:
                raise HTTPException(status_code=502, detail=f"Failed to execute tool on service '{service_path}': {str(last_error)}")
            
    except Exception as e:
        # Log the error with appropriate level and context
        if isinstance(e, HTTPException):
            # For expected HTTP exceptions, we log at warning level
            if e.status_code >= 500:
                logger.error(f"Server error during tool execution on '{service_path}': {e}")
            else:
                logger.warning(f"Client error during tool execution on '{service_path}': {e}")
            raise
        else:
            # For unexpected exceptions, log as error with traceback
            logger.error(f"Unexpected error during tool execution on '{service_path}': {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"Internal server error during tool execution")
        
@app.post("/api/streamable/{service_path:path}", response_model=None)
async def execute_tool_streamable(
    request: Request,
    service_path: str,
    username: Annotated[str, Depends(api_auth)],
):
    """
    Execute a tool on a specific service using MCP client with StreamableHTTP transport.
    
    This endpoint acts as an MCP client to backend servers, providing OAuth-protected
    access to tools while maintaining proper MCP protocol compliance.
    
    Transport: StreamableHTTP
    Auth required: mcp:server:{service_path}:execute scope or mcp:registry:admin scope
    
    Flow identical to execute_tool but for StreamableHTTP transport.
    """
    try:
        # Normalize the service path
        if not service_path.startswith('/'):
            service_path = '/' + service_path
        
        # Check for authenticated user in request.state
        if not hasattr(request.state, "user") or not request.state.user or not getattr(request.state.user, "is_authenticated", False):
            logger.warning(f"Unauthorized attempt to execute tool (streamable) on '{service_path}': No valid authentication")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Check if the service exists and is enabled
        if service_path not in REGISTERED_SERVERS:
            logger.warning(f"Service not found for tool execution (streamable): '{service_path}'")
            raise HTTPException(status_code=404, detail=f"Service '{service_path}' not found")
        
        if not MOCK_SERVICE_STATE.get(service_path, False):
            logger.warning(f"Service disabled for tool execution (streamable): '{service_path}'")
            raise HTTPException(status_code=403, detail=f"Service '{service_path}' is disabled")
        
        # Get service info and determine port
        service_info = REGISTERED_SERVERS.get(service_path)
        proxy_url = service_info.get("proxy_pass_url")
        
        if not proxy_url:
            logger.error(f"No proxy URL configured for service '{service_path}'")
            raise HTTPException(status_code=500, detail=f"No proxy URL configured for service '{service_path}'")
        
        # Check required scopes
        auth_settings = AuthSettings()
        execute_scope = auth_settings.get_server_execute_scope(service_path)
        
        if not (request.state.user.has_scope(auth_settings.registry_admin_scope) or 
                request.state.user.has_scope(execute_scope)):
            logger.warning(f"User '{username}' denied access to execute tool (streamable) on '{service_path}' - missing scope: {execute_scope}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scope for service access: {execute_scope}",
            )
        
        # Parse JSON-RPC request
        try:
            body = await request.json()
            if not all(key in body for key in ["jsonrpc", "method", "params", "id"]):
                raise ValueError("Invalid JSON-RPC format")
            
            tool_name = body["params"]["name"]
            tool_arguments = body["params"]["arguments"]
            request_id = body["id"]
            
            logger.info(f"StreamableHTTP tool execution: '{tool_name}' on '{service_path}' by '{username}' with args: {tool_arguments}")
        except Exception as e:
            logger.error(f"Failed to parse JSON-RPC request: {e}")
            raise HTTPException(status_code=400, detail="Invalid JSON-RPC request format")
        
        # Import MCP client with proper error handling
        try:
            from mcp import ClientSession
            import httpx
        except ImportError as e:
            logger.error(f"MCP SDK not available: {e}")
            raise HTTPException(status_code=500, detail="MCP SDK not properly installed")
        
        # Check if this server supports StreamableHTTP transport
        # Route through nginx to handle mount_path properly
        nginx_base = f"http://localhost{service_path}"  # e.g., http://localhost/currenttime
        
        # Try the MCP endpoint through nginx
        mcp_endpoints = [
            f"{nginx_base}/mcp",  # e.g., http://localhost/currenttime/mcp -> proxied to backend
        ]
        
        streamable_url = None
        for test_url in mcp_endpoints:
            try:
                # Test if StreamableHTTP endpoint exists
                async with httpx.AsyncClient(timeout=5.0) as test_client:
                    test_response = await test_client.get(test_url)
                    if test_response.status_code != 404:
                        streamable_url = test_url
                        logger.info(f"Found StreamableHTTP endpoint at: {streamable_url}")
                        break
            except Exception as e:
                logger.debug(f"Failed to test {test_url}: {e}")
                continue
        
        try:
            if streamable_url is None:
                # Server doesn't support StreamableHTTP, fall back to SSE approach
                logger.info(f"Server '{service_path}' doesn't support StreamableHTTP, using SSE approach")
                
                # Use SSE transport for this request
                # Route through nginx to handle mount_path properly
                nginx_base = f"http://localhost{service_path}"  # e.g., http://localhost/currenttime
                
                # Try SSE endpoint through nginx
                sse_endpoints = [
                    f"{nginx_base}/sse",  # e.g., http://localhost/currenttime/sse -> proxied to backend
                ]
                
                last_error = None
                for sse_url in sse_endpoints:
                    try:
                        logger.info(f"StreamableHTTP fallback - attempting SSE connection to: {sse_url}")
                        # Connect to MCP server with timeout
                        async with sse_client(sse_url, timeout=10.0) as (read_stream, write_stream):
                            async with ClientSession(read_stream, write_stream) as session:
                                # Initialize the session
                                await asyncio.wait_for(session.initialize(), timeout=5.0)
                                
                                # Execute the tool
                                result = await asyncio.wait_for(
                                    session.call_tool(tool_name, tool_arguments),
                                    timeout=30.0
                                )
                                
                                # Extract content from MCP result and ensure it's serializable
                                if hasattr(result, 'content'):
                                    if hasattr(result.content, 'text'):
                                        # Handle TextContent objects
                                        result_content = result.content.text
                                    elif isinstance(result.content, list):
                                        # Handle list of content objects
                                        result_content = []
                                        for item in result.content:
                                            if hasattr(item, 'text'):
                                                result_content.append(item.text)
                                            else:
                                                result_content.append(str(item))
                                    else:
                                        result_content = str(result.content)
                                else:
                                    result_content = str(result)
                                
                                # Return JSON-RPC response
                                # Ensure result is always an array for consistency
                                if isinstance(result_content, list):
                                    result_array = result_content
                                else:
                                    result_array = [result_content] if result_content else []
                                
                                return JSONResponse(
                                    content={
                                        "jsonrpc": "2.0",
                                        "result": result_array,
                                        "id": request_id
                                    },
                                    headers={
                                        "Cache-Control": "no-cache, no-store, must-revalidate",
                                        "Pragma": "no-cache",
                                        "Expires": "0"
                                    }
                                )
                                    
                    except asyncio.TimeoutError as e:
                        logger.warning(f"StreamableHTTP fallback - timeout connecting to MCP server at {sse_url}")
                        last_error = e
                        continue  # Try next endpoint
                    except Exception as e:
                        logger.warning(f"StreamableHTTP fallback - error connecting to {sse_url}: {e}")
                        last_error = e
                        continue  # Try next endpoint
                    
                # If we've tried all endpoints and none worked, raise the last error
                if last_error:
                    if isinstance(last_error, asyncio.TimeoutError):
                        raise HTTPException(status_code=504, detail=f"Timeout connecting to service '{service_path}'")
                    else:
                        raise HTTPException(status_code=502, detail=f"Failed to execute tool on service '{service_path}': {str(last_error)}")
                
            # Server supports StreamableHTTP, proceed with original implementation
            else:
                # Use the discovered streamable URL
                # Make direct HTTP request to StreamableHTTP endpoint
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.post(
                        streamable_url,
                        json={
                        "jsonrpc": "2.0",
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {
                                "name": "mcp-gateway",
                                "version": "1.0.0"
                            }
                        },
                        "id": 1
                    },
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream"
                    }
                    )
                    
                    if response.status_code != 200:
                        raise Exception(f"Failed to initialize MCP session: {response.status_code}")
                    
                    # Now execute the tool
                    tool_response = await client.post(
                    streamable_url,
                    json={
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {
                            "name": tool_name,
                            "arguments": tool_arguments
                        },
                        "id": request_id
                    },
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream"
                    }
                    )
                    
                    if tool_response.status_code != 200:
                        raise Exception(f"Tool execution failed: {tool_response.status_code} - {tool_response.text}")
                    
                    # Return the tool response
                    result = tool_response.json()
                    return JSONResponse(
                    content=result,
                    headers={
                        "Cache-Control": "no-cache, no-store, must-revalidate",
                        "Pragma": "no-cache",
                        "Expires": "0"
                    }
                )
                
        except asyncio.TimeoutError:
            logger.error(f"Timeout connecting to MCP server at {streamable_url}")
            raise HTTPException(status_code=504, detail=f"Timeout connecting to service '{service_path}'")
        except Exception as e:
            logger.error(f"Error executing tool via StreamableHTTP: {e}", exc_info=True)
            raise HTTPException(status_code=502, detail=f"Failed to execute tool on service '{service_path}': {str(e)}")
            
    except Exception as e:
        # Log the error with appropriate level and context
        if isinstance(e, HTTPException):
            # For expected HTTP exceptions, we log at warning level
            if e.status_code >= 500:
                logger.error(f"Server error during StreamableHTTP tool execution on '{service_path}': {e}")
            else:
                logger.warning(f"Client error during StreamableHTTP tool execution on '{service_path}': {e}")
            raise
        else:
            # For unexpected exceptions, log as error with traceback
            logger.error(f"Unexpected error during StreamableHTTP tool execution on '{service_path}': {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"Internal server error during tool execution")

@app.post("/api/tool_auth/{service_path:path}", response_model=None)
async def auth_tool_request(
    request: Request,
    service_path: str,
    username: Annotated[str, Depends(api_auth)],
):
    """
    Authentication endpoint for tool execution via Nginx auth_request.
    
    This endpoint is used by Nginx to check if a user has permission to execute a tool
    on a specific service. It returns 200 if the user has permission, and an
    appropriate error code otherwise.
    
    This implementation leverages the MCP SDK's authentication mechanisms to verify
    user permissions against service-specific scopes following the MCP protocol standards.
    
    Auth flow:
    1. Verify user is authenticated using the MCP auth context
    2. Check service path exists and is enabled
    3. Verify user has appropriate scope for the service
    4. Return 200 OK if authorized, appropriate error code otherwise
    """
    try:
        # Normalize the service path for consistent handling
        if not service_path.startswith('/'):
            service_path = '/' + service_path
        
        # Check for authenticated user in request.state
        if not hasattr(request.state, "user") or not request.state.user or not getattr(request.state.user, "is_authenticated", False):
            logger.warning(f"Unauthorized attempt to access service '{service_path}': No valid authentication")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Check if the service exists and is enabled
        if service_path not in REGISTERED_SERVERS:
            logger.warning(f"Service not found: '{service_path}'")
            raise HTTPException(status_code=404, detail=f"Service '{service_path}' not found")
        
        if not MOCK_SERVICE_STATE.get(service_path, False):
            logger.warning(f"Service disabled: '{service_path}'")
            raise HTTPException(status_code=403, detail=f"Service '{service_path}' is disabled")
        
        # Get settings and determine required scope for this service
        auth_settings = AuthSettings()
        # First check for admin scope - grants access to all services
        if request.state.user.has_scope(auth_settings.registry_admin_scope):
            logger.info(f"User '{username}' granted execute access to '{service_path}' via admin scope")
            return JSONResponse(status_code=200, content={"status": "authorized"})
        
        # Check for service-specific execute scope
        execute_scope = auth_settings.get_server_execute_scope(service_path)
        if request.state.user.has_scope(execute_scope):
            logger.info(f"User '{username}' granted execute access to '{service_path}' via execute scope")
            return JSONResponse(status_code=200, content={"status": "authorized"})
        
        # No valid scope found
        logger.warning(f"User '{username}' denied access to '{service_path}' - missing scope: {execute_scope}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing required scope for service access: {execute_scope}",
        )
    except Exception as e:
        # Log the error with appropriate level and context
        if isinstance(e, HTTPException):
            # For expected HTTP exceptions, we log at warning level
            if e.status_code >= 500:
                logger.error(f"Server error during auth check for '{service_path}': {e}")
            else:
                logger.warning(f"Client error during auth check for '{service_path}': {e}")
            raise
        else:
            # For unexpected exceptions, log as error with traceback
            logger.error(f"Unexpected error during auth check for '{service_path}': {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"Internal server error during authorization")
# --- API endpoint for Tool Execution --- END

# --- Endpoint to get tool list for a service --- START
@app.get("/api/tools/{service_path:path}", response_model=None)
async def get_service_tools(
    request: Request,
    service_path: str,
    username: Annotated[str, Depends(api_auth)], # Requires authentication
):
    """
    Get the list of tools for a specific server.
    Requires the mcp:server:{service_path}:read scope or mcp:registry:admin scope.
    """
    # Check authorization
    if service_path != 'all':
        auth_dependency = require_access_for_path(service_path)
        await run_async_dependency(auth_dependency, {"request": request})
    else:
        auth_dependency = check_admin_scope()
        await run_async_dependency(auth_dependency, {"request": request})
        
    if not service_path.startswith('/'):
        service_path = '/' + service_path

    # Handle special case for '/all' to return tools from all servers
    if service_path == '/all':
        all_tools = []
        all_servers_tools = {}
        
        for path, server_info in REGISTERED_SERVERS.items():
            tool_list = server_info.get("tool_list")
            
            if tool_list is not None and isinstance(tool_list, list):
                # Add server information to each tool
                server_tools = []
                for tool in tool_list:
                    # Create a copy of the tool with server info added
                    tool_with_server = dict(tool)
                    tool_with_server["server_path"] = path
                    tool_with_server["server_name"] = server_info.get("server_name", "Unknown")
                    server_tools.append(tool_with_server)
                
                all_tools.extend(server_tools)
                all_servers_tools[path] = server_tools
        
        return {
            "service_path": "all",
            "tools": all_tools,
            "servers": all_servers_tools
        }
    
    # Handle specific server case (existing logic)
    server_info = REGISTERED_SERVERS.get(service_path)
    if not server_info:
        raise HTTPException(status_code=404, detail="Service path not registered")

    tool_list = server_info.get("tool_list") # Get the stored list

    if tool_list is None:
        # This might happen if the service hasn't become healthy yet
        raise HTTPException(status_code=404, detail="Tool list not available yet. Service may not be healthy or check is pending.")
    elif not isinstance(tool_list, list):
         # Data integrity check
        logger.warning(f"Warning: tool_list for {service_path} is not a list: {type(tool_list)}")
        raise HTTPException(status_code=500, detail="Internal server error: Invalid tool list format.")

    return {"service_path": service_path, "tools": tool_list}
# --- Endpoint to get tool list for a service --- END


# --- Refresh Endpoint --- START
@app.post("/api/refresh/{service_path:path}", response_model=None)
async def refresh_service(
    request: Request,
    service_path: str, 
    username: Annotated[str, Depends(api_auth)],
):
    """
    Refresh a service by running a health check.
    Requires the mcp:server:{service_path}:toggle scope or mcp:registry:admin scope.
    """
    # Check authorization
    auth_dependency = require_toggle_for_path(service_path)
    await run_async_dependency(auth_dependency, {"request": request})
    
    if not service_path.startswith('/'):
        service_path = '/' + service_path

    # Check if service exists
    if service_path not in REGISTERED_SERVERS:
        raise HTTPException(status_code=404, detail="Service path not registered")

    # Check if service is enabled
    is_enabled = MOCK_SERVICE_STATE.get(service_path, False)
    if not is_enabled:
        raise HTTPException(status_code=400, detail="Cannot refresh a disabled service")

    logger.info(f"Manual refresh requested for {service_path} by user '{username}'...")
    try:
        # Trigger the health check (which also updates tools if healthy)
        await perform_single_health_check(service_path)
        # --- Regenerate Nginx config after manual refresh --- START
        # The health check itself might trigger regeneration, but do it explicitly
        # here too to ensure it happens after the refresh attempt completes.
        logger.info(f"Regenerating Nginx config after manual refresh for {service_path}...")
        regenerate_nginx_config()
        # --- Regenerate Nginx config after manual refresh --- END
    except Exception as e:
        # Catch potential errors during the check itself
        logger.error(f"ERROR during manual refresh check for {service_path}: {e}")
        # Update status to reflect the error
        error_status = f"error: refresh execution failed ({type(e).__name__})"
        SERVER_HEALTH_STATUS[service_path] = error_status
        SERVER_LAST_CHECK_TIME[service_path] = datetime.now(timezone.utc)
        # Still broadcast the error state
        await broadcast_single_service_update(service_path)
        # --- Regenerate Nginx config even after refresh failure --- START
        # Ensure Nginx reflects the error state if it was previously healthy
        logger.info(f"Regenerating Nginx config after manual refresh failed for {service_path}...")
        regenerate_nginx_config()
        # --- Regenerate Nginx config even after refresh failure --- END
        # Return error response
        raise HTTPException(status_code=500, detail=f"Refresh check failed: {e}")

    # Check completed, broadcast the latest status
    await broadcast_single_service_update(service_path)

    # Return the latest status from global state
    final_status = SERVER_HEALTH_STATUS.get(service_path, "unknown")
    final_last_checked_dt = SERVER_LAST_CHECK_TIME.get(service_path)
    final_last_checked_iso = final_last_checked_dt.isoformat() if final_last_checked_dt else None
    final_num_tools = REGISTERED_SERVERS.get(service_path, {}).get("num_tools", 0)

    return {
        "service_path": service_path,
        "status": final_status,
        "last_checked_iso": final_last_checked_iso,
        "num_tools": final_num_tools
    }
# --- Refresh Endpoint --- END


# --- Add Edit Routes ---

@app.get("/edit/{service_path:path}", response_class=HTMLResponse)
async def edit_server_form(
    request: Request, 
    service_path: str, 
    username: Annotated[str, Depends(get_current_user)] # Require login
):
    if not service_path.startswith('/'):
        service_path = '/' + service_path

    server_info = REGISTERED_SERVERS.get(service_path)
    if not server_info:
        raise HTTPException(status_code=404, detail="Service path not found")
    
    return templates.TemplateResponse(
        "edit_server.html",
        {
            "request": request,
            "server": server_info,
            "username": username,
            "user_has_toggle_scope": lambda server_path: user_has_toggle_scope(request, server_path),
            "user_has_edit_scope": lambda server_path: user_has_edit_scope(request, server_path),
            "user_has_admin_scope": lambda: user_has_admin_scope(request)
        }
    )

@app.post("/edit/{service_path:path}")
async def edit_server_submit(
    service_path: str, 
    # Required Form fields
    name: Annotated[str, Form()], 
    proxy_pass_url: Annotated[str, Form()], 
    # Dependency
    username: Annotated[str, Depends(get_current_user)], 
    # Optional Form fields
    description: Annotated[str, Form()] = "", 
    tags: Annotated[str, Form()] = "", 
    num_tools: Annotated[int, Form()] = 0, 
    num_stars: Annotated[int, Form()] = 0, 
    is_python: Annotated[bool | None, Form()] = False,  
    license_str: Annotated[str, Form(alias="license")] = "N/A", 
):
    if not service_path.startswith('/'):
        service_path = '/' + service_path

    # Check if the server exists
    if service_path not in REGISTERED_SERVERS:
        raise HTTPException(status_code=404, detail="Service path not found")

    # Process tags
    tag_list = [tag.strip() for tag in tags.split(',') if tag.strip()]

    # Prepare updated server data (keeping original path)
    updated_server_entry = {
        "server_name": name,
        "description": description,
        "path": service_path, # Keep original path
        "proxy_pass_url": proxy_pass_url,
        "tags": tag_list,
        "num_tools": num_tools,
        "num_stars": num_stars,
        "is_python": bool(is_python), # Convert checkbox value
        "license": license_str,
    }

    # Save updated data to file
    success = save_server_to_file(updated_server_entry)
    if not success:
        # Optionally render form again with an error message
        raise HTTPException(status_code=500, detail="Failed to save updated server data")

    # Update in-memory registry
    REGISTERED_SERVERS[service_path] = updated_server_entry

    # Regenerate Nginx config as proxy_pass_url might have changed
    if not regenerate_nginx_config():
        logger.error("ERROR: Failed to update Nginx configuration after edit.")
        # Consider how to notify user - maybe flash message system needed
        
    # --- Update FAISS Index --- START
    logger.info(f"Updating service '{service_path}' in FAISS index after edit.")
    if embedding_model and faiss_index is not None:
        await add_or_update_service_in_faiss(service_path, updated_server_entry)
        logger.info(f"Service '{service_path}' updated in FAISS index.")
    else:
        logger.warning(f"Skipped FAISS update for '{service_path}' post-edit: model or index not ready.")
    # --- Update FAISS Index --- END

    logger.info(f"Server '{name}' ({service_path}) updated by user '{username}'")

    # Redirect back to the main page
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


# --- Helper function to broadcast single service update --- START
async def broadcast_single_service_update(service_path: str):
    """Sends the current status, tool count, and last check time for a specific service."""
    global active_connections, SERVER_HEALTH_STATUS, SERVER_LAST_CHECK_TIME, REGISTERED_SERVERS

    if not active_connections:
        return # No clients connected

    status = SERVER_HEALTH_STATUS.get(service_path, "unknown")
    last_checked_dt = SERVER_LAST_CHECK_TIME.get(service_path)
    last_checked_iso = last_checked_dt.isoformat() if last_checked_dt else None
    num_tools = REGISTERED_SERVERS.get(service_path, {}).get("num_tools", 0)

    update_data = {
        service_path: {
            "status": status,
            "last_checked_iso": last_checked_iso,
            "num_tools": num_tools
        }
    }
    message = json.dumps(update_data)
    logger.info(f"--- BROADCAST SINGLE: Sending update for {service_path}: {message}")

    # Use the same concurrent sending logic as in toggle
    disconnected_clients = set()
    current_connections = list(active_connections) # Copy to iterate safely
    send_tasks = []
    for conn in current_connections:
        send_tasks.append((conn, conn.send_text(message)))

    results = await asyncio.gather(*(task for _, task in send_tasks), return_exceptions=True)

    for i, result in enumerate(results):
        conn, _ = send_tasks[i]
        if isinstance(result, Exception):
            logger.warning(f"Error sending single update to WebSocket client {conn.client}: {result}. Marking for removal.")
            disconnected_clients.add(conn)
    if disconnected_clients:
        logger.info(f"Removing {len(disconnected_clients)} disconnected clients after single update broadcast.")
        for conn in disconnected_clients:
            if conn in active_connections:
                active_connections.remove(conn)
# --- Helper function to broadcast single service update --- END


# --- WebSocket Endpoint ---
@app.websocket("/ws/health_status")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.add(websocket)
    logger.info(f"WebSocket client connected: {websocket.client}")
    try:
        # --- Send initial status upon connection (Formatted) --- START
        initial_data_to_send = {}
        for path, status in SERVER_HEALTH_STATUS.items():
            last_checked_dt = SERVER_LAST_CHECK_TIME.get(path)
            # Send ISO string or None
            last_checked_iso = last_checked_dt.isoformat() if last_checked_dt else None
            # Get the current tool count from REGISTERED_SERVERS
            num_tools = REGISTERED_SERVERS.get(path, {}).get("num_tools", 0) # Default to 0 if not found

            initial_data_to_send[path] = {
                "status": status,
                "last_checked_iso": last_checked_iso,
                "num_tools": num_tools # --- Add num_tools --- START
            }
            # --- Add num_tools --- END
        await websocket.send_text(json.dumps(initial_data_to_send))
        # --- Send initial status upon connection (Formatted) --- END

        # Keep connection open, handle potential disconnects
        while True:
            # We don't expect messages from client in this case, just keep alive
            await websocket.receive_text() # This will raise WebSocketDisconnect if client closes
    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected: {websocket.client}")
    except Exception as e:
        logger.error(f"WebSocket error for {websocket.client}: {e}")
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)
            logger.info(f"WebSocket connection removed: {websocket.client}")


# --- Run (for local testing) ---
# Use: uvicorn registry.main:app --reload --host 0.0.0.0 --port 7860

if __name__ == "__main__":
    # Get port from environment variable or use default
    port = int(os.environ.get("REGISTRY_PORT", 7860))
    uvicorn.run(app, host="0.0.0.0", port=port)
# Helper functions for template context
def user_has_toggle_scope(request, server_path):
    """Check if the current user has toggle permission for a server."""
    if not hasattr(request.state, "user") or not hasattr(request.state.user, "has_scope"):
        return False
        
    auth_settings = AuthSettings()
    
    # Admin scope grants all permissions
    if request.state.user.has_scope(auth_settings.registry_admin_scope):
        return True
        
    # Check for server-specific toggle scope
    base_scope = auth_settings.server_execute_scope_prefix + server_path.lstrip("/")
    toggle_scope = f"{base_scope}:toggle"
    return request.state.user.has_scope(toggle_scope)
    
def user_has_edit_scope(request, server_path):
    """Check if the current user has edit permission for a server."""
    if not hasattr(request.state, "user") or not hasattr(request.state.user, "has_scope"):
        return False
        
    auth_settings = AuthSettings()
    
    # Admin scope grants all permissions
    if request.state.user.has_scope(auth_settings.registry_admin_scope):
        return True
        
    # Check for server-specific edit scope
    base_scope = auth_settings.server_execute_scope_prefix + server_path.lstrip("/")
    edit_scope = f"{base_scope}:edit"
    return request.state.user.has_scope(edit_scope)
    
def user_has_admin_scope(request):
    """Check if the current user has admin scope."""
    if not hasattr(request.state, "user") or not hasattr(request.state.user, "has_scope"):
        return False
        
    auth_settings = AuthSettings()
    return request.state.user.has_scope(auth_settings.registry_admin_scope)
