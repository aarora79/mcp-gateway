import os
import json
import secrets
import asyncio
import subprocess
import httpx
import logging
from urllib.parse import urlparse
# argparse removed as we're using environment variables instead
from contextlib import asynccontextmanager
from pathlib import Path  # Import Path
from typing import Annotated, List, Set
from datetime import datetime, timezone

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer
from registry.oauth_service import oauth_manager, OAuthConfig, OAuthDiscovery

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
)
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from dotenv import load_dotenv

# --- MCP Client Imports --- START
from mcp import ClientSession
from mcp.client.sse import sse_client
# --- MCP Client Imports --- END

# --- Define paths based on container structure --- START
CONTAINER_APP_DIR = Path("/app")
CONTAINER_REGISTRY_DIR = CONTAINER_APP_DIR / "registry"
CONTAINER_LOG_DIR = CONTAINER_APP_DIR / "logs"
EMBEDDINGS_MODEL_DIR = CONTAINER_REGISTRY_DIR / "models" / EMBEDDINGS_MODEL_NAME
# --- Define paths based on container structure --- END

# Determine the base directory of this script (registry folder)
# BASE_DIR = Path(__file__).resolve().parent # Less relevant inside container

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
NGINX_CONFIG_PATH = Path("/etc/nginx/conf.d/nginx_rev_proxy.conf") # Target the actual Nginx config file
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

# --- REMOVE Logging Setup from here --- START
# # Ensure log directory exists
# CONTAINER_LOG_DIR.mkdir(parents=True, exist_ok=True)
#
# # Configure logging
# logging.basicConfig(
#     level=logging.INFO,
#     format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
#     handlers=[
#         logging.FileHandler(LOG_FILE_PATH), # Log to file in /app/logs
#         logging.StreamHandler() # Log to console (stdout/stderr)
#     ]
# )
#
# logger = logging.getLogger(__name__) # Get a logger instance
# logger.info("Logging configured. Application starting...")
# --- REMOVE Logging Setup from here --- END

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

# --- WebSocket Connection Management ---
active_connections: Set[WebSocket] = set()

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
        model_path = Path(EMBEDDINGS_MODEL_PATH)
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

        # Keep track of connections that fail during send
        disconnected_clients = set()

        # Iterate over a copy of the set to allow modification during iteration
        current_connections = list(active_connections)

        # Create send tasks and associate them with the connection
        send_tasks = []
        for conn in current_connections:
            send_tasks.append((conn, conn.send_text(message)))

        # Run tasks concurrently and check results
        results = await asyncio.gather(*(task for _, task in send_tasks), return_exceptions=True)

        for i, result in enumerate(results):
            conn, _ = send_tasks[i] # Get the corresponding connection
            if isinstance(result, Exception):
                # Check if it's a connection-related error (more specific checks possible)
                # For now, assume any exception during send means the client is gone
                logger.warning(f"Error sending to WebSocket client {conn.client}: {result}. Marking for removal.")
                disconnected_clients.add(conn)

        # Remove all disconnected clients identified during the broadcast
        if disconnected_clients:
            logger.info(f"Removing {len(disconnected_clients)} disconnected clients after broadcast.")
            for conn in disconnected_clients:
                if conn in active_connections:
                    active_connections.remove(conn)

# Session management configuration
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

# --- Nginx Config Generation ---

LOCATION_BLOCK_TEMPLATE = """
    location {path}/ {{
        proxy_pass {proxy_pass_url};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
"""

HTTPS_LOCATION_BLOCK_TEMPLATE = """
    location {path}/ {{
        proxy_pass {proxy_pass_url}/;
        proxy_http_version 1.1;
        
        # HTTPS upstream SSL configuration
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
        proxy_ssl_protocols TLSv1.2 TLSv1.3;
        proxy_ssl_server_name on;
        proxy_ssl_name {upstream_host};
        
        # Proxy headers - use actual upstream hostname for Host
        proxy_set_header Host {upstream_host};
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # OAuth token forwarding (if available)
        {auth_headers}
    }}
"""

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

COMMENTED_HTTPS_LOCATION_BLOCK_TEMPLATE = """
#    location {path}/ {{
#        proxy_pass {proxy_pass_url}/;
#        proxy_http_version 1.1;
#        
#        # HTTPS upstream SSL configuration
#        proxy_ssl_verify on;
#        proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
#        proxy_ssl_protocols TLSv1.2 TLSv1.3;
#        proxy_ssl_server_name on;
#        proxy_ssl_name {upstream_host};
#        
#        # Proxy headers - use actual upstream hostname for Host
#        proxy_set_header Host {upstream_host};
#        proxy_set_header X-Real-IP $remote_addr;
#        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#        proxy_set_header X-Forwarded-Proto $scheme;
#        
#        # OAuth token forwarding (if available)
#        {auth_headers}
#    }}
"""

def extract_upstream_host(proxy_url: str) -> str:
    """Extract the hostname from a proxy URL for SNI configuration."""
    parsed = urlparse(proxy_url)
    return parsed.hostname or "localhost"

def generate_auth_headers_for_nginx(server_path: str) -> str:
    """Generate nginx proxy_set_header directives for OAuth authentication."""
    if not oauth_manager.has_oauth_config(server_path):
        return "# No OAuth configuration"
    
    try:
        # Get auth headers from OAuth manager
        auth_headers = oauth_manager.get_auth_headers(server_path)
        if not auth_headers:
            return "# OAuth configured but no valid token"
        
        # Convert to nginx proxy_set_header directives
        nginx_headers = []
        for header_name, header_value in auth_headers.items():
            # Escape any special characters in the header value
            escaped_value = header_value.replace('"', '\\"')
            nginx_headers.append(f'        proxy_set_header {header_name} "{escaped_value}";')
        
        return "\n".join(nginx_headers)
    except Exception as e:
        logger.warning(f"Failed to generate auth headers for {server_path}: {e}")
        return "# OAuth configured but error generating headers"

def regenerate_nginx_config():
    """Generates the nginx config file based on registered servers and their state."""
    logger.info(f"Attempting to directly modify Nginx config at {NGINX_CONFIG_PATH}...")
    
    # Define markers
    START_MARKER = "# DYNAMIC_LOCATIONS_START"
    END_MARKER = "# DYNAMIC_LOCATIONS_END"

    try:
        # Read the *target* Nginx config file
        with open(NGINX_CONFIG_PATH, 'r') as f_target:
            target_content = f_target.read()

        # Generate the location blocks section content (only needs to be done once)
        location_blocks_content = []
        sorted_paths = sorted(REGISTERED_SERVERS.keys())

        for path in sorted_paths:
            server_info = REGISTERED_SERVERS[path]
            proxy_url = server_info.get("proxy_pass_url")
            is_enabled = MOCK_SERVICE_STATE.get(path, False)
            health_status = SERVER_HEALTH_STATUS.get(path)

            if not proxy_url:
                logger.warning(f"Skipping server '{server_info['server_name']}' ({path}) - missing proxy_pass_url.")
                continue

            # Determine if this is an HTTPS upstream
            is_https = proxy_url.startswith("https://")
            upstream_host = extract_upstream_host(proxy_url) if is_https else ""
            auth_headers = generate_auth_headers_for_nginx(path) if is_https else ""

            # Choose the appropriate template based on status and protocol
            if is_enabled and health_status == "healthy":
                if is_https:
                    block = HTTPS_LOCATION_BLOCK_TEMPLATE.format(
                        path=path, 
                        proxy_pass_url=proxy_url,
                        upstream_host=upstream_host,
                        auth_headers=auth_headers
                    )
                else:
                    block = LOCATION_BLOCK_TEMPLATE.format(path=path, proxy_pass_url=proxy_url)
            else:
                if is_https:
                    block = COMMENTED_HTTPS_LOCATION_BLOCK_TEMPLATE.format(
                        path=path, 
                        proxy_pass_url=proxy_url,
                        upstream_host=upstream_host,
                        auth_headers=auth_headers
                    )
                else:
                    block = COMMENTED_LOCATION_BLOCK_TEMPLATE.format(path=path, proxy_pass_url=proxy_url)
            
            location_blocks_content.append(block)
        
        generated_section = "\n".join(location_blocks_content).strip()

        # --- Replace content between ALL marker pairs --- START
        new_content = ""
        current_pos = 0
        while True:
            # Find the next start marker
            start_index = target_content.find(START_MARKER, current_pos)
            if start_index == -1:
                # No more start markers found, append the rest of the file
                new_content += target_content[current_pos:]
                break

            # Find the corresponding end marker after the start marker
            end_index = target_content.find(END_MARKER, start_index + len(START_MARKER))
            if end_index == -1:
                # Found a start marker without a matching end marker, log error and stop
                logger.error(f"Found '{START_MARKER}' at position {start_index} without a matching '{END_MARKER}' in {NGINX_CONFIG_PATH}. Aborting regeneration.")
                # Append the rest of the file to avoid data loss, but don't reload
                new_content += target_content[current_pos:] 
                # Write back the partially processed content? Or just return False?
                # Let's return False to indicate failure without modifying the file potentially incorrectly.
                return False # Indicate failure
            
            # Append the content before the current start marker
            new_content += target_content[current_pos:start_index + len(START_MARKER)]
            # Append the newly generated section (with appropriate newlines)
            new_content += f"\n\n{generated_section}\n\n    "
            # Update current position to be after the end marker
            current_pos = end_index
        
        # Check if any replacements were made (i.e., if current_pos moved beyond 0)
        if current_pos == 0:
             logger.error(f"No marker pairs '{START_MARKER}'...'{END_MARKER}' found in {NGINX_CONFIG_PATH}. Cannot regenerate.")
             return False

        final_config = new_content # Use the iteratively built content
        # --- Replace content between ALL marker pairs --- END

        # # Find the start and end markers in the target content
        # start_index = target_content.find(START_MARKER)
        # end_index = target_content.find(END_MARKER)
        #
        # if start_index == -1 or end_index == -1 or end_index <= start_index:
        #     logger.error(f"Markers '{START_MARKER}' and/or '{END_MARKER}' not found or in wrong order in {NGINX_CONFIG_PATH}. Cannot regenerate.")
        #     return False
        # 
        # # Extract the parts before the start marker and after the end marker
        # prefix = target_content[:start_index + len(START_MARKER)]
        # suffix = target_content[end_index:]
        #
        # # Construct the new content
        # # Add newlines around the generated section for readability
        # final_config = f"{prefix}\n\n{generated_section}\n\n    {suffix}"

        # Write the modified content back to the target file
        with open(NGINX_CONFIG_PATH, 'w') as f_out:
            f_out.write(final_config)
        logger.info(f"Nginx config file {NGINX_CONFIG_PATH} modified successfully.")

        # --- Reload Nginx --- START
        try:
            logger.info("Attempting to reload Nginx configuration...")
            result = subprocess.run(['/usr/sbin/nginx', '-s', 'reload'], check=True, capture_output=True, text=True)
            logger.info(f"Nginx reload successful. stdout: {result.stdout.strip()}")
            return True
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
        # --- Reload Nginx --- END

    except FileNotFoundError:
        logger.error(f"Target Nginx config file not found at {NGINX_CONFIG_PATH}. Cannot regenerate.")
        return False
    except Exception as e:
        logger.error(f"Failed to modify Nginx config at {NGINX_CONFIG_PATH}: {e}", exc_info=True)
        return False

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

    SERVERS_DIR.mkdir(parents=True, exist_ok=True)

    temp_servers = {}
    server_files = list(SERVERS_DIR.glob("**/*.json"))
    logger.info(f"Found {len(server_files)} JSON files in {SERVERS_DIR} and its subdirectories")

    for server_file in server_files:
        if server_file.name == STATE_FILE_PATH.name:
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
                    server_info["tool_list"] = server_info.get("tool_list", [])
                    server_info["auth_type"] = server_info.get("auth_type", "none")

                    # Restore OAuth configuration
                    if server_info.get("auth_type") == "oauth2" and "oauth_config" in server_info:
                        try:
                            oauth_config = OAuthConfig.from_dict(server_info["oauth_config"])
                            oauth_manager.register_server_oauth(server_path, oauth_config)
                            logger.info(f"Restored OAuth config for {server_path}")
                        except Exception as e:
                            logger.error(f"Failed to restore OAuth config for {server_path}: {e}")

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
                logger.info("Successfully loaded persisted state.")
        else:
            logger.info(f"No persisted state file found at {STATE_FILE_PATH}. Initializing state.")

    except json.JSONDecodeError as e:
        logger.error(f"Could not parse JSON from {STATE_FILE_PATH}: {e}. Initializing empty state.")
        loaded_state = {}
    except Exception as e:
        logger.error(f"Failed to read state file {STATE_FILE_PATH}: {e}. Initializing empty state.", exc_info=True)
        loaded_state = {}

    # Initialize MOCK_SERVICE_STATE: Use loaded state if valid, otherwise default to False.
    # Ensure state only contains keys for currently registered servers.
    MOCK_SERVICE_STATE = {}
    for path in REGISTERED_SERVERS.keys():
        MOCK_SERVICE_STATE[path] = loaded_state.get(path, False) # Default to False if not in loaded state or state was invalid

    logger.info(f"Initial mock service state loaded: {MOCK_SERVICE_STATE}")
    # --- Load persisted mock service state --- END


    # Initialize health status to 'checking' or 'disabled' based on the just loaded state
    global SERVER_HEALTH_STATUS
    SERVER_HEALTH_STATUS = {} # Start fresh
    for path, is_enabled in MOCK_SERVICE_STATE.items():
        if path in REGISTERED_SERVERS: # Should always be true here now
            SERVER_HEALTH_STATUS[path] = "checking" if is_enabled else "disabled"
        else:
             # This case should ideally not happen if MOCK_SERVICE_STATE is built from REGISTERED_SERVERS
             logger.warning(f"Path {path} found in loaded state but not in registered servers. Ignoring.")

    logger.info(f"Initialized health status based on loaded state: {SERVER_HEALTH_STATUS}")

    # We no longer need the explicit default initialization block below
    # print("Initializing mock service state (defaulting to disabled)...")
    # MOCK_SERVICE_STATE = {path: False for path in REGISTERED_SERVERS.keys()}
    # # TODO: Consider loading initial state from a persistent store if needed
    # print(f"Initial mock state: {MOCK_SERVICE_STATE}")


# --- Helper function to save server data ---
def save_server_to_file(server_info):
    try:
        # Create servers directory if it doesn't exist
        SERVERS_DIR.mkdir(parents=True, exist_ok=True) # Ensure it exists

        # Generate filename based on path
        path = server_info["path"]
        filename = path_to_filename(path)
        file_path = SERVERS_DIR / filename

        with open(file_path, "w") as f:
            json.dump(server_info, f, indent=2)

        logger.info(f"Successfully saved server '{server_info['server_name']}' to {file_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to save server '{server_info.get('server_name', 'UNKNOWN')}' data to {filename}: {e}", exc_info=True)
        return False


# --- Helper function to generate description from schema --- START
def generate_description_from_schema(tool_name: str, tool_schema: dict) -> dict:
    """Generate a meaningful description from the tool schema when no description is available"""
    parsed_desc = {
        "main": "No description available.",
        "args": None,
        "returns": None,
        "raises": None,
    }
    
    if not tool_schema or not isinstance(tool_schema, dict):
        return parsed_desc
    
    properties = tool_schema.get("properties", {})
    required = tool_schema.get("required", [])
    
    if properties:
        # Generate main description
        param_count = len(properties)
        required_count = len(required)
        
        if param_count > 0:
            main_desc_parts = [f"Tool that accepts {param_count} parameter{'s' if param_count != 1 else ''}"]
            if required_count > 0:
                main_desc_parts.append(f"({required_count} required)")
            parsed_desc["main"] = " ".join(main_desc_parts) + "."
        
        # Generate args description from schema properties
        args_parts = []
        for prop_name, prop_info in properties.items():
            prop_desc = prop_info.get("description", "")
            prop_type = prop_info.get("type", "")
            is_required = prop_name in required
            
            arg_line = f"- {prop_name}"
            if prop_type:
                arg_line += f" ({prop_type})"
            if is_required:
                arg_line += " [required]"
            if prop_desc:
                arg_line += f": {prop_desc}"
            
            args_parts.append(arg_line)
        
        if args_parts:
            parsed_desc["args"] = "\n".join(args_parts)
    
    return parsed_desc
# --- Helper function to generate description from schema --- END

# --- MCP Client Function to Get Tool List --- START (Renamed)
async def get_tools_from_server(base_url: str, server_path: str = None) -> List[dict] | None:
    """
    Connects to an MCP server via SSE, lists tools, and returns their details
    (name, description, schema). Now supports OAuth authentication.

    Args:
        base_url: The base URL of the MCP server (e.g., http://localhost:8000).
        server_path: The server path for OAuth token lookup (optional).

    Returns:
        A list of tool detail dictionaries (keys: name, description, schema),
        or None if connection/retrieval fails.
    """
    if not base_url:
        logger.error("MCP Check Error: Base URL is empty.")
        return None

    sse_url = base_url.rstrip('/') + "/sse"
    secure_prefix = "s" if sse_url.startswith("https://") else ""
    mcp_server_url = f"http{secure_prefix}://{sse_url[len(f'http{secure_prefix}://'):]}"

    # Get OAuth headers if server requires authentication
    auth_headers = {}
    if server_path and oauth_manager.has_oauth_config(server_path):
        try:
            token = await oauth_manager.get_valid_token(server_path)
            if token:
                auth_headers = oauth_manager.get_auth_headers(server_path)
                logger.info(f"Using OAuth authentication for {server_path}")
        except Exception as e:
            logger.error(f"Failed to get OAuth token for {server_path}: {e}")
            return None

    logger.info(f"Attempting to connect to MCP server at {mcp_server_url} to get tool list...")
    try:
        # Use SSE connection with auth headers (if provided)
        async with sse_client(mcp_server_url, headers=auth_headers) as (read, write):
            async with ClientSession(read, write, sampling_callback=None) as session:
                await asyncio.wait_for(session.initialize(), timeout=10.0)
                tools_response = await asyncio.wait_for(session.list_tools(), timeout=15.0)

                tool_details_list = []
                if tools_response and hasattr(tools_response, 'tools'):
                    for tool in tools_response.tools:
                        tool_name = getattr(tool, 'name', 'Unknown Name')
                        tool_desc = getattr(tool, 'description', None) or getattr(tool, '__doc__', None)

                        # Parse docstring (existing logic)
                        parsed_desc = {
                            "main": "No description available.",
                            "args": None,
                            "returns": None,
                            "raises": None,
                        }
                        
                        # Try to get tool-level description first
                        has_tool_description = False
                        if tool_desc:
                            tool_desc = tool_desc.strip()
                            lines = tool_desc.split('\n')
                            main_desc_lines = []
                            current_section = "main"
                            section_content = []

                            for line in lines:
                                stripped_line = line.strip()
                                if stripped_line.startswith("Args:"):
                                    parsed_desc["main"] = "\n".join(main_desc_lines).strip()
                                    current_section = "args"
                                    section_content = [stripped_line[len("Args:"):].strip()]
                                elif stripped_line.startswith("Returns:"):
                                    if current_section != "main": 
                                        parsed_desc[current_section] = "\n".join(section_content).strip()
                                    else: 
                                        parsed_desc["main"] = "\n".join(main_desc_lines).strip()
                                    current_section = "returns"
                                    section_content = [stripped_line[len("Returns:"):].strip()]
                                elif stripped_line.startswith("Raises:"):
                                    if current_section != "main": 
                                        parsed_desc[current_section] = "\n".join(section_content).strip()
                                    else: 
                                        parsed_desc["main"] = "\n".join(main_desc_lines).strip()
                                    current_section = "raises"
                                    section_content = [stripped_line[len("Raises:"):].strip()]
                                elif current_section == "main":
                                    main_desc_lines.append(line.strip())
                                else:
                                    section_content.append(line.strip())

                            if current_section != "main":
                                parsed_desc[current_section] = "\n".join(section_content).strip()
                            elif not parsed_desc["main"] and main_desc_lines:
                                parsed_desc["main"] = "\n".join(main_desc_lines).strip()

                            if not parsed_desc["main"] and (parsed_desc["args"] or parsed_desc["returns"] or parsed_desc["raises"]):
                                parsed_desc["main"] = "(No primary description provided)"
                            
                            # Check if we actually got a meaningful description
                            if parsed_desc["main"] and parsed_desc["main"] != "No description available.":
                                has_tool_description = True

                        tool_schema = getattr(tool, 'inputSchema', {})
                        
                        # If no meaningful tool description was found, generate from schema
                        if not has_tool_description and tool_schema:
                            logger.info(f"No tool description found for {tool_name}, generating from schema...")
                            parsed_desc = generate_description_from_schema(tool_name, tool_schema)

                        tool_details_list.append({
                            "name": tool_name,
                            "parsed_description": parsed_desc,
                            "schema": tool_schema
                        })

                logger.info(f"Successfully retrieved details for {len(tool_details_list)} tools from {mcp_server_url}.")
                return tool_details_list

    except asyncio.TimeoutError:
        logger.error(f"MCP Check Error: Timeout during session operation with {mcp_server_url}.")
        return None
    except ConnectionRefusedError:
        logger.error(f"MCP Check Error: Connection refused by {mcp_server_url}.")
        return None
    except Exception as e:
        logger.error(f"MCP Check Error: Failed to get tool list from {mcp_server_url}: {type(e).__name__} - {e}")
        return None

# --- MCP Client Function to Get Tool List --- END


# --- Single Health Check Logic ---
async def health_check_with_session(url: str, server_path: str) -> tuple[bool, str]:
    """Check MCP server health using SSE client connection"""
    try:
        # Get OAuth headers
        token = await oauth_manager.get_valid_token(server_path)
        if not token:
            return False, "No valid OAuth token"
        
        auth_headers = oauth_manager.get_auth_headers(server_path)
        
        # Build SSE URL
        sse_url = url.rstrip('/') + "/sse"
        secure_prefix = "s" if sse_url.startswith("https://") else ""
        mcp_server_url = f"http{secure_prefix}://{sse_url[len(f'http{secure_prefix}://'):]}"
        
        logger.info(f"Testing OAuth MCP connection to {mcp_server_url}")
        
        # Test SSE connection with a short timeout
        async with sse_client(mcp_server_url, headers=auth_headers) as (read, write):
            async with ClientSession(read, write, sampling_callback=None) as session:
                # Just test if we can initialize the session
                await asyncio.wait_for(session.initialize(), timeout=5.0)
                logger.info(f"OAuth MCP session initialized successfully for {server_path}")
                return True, "MCP session healthy"
                
    except asyncio.TimeoutError:
        return False, "MCP connection timeout"
    except Exception as e:
        logger.debug(f"OAuth MCP health check failed for {server_path}: {e}")
        return False, f"MCP connection failed: {type(e).__name__}"


async def perform_single_health_check(path: str) -> tuple[str, datetime | None]:
    """Performs a health check for a single service path and updates global state."""
    global SERVER_HEALTH_STATUS, SERVER_LAST_CHECK_TIME, REGISTERED_SERVERS

    server_info = REGISTERED_SERVERS.get(path)
    previous_status = SERVER_HEALTH_STATUS.get(path)

    if not server_info:
        return "error: server not registered", None

    url = server_info.get("proxy_pass_url")
    is_enabled = MOCK_SERVICE_STATE.get(path, False)

    last_checked_time = datetime.now(timezone.utc)
    SERVER_LAST_CHECK_TIME[path] = last_checked_time

    if not url:
        current_status = "error: missing URL"
        SERVER_HEALTH_STATUS[path] = current_status
        logger.info(f"Health check skipped for {path}: Missing URL.")
        if is_enabled and previous_status == "healthy":
            logger.info(f"Status changed from healthy for {path}, regenerating Nginx config...")
            regenerate_nginx_config()
        return current_status, last_checked_time

    if previous_status != "checking":
        logger.info(f"Setting status to 'checking' for {path} ({url})...")
        SERVER_HEALTH_STATUS[path] = "checking"

    # Use different health check methods based on OAuth requirement
    if oauth_manager.has_oauth_config(path):
        # For OAuth servers, use MCP SSE client directly
        logger.info(f"Using MCP SSE health check for OAuth server {path}")
        try:
            is_healthy, health_message = await health_check_with_session(url, path)
            if is_healthy:
                current_status = "healthy"
                logger.info(f"OAuth MCP health check successful for {path}: {health_message}")
                
                # Run tool fetching logic if transitioning to healthy
                if previous_status != "healthy":
                    logger.info(f"OAuth service {path} transitioned to healthy. Regenerating Nginx config and fetching tool list...")
                    regenerate_nginx_config()

                    if url:
                        tool_list = await get_tools_from_server(url, path)

                        if tool_list is not None:
                            new_tool_count = len(tool_list)
                            current_tool_list = REGISTERED_SERVERS[path].get("tool_list", [])
                            current_tool_count = REGISTERED_SERVERS[path].get("num_tools", 0)

                            current_tool_list_str = sorted([json.dumps(t, sort_keys=True) for t in current_tool_list])
                            new_tool_list_str = sorted([json.dumps(t, sort_keys=True) for t in tool_list])

                            if current_tool_list_str != new_tool_list_str or current_tool_count != new_tool_count:
                                logger.info(f"Updating tool list for {path}. New count: {new_tool_count}.")
                                REGISTERED_SERVERS[path]["tool_list"] = tool_list
                                REGISTERED_SERVERS[path]["num_tools"] = new_tool_count
                                if not save_server_to_file(REGISTERED_SERVERS[path]):
                                    logger.error(f"Failed to save updated server info for {path}")
                            else:
                                logger.info(f"Tool list for {path} unchanged.")
                        else:
                            logger.info(f"Failed to retrieve tool list for healthy OAuth service {path}.")
            else:
                current_status = f"unhealthy: {health_message}"
                logger.info(f"OAuth MCP health check failed for {path}: {health_message}")
                
        except Exception as e:
            current_status = f"error: MCP check failed - {e}"
            logger.error(f"OAuth MCP health check error for {path}: {e}")
    else:
        # For non-OAuth servers, use traditional curl HEAD request
        health_check_url = url.rstrip('/') + "/sse"
        cmd = ['curl', '--head', '-s', '-f', '--max-time', str(HEALTH_CHECK_TIMEOUT_SECONDS)]
        cmd.append(health_check_url)
        current_status = "checking"

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=HEALTH_CHECK_TIMEOUT_SECONDS + 2)
            stderr_str = stderr.decode().strip() if stderr else ''

            if proc.returncode == 0:
                current_status = "healthy"
                logger.info(f"Health check successful for {path} ({url}).")

                if previous_status != "healthy":
                    logger.info(f"Service {path} transitioned to healthy. Regenerating Nginx config and fetching tool list...")
                    regenerate_nginx_config()

                    if url:
                        tool_list = await get_tools_from_server(url, path)

                        if tool_list is not None:
                            new_tool_count = len(tool_list)
                            current_tool_list = REGISTERED_SERVERS[path].get("tool_list", [])
                            current_tool_count = REGISTERED_SERVERS[path].get("num_tools", 0)

                            current_tool_list_str = sorted([json.dumps(t, sort_keys=True) for t in current_tool_list])
                            new_tool_list_str = sorted([json.dumps(t, sort_keys=True) for t in tool_list])

                            if current_tool_list_str != new_tool_list_str or current_tool_count != new_tool_count:
                                logger.info(f"Updating tool list for {path}. New count: {new_tool_count}.")
                                REGISTERED_SERVERS[path]["tool_list"] = tool_list
                                REGISTERED_SERVERS[path]["num_tools"] = new_tool_count
                                if not save_server_to_file(REGISTERED_SERVERS[path]):
                                    logger.error(f"Failed to save updated server info for {path}")
                            else:
                                logger.info(f"Tool list for {path} unchanged.")
                        else:
                            logger.info(f"Failed to retrieve tool list for healthy service {path}.")

            elif proc.returncode == 22:
                current_status = "unhealthy (HTTP error)"
                logger.info(f"Health check unhealthy (HTTP >= 400) for {path} ({url}). Stderr: {stderr_str}")
            elif proc.returncode == 7:
                current_status = "error: connection failed"
                logger.info(f"Health check connection failed for {path} ({url}). Stderr: {stderr_str}")
            elif proc.returncode == 28:
                current_status = f"error: timeout ({HEALTH_CHECK_TIMEOUT_SECONDS}s)"
                logger.info(f"Health check timeout for {path} ({url})")
            else:
                error_msg = f"error: check failed (code {proc.returncode})"
                if stderr_str:
                    error_msg += f" - {stderr_str}"
                current_status = error_msg
                logger.info(f"Health check failed for {path} ({url}): {error_msg}")

        except asyncio.TimeoutError:
            current_status = "error: check process timeout"
            logger.info(f"Health check asyncio.wait_for timeout for {path} ({url})")
        except FileNotFoundError:
            current_status = "error: command not found"
            logger.error(f"ERROR: 'curl' command not found during health check for {path}.")
        except Exception as e:
            current_status = f"error: {type(e).__name__}"
            logger.error(f"ERROR: Unexpected error during health check for {path} ({url}): {e}")

    SERVER_HEALTH_STATUS[path] = current_status
    logger.info(f"Final health status for {path}: {current_status}")

    if path in REGISTERED_SERVERS and embedding_model and faiss_index is not None:
        await add_or_update_service_in_faiss(path, REGISTERED_SERVERS[path])

    if is_enabled:
        if previous_status == "healthy" and current_status != "healthy":
            logger.info(f"Status changed FROM healthy for enabled service {path}, regenerating Nginx config...")
            regenerate_nginx_config()

    return current_status, last_checked_time


# --- Background Health Check Task ---
async def run_health_checks():
    """Periodically checks the health of registered *enabled* services."""
    while True:
        logger.info(f"Running periodic health checks (Interval: {HEALTH_CHECK_INTERVAL_SECONDS}s)...")
        paths_to_check = list(REGISTERED_SERVERS.keys())
        needs_broadcast = False # Flag to check if any status actually changed

        # --- Use a copy of MOCK_SERVICE_STATE for stable iteration --- START
        current_enabled_state = MOCK_SERVICE_STATE.copy()
        # --- Use a copy of MOCK_SERVICE_STATE for stable iteration --- END

        for path in paths_to_check:
            if path not in REGISTERED_SERVERS: # Check if server was removed during the loop
                continue

            # --- Use copied state for check --- START
            # is_enabled = MOCK_SERVICE_STATE.get(path, False)
            is_enabled = current_enabled_state.get(path, False)
            # --- Use copied state for check --- END
            previous_status = SERVER_HEALTH_STATUS.get(path)

            if not is_enabled:
                new_status = "disabled"
                if previous_status != new_status:
                    SERVER_HEALTH_STATUS[path] = new_status
                    # Also clear last check time when disabling? Or keep it? Keep for now.
                    # SERVER_LAST_CHECK_TIME[path] = None
                    needs_broadcast = True
                    logger.info(f"Service {path} is disabled. Setting status.")
                continue # Skip health check for disabled services

            # --- Service is enabled, perform check using the new function ---
            logger.info(f"Performing periodic check for enabled service: {path}")
            try:
                # Call the refactored check function
                # We only care if the status *changed* from the beginning of the cycle for broadcast purposes
                current_status, _ = await perform_single_health_check(path)
                if previous_status != current_status:
                    needs_broadcast = True
            except Exception as e:
                # Log error if the check function itself fails unexpectedly
                logger.error(f"ERROR: Unexpected exception calling perform_single_health_check for {path}: {e}")
                # Update status to reflect this error?
                error_status = f"error: check execution failed ({type(e).__name__})"
                if previous_status != error_status:
                    SERVER_HEALTH_STATUS[path] = error_status
                    SERVER_LAST_CHECK_TIME[path] = datetime.now(timezone.utc) # Record time of failure
                    needs_broadcast = True


        logger.info(f"Finished periodic health checks. Current status map: {SERVER_HEALTH_STATUS}")
        # Broadcast status update only if something changed during this cycle
        if needs_broadcast:
            logger.info("Broadcasting updated health status after periodic check...")
            await broadcast_health_status()
        else:
            logger.info("No status changes detected in periodic check, skipping broadcast.")

        # Wait for the next interval
        await asyncio.sleep(HEALTH_CHECK_INTERVAL_SECONDS)


# --- Lifespan for Startup Task ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Configure Logging INSIDE lifespan --- START
    # Ensure log directory exists
    CONTAINER_LOG_DIR.mkdir(parents=True, exist_ok=True) # Should be defined now

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE_PATH), # Use correct variable
            logging.StreamHandler() # Log to console (stdout/stderr)
        ]
    )
    logger.info("Logging configured. Running startup tasks...") # Now logger is configured
    # --- Configure Logging INSIDE lifespan --- END

    # 0. Load FAISS data and embedding model
    load_faiss_data() # Loads model, empty index or existing index. Synchronous.

    # 1. Load server definitions and persisted enabled/disabled state
    load_registered_servers_and_state() # This populates REGISTERED_SERVERS. Synchronous.

    # 1.5 Sync FAISS with loaded servers (initial build or update)
    if embedding_model and faiss_index is not None: # Check faiss_index is not None
        logger.info("Performing initial FAISS synchronization with loaded server definitions...")
        sync_tasks = []
        for path, server_info in REGISTERED_SERVERS.items():
            # add_or_update_service_in_faiss is async, can be gathered
            sync_tasks.append(add_or_update_service_in_faiss(path, server_info))
        
        if sync_tasks:
            await asyncio.gather(*sync_tasks)
        logger.info("Initial FAISS synchronization complete.")
    else:
        logger.warning("Skipping initial FAISS synchronization: embedding model or FAISS index not ready.")

    # 2. Perform initial health checks concurrently for *enabled* services
    logger.info("Performing initial health checks for enabled services...")
    initial_check_tasks = []
    enabled_paths = [path for path, is_enabled in MOCK_SERVICE_STATE.items() if is_enabled]

    global SERVER_HEALTH_STATUS, SERVER_LAST_CHECK_TIME
    # Initialize status for all servers (defaults for disabled)
    for path in REGISTERED_SERVERS.keys():
        SERVER_LAST_CHECK_TIME[path] = None # Initialize last check time
        if path not in enabled_paths:
             SERVER_HEALTH_STATUS[path] = "disabled"
        else:
             # Will be set by the check task below (or remain unset if check fails badly)
             SERVER_HEALTH_STATUS[path] = "checking" # Tentative status before check runs

    logger.info(f"Initially enabled services to check: {enabled_paths}")
    if enabled_paths:
        for path in enabled_paths:
            # Create a task for each enabled service check
            task = asyncio.create_task(perform_single_health_check(path))
            initial_check_tasks.append(task)

        # Wait for all initial checks to complete
        results = await asyncio.gather(*initial_check_tasks, return_exceptions=True)

        # Log results/errors from initial checks
        for i, result in enumerate(results):
            path = enabled_paths[i]
            if isinstance(result, Exception):
                logger.error(f"ERROR during initial health check for {path}: {result}")
                # Status might have already been set to an error state within the check function
            else:
                status, _ = result # Unpack the result tuple
                logger.info(f"Initial health check completed for {path}: Status = {status}")
                # Update FAISS with potentially changed server_info (e.g., num_tools from health check)
                if path in REGISTERED_SERVERS and embedding_model and faiss_index is not None:
                     # This runs after each health check result, can be awaited individually
                    await add_or_update_service_in_faiss(path, REGISTERED_SERVERS[path])
    else:
        logger.info("No services are initially enabled.")

    logger.info(f"Initial health status after checks: {SERVER_HEALTH_STATUS}")

    # 3. Generate Nginx config *after* initial checks are done
    logger.info("Generating initial Nginx configuration...")
    regenerate_nginx_config() # Generate config based on initial health status

    # 4. Start the background periodic health check task
    logger.info("Starting background health check task...")
    health_check_task = asyncio.create_task(run_health_checks())

    # --- Yield to let the application run --- START
    yield
    # --- Yield to let the application run --- END

    # --- Shutdown tasks --- START
    logger.info("Running shutdown tasks...")
    logger.info("Cancelling background health check task...")
    health_check_task.cancel()
    try:
        await health_check_task
    except asyncio.CancelledError:
        logger.info("Health check task cancelled successfully.")
    # --- Shutdown tasks --- END


app = FastAPI(lifespan=lifespan)


# --- Authentication / Session Dependency ---
def get_current_user(
    session: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> str:
    if session is None:
        raise HTTPException(
            status_code=307, detail="Not authenticated", headers={"Location": "/login"}
        )
    try:
        data = signer.loads(session, max_age=SESSION_MAX_AGE_SECONDS)
        username = data.get("username")
        if not username:
            raise HTTPException(
                status_code=307,
                detail="Invalid session data",
                headers={"Location": "/login"},
            )
        return username
    except (BadSignature, SignatureExpired):
        response = RedirectResponse(
            url="/login?error=Session+expired+or+invalid", status_code=307
        )
        response.delete_cookie(SESSION_COOKIE_NAME)
        raise HTTPException(
            status_code=307,
            detail="Session expired or invalid",
            headers={"Location": "/login"},
        )
    except Exception:
        raise HTTPException(
            status_code=307,
            detail="Authentication error",
            headers={"Location": "/login"},
        )


# --- API Authentication Dependency (returns 401 instead of redirecting) ---
def api_auth(
    session: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> str:
    if session is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        data = signer.loads(session, max_age=SESSION_MAX_AGE_SECONDS)
        username = data.get("username")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid session data")
        return username
    except (BadSignature, SignatureExpired):
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    except Exception:
        raise HTTPException(status_code=401, detail="Authentication error")


# --- Static Files and Templates (Paths relative to this script) ---
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# --- Routes ---


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, error: str | None = None):
    return templates.TemplateResponse(
        "login.html", {"request": request, "error": error}
    )


@app.post("/login")
async def login_submit(
    username: Annotated[str, Form()], password: Annotated[str, Form()]
):
    # cu = os.environ.get("ADMIN_USER", "admin")
    # cp = os.environ.get("ADMIN_PASSWORD", "password")
    # logger.info(f"Login attempt with username: {username}, {cu}")
    # logger.info(f"Login attempt with password: {password}, {cp}")
    correct_username = secrets.compare_digest(
        username, os.environ.get("ADMIN_USER", "admin")
    )
    correct_password = secrets.compare_digest(
        password, os.environ.get("ADMIN_PASSWORD", "password")
    )
    if correct_username and correct_password:
        session_data = signer.dumps({"username": username})
        response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=session_data,
            max_age=SESSION_MAX_AGE_SECONDS,
            httponly=True,
            samesite="lax",
        )
        logger.info(f"User '{username}' logged in successfully.")
        return response
    else:
        logger.info(f"Login failed for user '{username}'.")
        return RedirectResponse(
            url="/login?error=Invalid+username+or+password",
            status_code=status.HTTP_303_SEE_OTHER,
        )


@app.post("/logout")
async def logout():
    logger.info("User logged out.")
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


@app.get("/", response_class=HTMLResponse)
async def read_root(
    request: Request,
    username: Annotated[str, Depends(get_current_user)],
    query: str | None = None,
):
    service_data = []
    search_query = query.lower() if query else ""
    sorted_server_paths = sorted(
        REGISTERED_SERVERS.keys(), key=lambda p: REGISTERED_SERVERS[p]["server_name"]
    )
    for path in sorted_server_paths:
        server_info = REGISTERED_SERVERS[path]
        server_name = server_info["server_name"]
        # Include description and tags in search
        searchable_text = f"{server_name.lower()} {server_info.get('description', '').lower()} {' '.join(server_info.get('tags', []))}"
        if not search_query or search_query in searchable_text:
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
                    "health_status": SERVER_HEALTH_STATUS.get(path, "unknown"), # Get current health status
                    "last_checked_iso": SERVER_LAST_CHECK_TIME.get(path).isoformat() if SERVER_LAST_CHECK_TIME.get(path) else None
                }
            )
    # --- End Debug ---
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "services": service_data, "username": username},
    )


@app.post("/toggle/{service_path:path}")
async def toggle_service_route(
    request: Request,
    service_path: str,
    enabled: Annotated[str | None, Form()] = None,
    username: Annotated[str, Depends(get_current_user)] = None,
):
    if not service_path.startswith("/"):
        service_path = "/" + service_path
    if service_path not in REGISTERED_SERVERS:
        raise HTTPException(status_code=404, detail="Service path not registered")

    new_state = enabled == "on"
    MOCK_SERVICE_STATE[service_path] = new_state
    server_name = REGISTERED_SERVERS[service_path]["server_name"]
    logger.info(
        f"Simulated toggle for '{server_name}' ({service_path}) to {new_state} by user '{username}'"
    )

    # --- Update health status immediately on toggle --- START
    new_status = ""
    last_checked_iso = None
    last_checked_dt = None # Initialize datetime object

    if new_state:
        # Perform immediate check when enabling
        logger.info(f"Performing immediate health check for {service_path} upon toggle ON...")
        try:
            new_status, last_checked_dt = await perform_single_health_check(service_path)
            last_checked_iso = last_checked_dt.isoformat() if last_checked_dt else None
            logger.info(f"Immediate check for {service_path} completed. Status: {new_status}")
        except Exception as e:
            # Handle potential errors during the immediate check itself
            logger.error(f"ERROR during immediate health check for {service_path}: {e}")
            new_status = f"error: immediate check failed ({type(e).__name__})"
            # Update global state to reflect this error
            SERVER_HEALTH_STATUS[service_path] = new_status
            last_checked_dt = SERVER_LAST_CHECK_TIME.get(service_path) # Use time if check started
            last_checked_iso = last_checked_dt.isoformat() if last_checked_dt else None
    else:
        # When disabling, set status to disabled and keep last check time
        new_status = "disabled"
        # Keep the last check time from when it was enabled
        last_checked_dt = SERVER_LAST_CHECK_TIME.get(service_path)
        last_checked_iso = last_checked_dt.isoformat() if last_checked_dt else None
        # Update global state directly when disabling
        SERVER_HEALTH_STATUS[service_path] = new_status
        logger.info(f"Service {service_path} toggled OFF. Status set to disabled.")
        # --- Update FAISS metadata for disabled service --- START
        if embedding_model and faiss_index is not None:
            logger.info(f"Updating FAISS metadata for disabled service {service_path}.")
            # REGISTERED_SERVERS[service_path] contains the static definition
            await add_or_update_service_in_faiss(service_path, REGISTERED_SERVERS[service_path])
        else:
            logger.warning(f"Skipped FAISS metadata update for disabled service {service_path}: model or index not ready.")
        # --- Update FAISS metadata for disabled service --- END

    # --- Send *targeted* update via WebSocket --- START
    # Send immediate feedback for the toggled service only
    # Always get the latest num_tools from the registry
    current_num_tools = REGISTERED_SERVERS.get(service_path, {}).get("num_tools", 0)

    update_data = {
        service_path: {
            "status": new_status,
            "last_checked_iso": last_checked_iso,
            "num_tools": current_num_tools # Include num_tools
        }
    }
    message = json.dumps(update_data)
    logger.info(f"--- TOGGLE: Sending targeted update: {message}")

    # Create task to send without blocking the request
    async def send_specific_update():
        disconnected_clients = set()
        current_connections = list(active_connections)
        send_tasks = []
        for conn in current_connections:
            send_tasks.append((conn, conn.send_text(message)))

        results = await asyncio.gather(*(task for _, task in send_tasks), return_exceptions=True)

        for i, result in enumerate(results):
            conn, _ = send_tasks[i]
            if isinstance(result, Exception):
                logger.warning(f"Error sending toggle update to WebSocket client {conn.client}: {result}. Marking for removal.")
                disconnected_clients.add(conn)
        if disconnected_clients:
            logger.info(f"Removing {len(disconnected_clients)} disconnected clients after toggle update.")
            for conn in disconnected_clients:
                if conn in active_connections:
                    active_connections.remove(conn)

    asyncio.create_task(send_specific_update())
    # --- Send *targeted* update via WebSocket --- END

    # --- Persist the updated state --- START
    try:
        with open(STATE_FILE_PATH, "w") as f:
            json.dump(MOCK_SERVICE_STATE, f, indent=2)
        logger.info(f"Persisted state to {STATE_FILE_PATH}")
    except Exception as e:
        logger.error(f"ERROR: Failed to persist state to {STATE_FILE_PATH}: {e}")
        # Decide if we should raise an error or just log
    # --- Persist the updated state --- END

    # Regenerate Nginx config after toggling state
    if not regenerate_nginx_config():
        logger.error("ERROR: Failed to update Nginx configuration after toggle.")

    # --- Return JSON instead of Redirect --- START
    final_status = SERVER_HEALTH_STATUS.get(service_path, "unknown")
    final_last_checked_dt = SERVER_LAST_CHECK_TIME.get(service_path)
    final_last_checked_iso = final_last_checked_dt.isoformat() if final_last_checked_dt else None
    final_num_tools = REGISTERED_SERVERS.get(service_path, {}).get("num_tools", 0)

    return JSONResponse(
        status_code=200,
        content={
            "message": f"Toggle request for {service_path} processed.",
            "service_path": service_path,
            "new_enabled_state": new_state, # The state it was set to
            "status": final_status, # The status after potential immediate check
            "last_checked_iso": final_last_checked_iso,
            "num_tools": final_num_tools
        }
    )
    # --- Return JSON instead of Redirect --- END

    # query_param = request.query_params.get("query", "")
    # redirect_url = f"/?query={query_param}" if query_param else "/"
    # return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


async def detect_auth_requirement(base_url: str) -> tuple[bool, str]:
    """
    Test if an endpoint requires authentication by trying common endpoints.
    Returns (requires_auth, reason)
    """
    logger.info(f"Testing if {base_url} requires authentication...")
    
    # Test endpoints in order of preference
    test_endpoints = [
        "/sse",          # SSE endpoint
        "/mcp",          # MCP endpoint
        "/api"           # API endpoint
    ]
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        for endpoint in test_endpoints:
            test_url = base_url.rstrip('/') + endpoint
            try:
                logger.debug(f"Testing endpoint: {test_url}")
                response = await client.get(test_url)
                
                if response.status_code == 401:
                    logger.info(f"Authentication required - got 401 from {test_url}")
                    return True, f"401 Unauthorized from {endpoint}"
                elif response.status_code == 403:
                    logger.info(f"Authentication required - got 403 from {test_url}")
                    return True, f"403 Forbidden from {endpoint}"
                elif response.status_code == 200:
                    logger.info(f"No authentication required - got 200 from {test_url}")
                    return False, f"200 OK from {endpoint}"
                else:
                    logger.debug(f"Got {response.status_code} from {test_url}, continuing...")
                    
            except Exception as e:
                logger.debug(f"Error testing {test_url}: {e}")
                continue
    
    # If we can't determine, assume no auth required
    logger.info(f"Could not determine auth requirement for {base_url}, assuming no auth")
    return False, "Unable to determine, assuming no auth"


async def detect_oauth_capabilities(discovered_endpoints: dict) -> dict:
    """
    Analyze discovered OAuth metadata to determine supported capabilities.
    Returns dict with detected capabilities.
    """
    capabilities = {
        "grant_types": ["authorization_code"],  # Default fallback
        "scopes": ["read", "write"],           # Default fallback
        "supports_pkce": True,                 # Assume PKCE support (OAuth 2.1 standard)
        "supports_dynamic_registration": False
    }
    
    # Extract supported grant types
    if 'supported_grant_types' in discovered_endpoints:
        supported_grants = discovered_endpoints['supported_grant_types']
        if isinstance(supported_grants, list):
            capabilities["grant_types"] = supported_grants
            logger.info(f"Detected supported grant types: {supported_grants}")
        
        # Prefer client_credentials for server-to-server communication
        if "client_credentials" in capabilities["grant_types"]:
            capabilities["preferred_grant_type"] = "client_credentials"
        elif "authorization_code" in capabilities["grant_types"]:
            capabilities["preferred_grant_type"] = "authorization_code"
        else:
            capabilities["preferred_grant_type"] = capabilities["grant_types"][0]
    else:
        capabilities["preferred_grant_type"] = "authorization_code"
    
    # Extract supported scopes
    if 'supported_scopes' in discovered_endpoints:
        supported_scopes = discovered_endpoints['supported_scopes']
        if isinstance(supported_scopes, list):
            capabilities["scopes"] = supported_scopes
            logger.info(f"Detected supported scopes: {supported_scopes}")
    
    # Check for dynamic registration support
    if 'registration_endpoint' in discovered_endpoints:
        capabilities["supports_dynamic_registration"] = True
        logger.info(f"Dynamic client registration supported at: {discovered_endpoints['registration_endpoint']}")
    
    # Determine optimal scope
    available_scopes = capabilities["scopes"]
    optimal_scope_parts = []
    
    # Prefer read and write if available
    if "read" in available_scopes:
        optimal_scope_parts.append("read")
    if "write" in available_scopes:
        optimal_scope_parts.append("write")
    
    # If neither read nor write available, use all available scopes
    if not optimal_scope_parts and available_scopes:
        optimal_scope_parts = available_scopes[:2]  # Take first 2 scopes
    
    capabilities["optimal_scope"] = " ".join(optimal_scope_parts) if optimal_scope_parts else "read write"
    
    logger.info(f"Detected OAuth capabilities: {capabilities}")
    return capabilities


@app.post("/register")
async def register_service(
    name: Annotated[str, Form()],
    description: Annotated[str, Form()],
    path: Annotated[str, Form()],
    proxy_pass_url: Annotated[str, Form()],
    tags: Annotated[str, Form()] = "",
    num_tools: Annotated[int, Form()] = 0,
    num_stars: Annotated[int, Form()] = 0,
    is_python: Annotated[bool, Form()] = False,
    license_str: Annotated[str, Form(alias="license")] = "N/A",
    username: Annotated[str, Depends(api_auth)] = None,
):
    """
    Intelligent service registration endpoint that automatically:
    1. Detects if the service requires OAuth authentication
    2. Discovers OAuth endpoints if auth is required
    3. Attempts dynamic client registration or falls back to .env credentials
    4. Configures optimal OAuth settings based on server capabilities
    5. Automatically initiates OAuth authorization flow if OAuth is detected
    6. Returns authorization URL for human completion
    """
    
    logger.info(f"[AUTO-REGISTER] Starting intelligent registration for '{name}' at {proxy_pass_url}")

    # Ensure path starts with a slash
    if not path.startswith("/"):
        path = "/" + path

    # Check if path already exists
    if path in REGISTERED_SERVERS:
        raise HTTPException(
            status_code=400, 
            detail=f"Service path '{path}' is already registered"
        )

    # Process tags
    tag_list = [tag.strip() for tag in tags.split(",") if tag.strip()]

    # Create base server entry
    server_entry = {
        "server_name": name,
        "description": description,
        "path": path,
        "proxy_pass_url": proxy_pass_url,
        "tags": tag_list,
        "num_tools": num_tools,
        "num_stars": num_stars,
        "is_python": is_python,
        "license": license_str,
        "tool_list": [],
        "auth_type": "none"  # Default, will be updated if OAuth is detected
    }

    # Detailed response info
    detection_info = {
        "auth_detection_performed": True,
        "oauth_detection_performed": False,
        "dynamic_registration_attempted": False,
        "dynamic_registration_successful": False,
        "fallback_credentials_used": False,
        "oauth_config_created": False,
        "oauth_authorization_initiated": False,
        "authorization_url": None,
        "detection_details": {},
        "oauth_capabilities": {},
        "errors": []
    }

    try:
        # Step 1: Test if the service requires authentication
        logger.info(f"[AUTO-REGISTER] Step 1: Testing auth requirement for {proxy_pass_url}")
        requires_auth, auth_reason = await detect_auth_requirement(proxy_pass_url)
        detection_info["detection_details"]["auth_required"] = requires_auth
        detection_info["detection_details"]["auth_reason"] = auth_reason
        
        if not requires_auth:
            logger.info(f"[AUTO-REGISTER] No authentication required for {proxy_pass_url}. Using standard registration.")
            # Proceed with non-OAuth registration
        else:
            logger.info(f"[AUTO-REGISTER] Authentication required for {proxy_pass_url}. Attempting OAuth discovery...")
            
            # Step 2: Discover OAuth endpoints
            try:
                detection_info["oauth_detection_performed"] = True
                discovered_endpoints = await OAuthDiscovery.discover_oauth_endpoints(proxy_pass_url)
                detection_info["detection_details"]["discovered_endpoints"] = discovered_endpoints
                
                if not discovered_endpoints.get('token_url'):
                    error_msg = f"OAuth endpoints not found for {proxy_pass_url} despite auth requirement"
                    logger.warning(f"[AUTO-REGISTER] {error_msg}")
                    detection_info["errors"].append(error_msg)
                    # Fall back to non-OAuth (server might use different auth method)
                else:
                    logger.info(f"[AUTO-REGISTER] OAuth endpoints discovered: {list(discovered_endpoints.keys())}")
                    
                    # Step 3: Analyze OAuth capabilities
                    oauth_capabilities = await detect_oauth_capabilities(discovered_endpoints)
                    detection_info["oauth_capabilities"] = oauth_capabilities
                    
                    # Step 4: Attempt OAuth configuration
                    oauth_config = None
                    
                    # Try dynamic registration first if supported
                    if oauth_capabilities["supports_dynamic_registration"]:
                        logger.info(f"[AUTO-REGISTER] Attempting dynamic client registration...")
                        detection_info["dynamic_registration_attempted"] = True
                        
                        try:
                            oauth_config = await oauth_manager.discover_register_and_configure_oauth(
                                server_path=path,
                                base_url=proxy_pass_url,
                                scope=oauth_capabilities["optimal_scope"]
                            )
                            detection_info["dynamic_registration_successful"] = True
                            logger.info(f"[AUTO-REGISTER] Dynamic client registration successful for {path}")
                            
                        except Exception as e:
                            error_msg = f"Dynamic client registration failed: {e}"
                            logger.warning(f"[AUTO-REGISTER] {error_msg}")
                            detection_info["errors"].append(error_msg)
                            # Fall through to .env credentials
                    
                    # If dynamic registration failed or not supported, use .env credentials
                    if oauth_config is None:
                        logger.info(f"[AUTO-REGISTER] Using .env CLIENT_ID and CLIENT_SECRET as fallback")
                        detection_info["fallback_credentials_used"] = True
                        
                        try:
                            # Get credentials from environment
                            fallback_client_id = os.environ.get("CLIENT_ID")
                            fallback_client_secret = os.environ.get("CLIENT_SECRET")
                            
                            if not fallback_client_id:
                                raise ValueError("CLIENT_ID not found in environment variables")
                            
                            oauth_config = OAuthConfig(
                                client_id=fallback_client_id,
                                client_secret=fallback_client_secret,
                                authorization_url=discovered_endpoints.get('authorization_url', ''),
                                token_url=discovered_endpoints['token_url'],
                                scope=oauth_capabilities["optimal_scope"],
                                grant_type=oauth_capabilities["preferred_grant_type"]
                            )
                            
                            # Register with OAuth manager
                            oauth_manager.register_server_oauth(path, oauth_config)
                            logger.info(f"[AUTO-REGISTER] OAuth configured using .env credentials for {path}")
                            
                        except Exception as e:
                            error_msg = f"Failed to configure OAuth with .env credentials: {e}"
                            logger.error(f"[AUTO-REGISTER] {error_msg}")
                            detection_info["errors"].append(error_msg)
                            raise HTTPException(
                                status_code=500,
                                detail=f"OAuth setup failed: {error_msg}"
                            )
                    
                    # If we got here, OAuth configuration was successful
                    server_entry["auth_type"] = "oauth2"
                    server_entry["oauth_config"] = oauth_config.to_dict()
                    detection_info["oauth_config_created"] = True
                    
                    logger.info(f"[AUTO-REGISTER] OAuth configuration successful for {path}")
                    logger.info(f"[AUTO-REGISTER] Grant type: {oauth_config.grant_type}")
                    logger.info(f"[AUTO-REGISTER] Scope: {oauth_config.scope}")
                    logger.info(f"[AUTO-REGISTER] Token URL: {oauth_config.token_url}")
                    
                    # Step 5: Automatically initiate OAuth authorization flow
                    if oauth_config.grant_type == "authorization_code":
                        logger.info(f"[AUTO-REGISTER] Automatically initiating OAuth authorization flow for {path}")
                        try:
                            auth_url, state = await oauth_manager.get_authorization_url(path)
                            detection_info["oauth_authorization_initiated"] = True
                            detection_info["authorization_url"] = auth_url
                            
                            logger.info(f"[AUTO-REGISTER] OAuth authorization URL generated for {path}")
                            logger.info(f"[AUTO-REGISTER] Authorization URL: {auth_url}")
                            logger.info(f"[AUTO-REGISTER] State: {state}")
                            
                        except Exception as e:
                            error_msg = f"Failed to generate authorization URL: {e}"
                            logger.warning(f"[AUTO-REGISTER] {error_msg}")
                            detection_info["errors"].append(error_msg)
                            # Don't fail registration - user can manually authorize later
                    else:
                        logger.info(f"[AUTO-REGISTER] Grant type is {oauth_config.grant_type}, no user authorization needed")
                    
            except Exception as e:
                error_msg = f"OAuth discovery failed: {e}"
                logger.warning(f"[AUTO-REGISTER] {error_msg}")
                detection_info["errors"].append(error_msg)
                # Fall back to non-OAuth registration (server might not actually have OAuth)
                logger.info(f"[AUTO-REGISTER] Falling back to non-OAuth registration for {path}")

    except Exception as e:
        error_msg = f"Authentication detection failed: {e}"
        logger.error(f"[AUTO-REGISTER] {error_msg}")
        detection_info["errors"].append(error_msg)
        detection_info["auth_detection_performed"] = False
        # Continue with non-OAuth registration

    # Step 6: Save server configuration
    logger.info(f"[AUTO-REGISTER] Saving server configuration...")
    success = save_server_to_file(server_entry)
    if not success:
        raise HTTPException(
            status_code=500,
            detail="Failed to save server configuration to file"
        )

    # Step 7: Update in-memory state
    REGISTERED_SERVERS[path] = server_entry
    MOCK_SERVICE_STATE[path] = False
    SERVER_HEALTH_STATUS[path] = "disabled"
    SERVER_LAST_CHECK_TIME[path] = None

    # Step 8: Regenerate Nginx config
    if not regenerate_nginx_config():
        logger.warning("[AUTO-REGISTER] Failed to regenerate Nginx configuration")

    # Step 9: Add to FAISS Index
    if embedding_model and faiss_index is not None:
        await add_or_update_service_in_faiss(path, server_entry)
    else:
        logger.warning("[AUTO-REGISTER] FAISS index not available for new service")

    # Step 10: Persist state and broadcast
    try:
        with open(STATE_FILE_PATH, "w") as f:
            json.dump(MOCK_SERVICE_STATE, f, indent=2)
        logger.info(f"[AUTO-REGISTER] Persisted state to {STATE_FILE_PATH}")
    except Exception as e:
        logger.error(f"[AUTO-REGISTER] Failed to persist state: {e}")

    asyncio.create_task(broadcast_health_status())

    # Prepare detailed response
    response_data = {
        "message": "Service registered successfully with intelligent auto-detection",
        "service": server_entry,
        "detection_info": detection_info
    }

    # Add OAuth status if OAuth was configured
    if server_entry["auth_type"] == "oauth2":
        oauth_status = oauth_manager.get_server_oauth_status(path)
        response_data["oauth_status"] = oauth_status

    # Special handling for OAuth authorization
    if detection_info.get("oauth_authorization_initiated") and detection_info.get("authorization_url"):
        response_data["message"] = "Service registered successfully! OAuth detected - complete authorization to enable the service."
        response_data["action_required"] = {
            "type": "oauth_authorization", 
            "authorization_url": detection_info["authorization_url"],
            "instructions": f"Visit the authorization URL to complete OAuth setup for {name}. The service will be available after authorization."
        }

    logger.info(f"[AUTO-REGISTER] Registration complete for '{name}' at path '{path}' by user '{username}'")
    logger.info(f"[AUTO-REGISTER] Final auth type: {server_entry['auth_type']}")
    if detection_info["errors"]:
        logger.info(f"[AUTO-REGISTER] Errors encountered: {detection_info['errors']}")
    if detection_info.get("authorization_url"):
        logger.info(f"[AUTO-REGISTER] Authorization required: {detection_info['authorization_url']}")

    return JSONResponse(
        status_code=201,
        content=response_data
    )

@app.delete("/api/delete/{service_path:path}")
async def delete_service(
    service_path: str,
    username: Annotated[str, Depends(api_auth)]
):
    """Delete a service from the registry"""
    if not service_path.startswith('/'):
        service_path = '/' + service_path
    
    # Check if server exists
    if service_path not in REGISTERED_SERVERS:
        raise HTTPException(status_code=404, detail=f"Service path '{service_path}' not found")
    
    server_name = REGISTERED_SERVERS[service_path]["server_name"]
    
    try:
        # 1. Remove from OAuth manager if it has OAuth config
        if oauth_manager.has_oauth_config(service_path):
            oauth_manager.unregister_server(service_path)
            logger.info(f"Removed OAuth config for {service_path}")
        
        # 2. Remove from file system
        filename = path_to_filename(service_path)
        file_path = SERVERS_DIR / filename
        if file_path.exists():
            file_path.unlink()
            logger.info(f"Deleted server file: {file_path}")
        
        # 3. Remove from in-memory structures
        del REGISTERED_SERVERS[service_path]
        MOCK_SERVICE_STATE.pop(service_path, None)
        SERVER_HEALTH_STATUS.pop(service_path, None)
        SERVER_LAST_CHECK_TIME.pop(service_path, None)
        
        # 4. Remove from FAISS index
        if embedding_model and faiss_index is not None:
            if service_path in faiss_metadata_store:
                faiss_id = faiss_metadata_store[service_path]["id"]
                try:
                    # Remove from FAISS index
                    ids_to_remove = np.array([faiss_id])
                    faiss_index.remove_ids(ids_to_remove)
                    # Remove from metadata store
                    del faiss_metadata_store[service_path]
                    # Save FAISS data
                    await asyncio.to_thread(save_faiss_data)
                    logger.info(f"Removed {service_path} from FAISS index")
                except Exception as e:
                    logger.warning(f"Failed to remove {service_path} from FAISS index: {e}")
        
        # 5. Update state file
        try:
            STATE_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(STATE_FILE_PATH, "w") as f:
                json.dump(MOCK_SERVICE_STATE, f, indent=2)
            logger.info("Updated server state file after deletion")
        except Exception as e:
            logger.warning(f"Failed to update state file after deletion: {e}")
        
        # 6. Regenerate Nginx config
        if not regenerate_nginx_config():
            logger.warning("Failed to regenerate Nginx configuration after deletion")
        
        # 7. Broadcast update
        asyncio.create_task(broadcast_health_status())
        
        logger.info(f"Successfully deleted server '{server_name}' ({service_path}) by user '{username}'")
        
        return {
            "message": f"Server '{server_name}' deleted successfully",
            "deleted_service_path": service_path,
            "deleted_server_name": server_name
        }
        
    except Exception as e:
        logger.error(f"Failed to delete server {service_path}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete server: {e}")

@app.get("/api/server_details/{service_path:path}")
async def get_server_details(
    service_path: str,
    username: Annotated[str, Depends(api_auth)]
):
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


# --- Endpoint to get tool list for a service --- START
@app.get("/api/tools/{service_path:path}")
async def get_service_tools(
    service_path: str,
    username: Annotated[str, Depends(api_auth)] # Requires authentication
):
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


# --- Endpoint to get server enabled status --- START
@app.get("/api/status/{service_path:path}")
async def get_server_status(
    service_path: str,
    username: Annotated[str, Depends(api_auth)]
):
    """Get enabled status for a specific server or all servers if service_path is 'all'"""
    if not service_path.startswith('/'):
        service_path = '/' + service_path

    # Handle special case for '/all' to return status for all servers
    if service_path == '/all':
        status_info = {}
        for path in REGISTERED_SERVERS.keys():
            is_enabled = MOCK_SERVICE_STATE.get(path, False)
            status_info[path] = "on" if is_enabled else "off"
        
        return {"servers": status_info}

    # Handle specific server case
    if service_path not in REGISTERED_SERVERS:
        raise HTTPException(status_code=404, detail="Service path not registered")
    
    is_enabled = MOCK_SERVICE_STATE.get(service_path, False)
    return {
        "service_path": service_path,
        "status": "on" if is_enabled else "off"
    }
# --- Endpoint to get server enabled status --- END


# --- Refresh Endpoint --- START
@app.post("/api/refresh/{service_path:path}")
async def refresh_service(service_path: str, username: Annotated[str, Depends(api_auth)]):
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
        {"request": request, "server": server_info, "username": username}
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
# Use: uvicorn registry.main:app --reload --host 0.0.0.0 --port 7860 --root-path /home/ubuntu/mcp-gateway
# (Running from parent dir)

# If running directly (python registry/main.py):
# if __name__ == "__main__":
#     import uvicorn
#     # Running this way makes relative paths tricky, better to use uvicorn command from parent
#     uvicorn.run(app, host="0.0.0.0", port=7860)

# OAuth callback endpoint
@app.get("/oauth/callback/")
async def oauth_callback(
    code: str = None,
    state: str = None,
    error: str = None
):
    """Handle OAuth authorization callback"""
    if error:
        logger.error(f"OAuth authorization error: {error}")
        return HTMLResponse(
            content=f"<h1>OAuth Error</h1><p>Authorization failed: {error}</p>",
            status_code=400
        )
    
    if not code or not state:
        logger.error("Missing code or state in OAuth callback")
        return HTMLResponse(
            content="<h1>OAuth Error</h1><p>Missing authorization code or state</p>",
            status_code=400
        )
    
    try:
        server_path = await oauth_manager.exchange_code_for_token(code, state)
        logger.info(f"OAuth authorization successful for {server_path}")
        return HTMLResponse(
            content=f"<h1>OAuth Success</h1><p>Successfully authorized server: {server_path}</p><script>window.close();</script>"
        )
    except Exception as e:
        logger.error(f"OAuth token exchange failed: {e}")
        return HTMLResponse(
            content=f"<h1>OAuth Error</h1><p>Token exchange failed: {e}</p>",
            status_code=400
        )

# OAuth status endpoint
@app.get("/api/oauth/status/{service_path:path}")
async def get_oauth_status(
    service_path: str,
    username: Annotated[str, Depends(api_auth)]
):
    """Get OAuth status for a service"""
    if not service_path.startswith('/'):
        service_path = '/' + service_path
    
    return oauth_manager.get_server_oauth_status(service_path)

# OAuth authorization endpoint
@app.post("/api/oauth/authorize/{service_path:path}")
async def initiate_oauth_authorization(
    service_path: str,
    username: Annotated[str, Depends(api_auth)]
):
    """Initiate OAuth authorization for a service"""
    if not service_path.startswith('/'):
        service_path = '/' + service_path
    
    if not oauth_manager.has_oauth_config(service_path):
        raise HTTPException(status_code=404, detail="Service does not have OAuth configuration")
    
    try:
        auth_url, state = await oauth_manager.get_authorization_url(service_path)
        return {
            "authorization_url": auth_url,
            "state": state,
            "message": "Open the authorization URL to complete OAuth flow"
        }
    except Exception as e:
        logger.error(f"Failed to generate authorization URL for {service_path}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to initiate OAuth: {e}")

# OAuth token refresh endpoint
@app.post("/api/oauth/refresh/{service_path:path}")
async def refresh_oauth_token(
    service_path: str,
    username: Annotated[str, Depends(api_auth)]
):
    """Refresh OAuth token for a service"""
    if not service_path.startswith('/'):
        service_path = '/' + service_path
    
    if not oauth_manager.has_oauth_config(service_path):
        raise HTTPException(status_code=404, detail="Service does not have OAuth configuration")
    
    try:
        # For client_credentials flow, always get a new token
        # For authorization_code flow, try to refresh existing token
        config = oauth_manager._configs[service_path]
        
        if config.grant_type == "client_credentials":
            # Get a new token using client credentials
            token_info = await oauth_manager.get_client_credentials_token(service_path)
            return {
                "message": "Token obtained successfully",
                "expires_at": token_info.expires_at.isoformat() if token_info.expires_at else None
            }
        else:
            # Try to refresh existing token for authorization_code flow
            token_info = await oauth_manager.refresh_token(service_path)
            return {
                "message": "Token refreshed successfully", 
                "expires_at": token_info.expires_at.isoformat() if token_info.expires_at else None
            }
    except Exception as e:
        logger.error(f"Failed to refresh/get token for {service_path}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get token: {e}")