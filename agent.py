#!/usr/bin/env python3
"""
MCP Gateway Agent with Dynamic Tool Discovery and Execution

This script implements a multi-stage agent process:
1.  Connects to an MCP gateway server which provides an 'intelligent_tool_finder' tool.
2.  An initial agent uses this tool finder to determine the correct tool, endpoint, 
    and schema required to fulfill the user's request.
3.  Parses the tool finder's response to extract the necessary information.
4.  Dynamically creates a second agent configured with the specific tool and endpoint.
5.  The second agent executes the user's original request using the discovered tool.

Usage:
    python agent.py --gateway-host hostname --gateway-port port --model model_id --message "your question"

Example:
    python agent.py --gateway-host mcp-gateway.example.com --gateway-port 8000 \\
        --model anthropic.claude-3-5-haiku-20241022-v1:0 --message "What's my S3 bucket usage?"
"""

import asyncio
import argparse
from typing import Dict, List, Any, Optional, Tuple
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from langchain_aws import ChatBedrock
from langchain_core.tools import BaseTool
import json
import re

def parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments for the MCP Gateway Agent.
    
    Returns:
        argparse.Namespace: The parsed command line arguments
    """
    parser = argparse.ArgumentParser(description='MCP Gateway Agent for Dynamic Tool Discovery')
    
    # Gateway server connection arguments
    parser.add_argument('--gateway-host', type=str, default='localhost', # Changed default
                        help='Hostname of the MCP gateway server')
    parser.add_argument('--gateway-port', type=int, default=8000,
                        help='Port of the MCP gateway server')
    parser.add_argument('--gateway-name', type=str, default='mcp_gateway',
                        help='Server name identifier for the gateway server')
    parser.add_argument('--tool-finder-name', type=str, default='find_intelligent_tool', # Use the correct tool name
                        help='Name of the tool finder tool on the gateway server')
    
    # Tool Finder specific arguments
    parser.add_argument('--tool-username', type=str, default="",
                         help='Username for tool finder authentication (if required by tool)')
    parser.add_argument('--tool-password', type=str, default="",
                         help='Password for tool finder authentication (if required by tool)')
    parser.add_argument('--top-k-services', type=int, default=3,
                         help='Tool finder: Number of top services to consider')
    parser.add_argument('--top-n-tools', type=int, default=1,
                         help='Tool finder: Number of best matching tools to return')

    # Model arguments
    parser.add_argument('--model', type=str, default='us.amazon.nova-pro-v1:0', # Use the specified model
                        help='Model ID to use with Bedrock')
    
    # Message arguments
    parser.add_argument('--message', type=str, required=True,
                        help='Message to send to the agent')
    
    # AWS account ID (optional) - Retained if tools might need it implicitly
    parser.add_argument('--aws-account-id', type=str, default="",
                        help='AWS account id potentially used by discovered tools')

    return parser.parse_args()

def extract_tool_info_from_response(response_content: str) -> Optional[Dict[str, Any]]:
    """
    Extracts the JSON blob containing tool info from the agent's response.
    Handles potential markdown code blocks.
    
    Args:
        response_content: The string content from the agent's final message.
        
    Returns:
        A dictionary with tool info (endpoint, name, schema) or None if not found.
    """
    print(f"Attempting to extract tool info from: {response_content}")
    # Regex to find JSON within optional markdown code blocks (```json ... ``` or ``` ... ```)
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```|(\{.*?\})", response_content, re.DOTALL | re.IGNORECASE)
    
    if match:
        json_str = match.group(1) or match.group(2)
        try:
            tool_info = json.loads(json_str)
            if all(k in tool_info for k in ("endpoint", "name", "schema")):
                 print(f"Successfully extracted tool info: {tool_info}")
                 return tool_info
            else:
                 print("Extracted JSON is missing required keys (endpoint, name, schema).")
        except json.JSONDecodeError as e:
            print(f"Failed to decode JSON: {e}")
            print(f"JSON string was: {json_str}")
    else:
        print("No JSON blob found in the response content.")
        
    return None


async def run_gateway_agent(
    gateway_client: MultiServerMCPClient, 
    gateway_name: str, 
    tool_finder_name: str, 
    model, 
    user_query: str,
    tool_username: str,
    tool_password: str,
    top_k_services: int,
    top_n_tools: int
) -> Optional[Dict[str, Any]]:
    """
    Runs the initial agent connected to the gateway to find the required tool.

    Args:
        gateway_client: Connected MCP client for the gateway server.
        gateway_name: Name identifier for the gateway server.
        tool_finder_name: The exact name of the tool discovery tool.
        model: The LLM model instance.
        user_query: The user's original request (used as natural_language_query).
        tool_username: Username for the tool finder tool.
        tool_password: Password for the tool finder tool.
        top_k_services: Parameter for the tool finder.
        top_n_tools: Parameter for the tool finder.


    Returns:
        A dictionary containing the discovered tool's info (endpoint, name, schema) 
        extracted from the agent's response, or None if failure.
    """
    print(f"Running gateway agent to find tool for query: {user_query}")
    
    # Get available tools from the gateway
    gateway_tools = gateway_client.get_tools()
    print(f"Tools available on gateway '{gateway_name}': {[tool.name for tool in gateway_tools]}")

    # Filter for the specific tool finder tool
    tool_finder = next((tool for tool in gateway_tools if tool.name == tool_finder_name), None)

    if not tool_finder:
        print(f"Error: Tool finder tool '{tool_finder_name}' not found on gateway server '{gateway_name}'.")
        return None
        
    print(f"Found tool finder: {tool_finder.name}")
    
    # Create the initial agent with all tools available on the gateway
    gateway_agent = create_react_agent(
        model, 
        gateway_tools # Pass all tools available on the gateway
    )

    # Define the system prompt for the gateway agent - WILL BE UPDATED SEPARATELY
    system_prompt = f"""You are a specialized assistant that identifies the correct tool to answer a user's query.
You have access to several tools, including a crucial one named: '{tool_finder_name}'. This tool takes 'natural_language_query', 'username', 'password', 'top_k_services', and 'top_n_tools' as input.
It returns a *list* of potential tools, each with details like endpoint, name, schema, and similarity score.

Your primary goal for this interaction is to:
1. Invoke the '{tool_finder_name}' tool using the user's original query as the 'natural_language_query'. 
   Use the provided username={tool_username} and password={tool_password}. Use top_k={top_k_services} and top_n={top_n_tools}.
2. Analyze the list returned by the tool.
3. Extract the details ('endpoint', 'name', 'schema') for the *single best matching tool* from the list (usually the first item if top_n is 1).
4. Your final response MUST ONLY be a single JSON blob containing precisely these three extracted fields: 'endpoint', 'name', and 'schema'. 
   Do not include any other information from the tool's output (like similarity scores) or any conversational text. Ensure the output is a valid JSON object.

Example required output format:
```json
{{
  "endpoint": "http://some-service:8001/sse",
  "name": "specific_tool_name",
  "schema": {{ "type": "object", "properties": {{ ... }} }}
}}
```"""

    formatted_messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_query} # The user query itself
    ]

    print("\nInvoking gateway agent to find tool...\n" + "-"*40)
    
    # Prepare arguments for the tool finder invocation
    tool_finder_args = {
        "natural_language_query": user_query,
        "username": tool_username,
        "password": tool_password,
        "top_k_services": top_k_services,
        "top_n_tools": top_n_tools
    }

    # Although the agent should ideally call the tool based on the prompt, 
    # LangGraph's create_react_agent expects the main input in 'messages'.
    # The agent internally decides which tool to call and with what arguments based on the prompt and message history.
    # We don't explicitly call tool_finder.invoke here. The agent does it.

    # Invoke the gateway agent
    config = {"recursion_limit": 10} # Limit the number of steps the agent can take
    gateway_response = await gateway_agent.ainvoke({"messages": formatted_messages}, config=config)

    print("\nGateway agent response:" + "\n" + "-"*40)
    
    # Process and extract tool info from the response
    if gateway_response and "messages" in gateway_response and gateway_response["messages"]:
        last_message = gateway_response["messages"][-1]
        response_content = ""
        if isinstance(last_message, dict) and "content" in last_message:
            response_content = last_message["content"]
        elif hasattr(last_message, 'content'):
             response_content = str(last_message.content)
        
        print(f"Gateway agent raw response content: {response_content}")
        tool_info = extract_tool_info_from_response(response_content)
        
        if tool_info:
            return tool_info
        else:
            print("Error: Could not extract valid tool information from the gateway agent's response.")
            print("Gateway agent final message was:", response_content)
            return None
    else:
        print("Error: No valid response received from the gateway agent.")
        return None


async def create_and_run_dynamic_agent(
    tool_info: Dict[str, Any], 
    model, 
    user_query: str,
    gateway_host: str, # Add gateway host
    gateway_port: int   # Add gateway port
):
    """
    Creates and runs a dynamic agent using the discovered tool information.
    
    Args:
        tool_info: Information about the tool (endpoint, name, schema).
        model: The LLM model to use.
        user_query: The user's original query to process.
        gateway_host: The hostname of the original gateway server.
        gateway_port: The port of the original gateway server.
        
    Returns:
        The final response from the dynamic agent.
    """
    endpoint = tool_info.get("endpoint")
    tool_name = tool_info.get("name")

    if not endpoint or not tool_name:
         print("Error: Tool info is missing 'endpoint' or 'name'. Cannot create dynamic agent.")
         return {"messages": [{"role": "assistant", "content": "Error: Failed to get complete tool details."}]}

    print(f"\nCreating dynamic agent for endpoint: {endpoint} with tool: {tool_name}\n" + "-"*40)
    
    # Construct the target URL
    target_url = ""
    if endpoint.startswith("/"): # Relative path
        print(f"Endpoint '{endpoint}' is relative. Constructing URL from gateway info.")
        protocol = "https" if gateway_port == 443 else "http"
        # Ensure no double slashes if endpoint already starts with /
        base_url = f"{protocol}://{gateway_host}:{gateway_port}"
        # Combine base and relative path, then add /sse
        full_path = endpoint # Already starts with /
        target_url = f"{base_url}{full_path}/sse"
        print(f"Constructed relative URL: {target_url}")
    elif endpoint.startswith(("http://", "https://")): # Absolute URL
        print(f"Endpoint '{endpoint}' is absolute. Parsing directly.")
        # Basic URL parsing (can be enhanced)
        protocol = "https" if endpoint.startswith("https://") else "http"
        # Very simple split, assumes host:port/path format is unlikely in base URL for SSE
        # Let's refine this to just use the provided endpoint and assume it includes the path correctly
        # We just need to ensure it ends appropriately, assuming /sse is the convention
        if "/sse" not in endpoint.lower():
             # Attempt to find where the path starts after host:port
             proto_stripped = endpoint.replace(f"{protocol}://", "")
             path_start_index = proto_stripped.find("/")
             if path_start_index != -1:
                 base_part = endpoint[:len(protocol) + 3 + path_start_index]
                 path_part = proto_stripped[path_start_index:]
                 target_url = f"{base_part}{path_part}/sse" # Append /sse if missing
             else: # No path found, just host or host:port
                 target_url = f"{endpoint}/sse"
             print(f"Appended /sse to absolute URL: {target_url}")
        else:
             target_url = endpoint # Assume endpoint is already correct with /sse
        print(f"Using absolute URL: {target_url}")
    else:
        print(f"Warning: Endpoint '{endpoint}' format is unrecognized. Assuming it is a host and using default port 80/443.")
        # Fallback for unrecognized format (treat as host?)
        protocol = "https" if gateway_port == 443 else "http" # Guess protocol based on gateway port
        host = endpoint
        port = gateway_port
        target_url = f"{protocol}://{host}:{port}/sse" # Append /sse


    target_server_name = f"dynamic_{tool_name.replace('-', '_').replace(' ','_')}" # Create a unique name, handle spaces
    server_config = {
        target_server_name: {
            "url": target_url, # Use the constructed URL
            "transport": "sse", 
        }
    }
    
    try:
        async with MultiServerMCPClient(server_config) as dynamic_client:
            print(f"Attempting to connect dynamic client to: {target_url}")
            # Get available tools from the target endpoint
            dynamic_tools = dynamic_client.get_tools()
            print(f"Available tools at endpoint '{endpoint}': {[tool.name for tool in dynamic_tools]}")

            # Verify the expected tool is present
            target_tool = next((tool for tool in dynamic_tools if tool.name == tool_name), None)
            if not target_tool:
                 print(f"Error: Expected tool '{tool_name}' not found at endpoint '{endpoint}'. Found: {[t.name for t in dynamic_tools]}")
                 return {"messages": [{"role": "assistant", "content": f"Error: Tool '{tool_name}' not found at the specified endpoint."}]}

            print(f"Found target tool: {target_tool.name}")

            # Create the dynamic agent with the specific tool found at the endpoint
            dynamic_agent = create_react_agent(
                model,
                [target_tool] # Provide only the specific tool needed
            )
            
            # Use a simple system prompt for the execution agent
            system_prompt = "You are a helpful assistant. Use the available tool to answer the user's query."
            
            formatted_messages = [
                {"role": "system", "content": system_prompt},
                # Use the ORIGINAL user query for the dynamic agent
                {"role": "user", "content": user_query} 
            ]
            
            print("\nInvoking dynamic agent...\n" + "-"*40)
            
            # Invoke the dynamic agent
            response = await dynamic_agent.ainvoke({"messages": formatted_messages})
            
            return response

    except Exception as e:
        print(f"Error connecting to or using dynamic endpoint {endpoint}: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return {"messages": [{"role": "assistant", "content": f"Error processing request with tool {tool_name}: {str(e)}"}]}


async def main():
    """
    Main function orchestrating the two-agent workflow.
    """
    args = parse_arguments()
    
    secure = 's' if args.gateway_port == 443 else ''
    gateway_url = f"http{secure}://{args.gateway_host}:{args.gateway_port}/mcpgw/sse"
    print(f"Connecting to MCP gateway server: {gateway_url}")
    print(f"Using model: {args.model}")
    print(f"Tool finder name: {args.tool_finder_name}")
    print(f"User message: {args.message}")
    
    model = ChatBedrock(model_id=args.model, region_name='us-east-1') # Assuming us-east-1, adjust if needed
    
    final_response = None
    
    try:
        # PHASE 1: Connect to gateway and run the initial agent to find the tool
        async with MultiServerMCPClient(
            {
                args.gateway_name: {
                    "url": gateway_url,
                    "transport": "sse",
                }
            }
        ) as gateway_client:
            print(f"Connected to MCP gateway server '{args.gateway_name}' successfully.")
            
            tool_info = await run_gateway_agent(
                gateway_client, 
                args.gateway_name, 
                args.tool_finder_name, 
                model, 
                args.message,
                args.tool_username,      # Pass new args
                args.tool_password,      # Pass new args
                args.top_k_services,     # Pass new args
                args.top_n_tools         # Pass new args
            )
            
            # PHASE 2: If tool info found, create and run the dynamic agent
            if tool_info:
                final_response = await create_and_run_dynamic_agent(
                    tool_info, 
                    model, 
                    args.message, # Pass the original user message
                    args.gateway_host, # Pass gateway host
                    args.gateway_port  # Pass gateway port
                )
            else:
                print("Could not find tool information. Cannot proceed to dynamic agent.")
                final_response = {"messages": [{"role": "assistant", "content": "Sorry, I could not find the appropriate tool to handle your request."}]}

    except Exception as e:
        print(f"Error during gateway connection or initial agent execution: {str(e)}")
        import traceback
        print(traceback.format_exc())
        final_response = {"messages": [{"role": "assistant", "content": f"An error occurred: {str(e)}"}]}

    # Display the final response from the dynamic agent (or error message)
    print("\nFinal Response:" + "\n" + "-"*40)
    if final_response and "messages" in final_response and final_response["messages"]:
        last_message = final_response["messages"][-1]
        if isinstance(last_message, dict) and "content" in last_message:
            print(last_message["content"])
        elif hasattr(last_message, 'content'):
             print(str(last_message.content))
        else:
             print("Received an unexpected response structure:", last_message)
    else:
        print("No valid final response received.")


if __name__ == "__main__":
    asyncio.run(main())