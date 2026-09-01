#!/usr/bin/env python3
"""
MCP Router – Unified interface for multiple MCP servers (stdio and HTTP/SSE).
Handles discovery, tool mapping, execution, and per‑server control.
"""

import os
import sys
import json
import uuid
import time
import queue
import threading
import subprocess
import requests
import logging
from typing import Dict, List, Optional, Any
from collections import defaultdict
from flask_login import current_user 

logger = logging.getLogger(__name__)

# =============================================================================
# Stdio MCP Session (reused from app.py, with small improvements)
# =============================================================================

class StdioMCPSession:
    """Manages a subprocess MCP server over stdio."""
    def __init__(self, command, env=None, cwd=None):
        self.command = command
        self.env = env or {}
        self.cwd = cwd
        self.proc = None
        self.lock = threading.Lock()
        self.response_queues = {}
        self.reader_thread = None
        self.running = False
        self.tools_cache = None

    def start(self):
        if self.proc and self.proc.poll() is None:
            return True
        full_env = os.environ.copy()
        full_env.update(self.env)
        try:
            self.proc = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=full_env,
                cwd=self.cwd,
                bufsize=1
            )
            def log_stderr():
                for line in iter(self.proc.stderr.readline, ''):
                    if line:
                        logger.error(f"STDIO stderr: {line.strip()}")
            threading.Thread(target=log_stderr, daemon=True).start()
            self.running = True
            self.response_queues = {}
            self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
            self.reader_thread.start()
            logger.info(f"Started stdio MCP process: {' '.join(self.command)}")
            return self._initialize()
        except Exception as e:
            logger.error(f"Failed to start stdio MCP: {e}")
            return False

    def _initialize(self):
        # Send initialize
        init_req = {
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "mcp-router", "version": "1.0"},
                "capabilities": {}
            }
        }
        resp = self.send_request("init-1", "initialize", init_req["params"])
        if resp is None:
            logger.error("Initialize request failed")
            return False
        # Send initialized notification (no response expected)
        notif = {
            "jsonrpc": "2.0",
            "method": "initialized",
            "params": {}
        }
        self.proc.stdin.write(json.dumps(notif) + "\n")
        self.proc.stdin.flush()
        logger.info("MCP initialization complete")
        return True

    def _reader_loop(self):
        while self.running and self.proc and self.proc.poll() is None:
            line = self.proc.stdout.readline()
            if not line:
                break
            logger.debug(f"Stdio stdout: {line.strip()}")
            try:
                response = json.loads(line.strip())
                req_id = response.get('id')
                if req_id is not None and req_id in self.response_queues:
                    self.response_queues[req_id].put(response)
            except json.JSONDecodeError:
                logger.warning(f"Non-JSON line from stdio: {line.strip()}")

    def send_request(self, request_id, method, params, timeout=600):
        """Send a JSON-RPC request and return the response (blocking)."""
        with self.lock:
            if not self.proc or self.proc.poll() is not None:
                if not self.start():
                    return None
            payload = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params
            }
            logger.debug(f"Sending stdio request: {payload}")
            self.proc.stdin.write(json.dumps(payload) + "\n")
            self.proc.stdin.flush()
            q = queue.Queue()
            self.response_queues[request_id] = q
        try:
            response = q.get(timeout=timeout)
            logger.debug(f"STDIO response for {method}: {response}")
            return response
        except queue.Empty:
            logger.error(f"Timeout waiting for response to {method}")
            return None
        finally:
            with self.lock:
                self.response_queues.pop(request_id, None)
        return response

    def stop(self):
        self.running = False
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=5)
            self.proc = None
        if self.reader_thread and self.reader_thread.is_alive():
            self.reader_thread.join(timeout=1)

    def is_alive(self):
        return self.proc is not None and self.proc.poll() is None

class ToolRateLimiter:
    def __init__(self):
        self.records = defaultdict(list)

    def is_allowed(self, user, tool, max_calls, period_seconds):
        key = (user, tool)
        now = time.time()
        self.records[key] = [ts for ts in self.records[key] if ts > now - period_seconds]
        if len(self.records[key]) >= max_calls:
            return False
        self.records[key].append(now)
        return True

# Global instance
tool_rate_limiter = ToolRateLimiter()

# =============================================================================
# HTTP/SSE MCP Session (simplified but functional)
# =============================================================================

class HttpMCPSession:
    """Manages an MCP server over HTTP/SSE."""
    def __init__(self, url):
        self.url = url
        self.session_id = None
        self.sse_thread = None
        self.stop_event = threading.Event()
        self.response_queues = {}
        self.lock = threading.Lock()
        self.tools_cache = None
        self._connected = False

    def start(self):
        if self._connected:
            return True
        # Connect to SSE and get session_id
        q = queue.Queue()
        session_id = None
        stop_event = self.stop_event

        def sse_worker():
            nonlocal session_id
            while not stop_event.is_set():
                try:
                    response = requests.get(f"{self.url}/sse", stream=True, timeout=3000)
                    if response.status_code != 200:
                        logger.error(f"SSE endpoint returned {response.status_code} for {self.url}")
                        time.sleep(5)
                        continue
                    logger.info(f"SSE connection established for {self.url}")
                    for line in response.iter_lines(decode_unicode=True):
                        if stop_event.is_set():
                            break
                        if not line:
                            continue
                        if line.startswith('data: '):
                            data_content = line[6:].strip()
                            # Capture session ID
                            if '?session_id=' in data_content and not session_id:
                                parts = data_content.split('?session_id=')
                                if len(parts) > 1:
                                    session_id = parts[1].split(' ')[0].split('&')[0]
                                    logger.info(f"Captured session_id: {session_id}")
                                    q.put(session_id)
                            # Parse JSON-RPC responses
                            try:
                                msg = json.loads(data_content)
                                if 'id' in msg:
                                    req_id = msg['id']
                                    with self.lock:
                                        if req_id in self.response_queues:
                                            self.response_queues[req_id].put(msg)
                            except json.JSONDecodeError:
                                pass
                except Exception as e:
                    logger.error(f"SSE worker error: {e}")
                    time.sleep(5)

        thread = threading.Thread(target=sse_worker, daemon=True)
        thread.start()
        self.sse_thread = thread
        try:
            session_id = q.get(timeout=30)
        except queue.Empty:
            self.stop_event.set()
            thread.join(timeout=2)
            return False
        self.session_id = session_id
        self._connected = True
        # Send initialize
        init_req_id = str(uuid.uuid4())
        init_response = self.send_request(init_req_id, "initialize", {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "mcp-router", "version": "1.0"},
            "capabilities": {}
        })
        if init_response is None or 'error' in init_response:
            self._connected = False
            return False
        # Send initialized notification
        notif_payload = {"jsonrpc": "2.0", "method": "initialized", "params": {}}
        requests.post(f"{self.url}/messages/?session_id={session_id}", json=notif_payload, timeout=5)
        logger.info(f"HTTP MCP initialization completed for {self.url}")
        return True

    def send_request(self, request_id, method, params, timeout=60):
        if not self._connected:
            if not self.start():
                return None
        with self.lock:
            q = queue.Queue()
            self.response_queues[request_id] = q
        try:
            payload = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params
            }
            url = f"{self.url}/messages/?session_id={self.session_id}"
            resp = requests.post(url, json=payload, timeout=30)
            if resp.status_code not in (200, 202):
                logger.error(f"HTTP request failed: {resp.status_code} {resp.text}")
                return None
            response = q.get(timeout=timeout)
            return response
        except queue.Empty:
            logger.error(f"Timeout waiting for response to {method}")
            return None
        finally:
            with self.lock:
                self.response_queues.pop(request_id, None)

    def stop(self):
        self.stop_event.set()
        if self.sse_thread:
            self.sse_thread.join(timeout=2)
        self._connected = False

    def is_alive(self):
        return self._connected and self.sse_thread and self.sse_thread.is_alive()


# =============================================================================
# Adapter Base and Implementations
# =============================================================================

class BaseAdapter:
    def connect(self) -> bool:
        raise NotImplementedError

    def disconnect(self):
        raise NotImplementedError

    def discover_tools(self) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def call_tool(self, tool_name: str, arguments: Dict) -> Any:
        raise NotImplementedError

    def is_alive(self) -> bool:
        raise NotImplementedError


class StdioAdapter(BaseAdapter):
    def __init__(self, command, env=None, cwd=None, discovery_timeout=6000, discovery_retries=1):
        self.session = StdioMCPSession(command, env, cwd)
        self.tools = None
        self.discovery_timeout = discovery_timeout
        self.discovery_retries = discovery_retries

    def connect(self) -> bool:
        return self.session.start()

    def disconnect(self):
        self.session.stop()

    def discover_tools(self) -> List[Dict[str, Any]]:
        if self.tools is not None:
            return self.tools
        for attempt in range(self.discovery_retries):
            logger.info(f"Discovering tools from {self.session.command} (attempt {attempt+1}/{self.discovery_retries})")
            req_id = str(uuid.uuid4())
            response = self.session.send_request(req_id, "tools/list", {}, timeout=self.discovery_timeout)
            if response and 'result' in response:
                tools = response['result'].get('tools', [])
                self.tools = [] 
                for tool in tools:
                    self.tools.append({
                        "name": tool.get('name'),
                        "inputSchema": tool.get('inputSchema', {})
                    })
                logger.info(f"Discovered {len(self.tools)} tools from {self.session.command}")
                return self.tools
            else:
                logger.warning(f"tools/list attempt {attempt+1} failed for {self.session.command}")
        self.tools = []
        logger.error(f"Failed to discover tools from {self.session.command} after {self.discovery_retries} attempts")
        return []

    def call_tool(self, tool_name, arguments):
        req_id = str(uuid.uuid4())
        response = self.session.send_request(req_id, "tools/call", {"name": tool_name, "arguments": arguments}, timeout=120)
        return response

    def is_alive(self) -> bool:
        return self.session.is_alive()


class HttpAdapter(BaseAdapter):
    def __init__(self, url, discovery_timeout=600, discovery_retries=1):
        self.session = HttpMCPSession(url)
        self.tools = None
        self.discovery_timeout = discovery_timeout
        self.discovery_retries = discovery_retries

    def connect(self) -> bool:
        return self.session.start()

    def disconnect(self):
        self.session.stop()

    def discover_tools(self) -> List[Dict[str, Any]]:
        if self.tools is not None:
            return self.tools
        for attempt in range(self.discovery_retries):
            logger.info(f"Discovering tools from {self.session.url} (attempt {attempt+1}/{self.discovery_retries})")
            req_id = str(uuid.uuid4())
            response = self.session.send_request(req_id, "tools/list", {}, timeout=self.discovery_timeout)
            if response and 'result' in response:
                tools = response['result'].get('tools', [])
                self.tools = []
                for tool in tools:
                    self.tools.append({
                        "name": tool.get('name'),
                        "inputSchema": tool.get('inputSchema', {})
                    })
                logger.info(f"Discovered {len(self.tools)} tools from {self.session.url}")
                return self.tools
            else:
                logger.warning(f"tools/list attempt {attempt+1} failed for {self.session.url}")
        self.tools = []
        logger.error(f"Failed to discover tools from {self.session.url} after {self.discovery_retries} attempts")
        return []

    def call_tool(self, tool_name, arguments):
        req_id = str(uuid.uuid4())
        response = self.session.send_request(req_id, "tools/call", {"name": tool_name, "arguments": arguments}, timeout=12000)
        return response

    def is_alive(self) -> bool:
        return self.session.is_alive()


# =============================================================================
# MCP Router
# =============================================================================

class MCPRouter:
    def __init__(self, config_path="mcp_servers.json"):
        self.config_path = config_path
        self._config = {}          # will store the loaded config
        self.adapters = {}          # server_name -> adapter instance
        self.tool_map = {}          # tool_name -> server_name
        self.tool_schemas = {}      # tool_name -> inputSchema   <-- ADD THIS LINE
        self.lock = threading.RLock()
        self._load_and_connect()

    def _load_and_connect(self):
        with open(self.config_path) as f:
            config = json.load(f)
        self._config = config
        # Disconnect existing adapters if any
        for name, adapter in self.adapters.items():
            try:
                adapter.disconnect()
            except Exception:
                pass
        self.adapters.clear()
        self.tool_map.clear()
        self.tool_schemas.clear()   # <-- ADD THIS LINE
        for name, cfg in config.items():
            adapter = self._create_adapter(name, cfg)
            if adapter and adapter.connect():
                self.adapters[name] = adapter
                logger.info(f"Connected to MCP server: {name}")
            else:
                logger.warning(f"Failed to connect to MCP server: {name}")
        self._discover_all()

    def _create_adapter(self, name: str, cfg: dict):
        if cfg.get('type') == 'stdio':
            command = cfg.get('command')
            if not command:
                return None
            discovery_timeout = cfg.get('discovery_timeout', 60)
            discovery_retries = cfg.get('discovery_retries', 1)
            return StdioAdapter(command, cfg.get('env'), cfg.get('cwd'), discovery_timeout, discovery_retries)
        elif cfg.get('type') == 'http':
            url = cfg.get('url')
            if not url:
                return None
            discovery_timeout = cfg.get('discovery_timeout', 60)
            discovery_retries = cfg.get('discovery_retries', 1)
            return HttpAdapter(url, discovery_timeout, discovery_retries)
        return None

    def _discover_all(self):
        self.tool_map.clear()
        self.tool_schemas.clear()   # <-- ADD THIS LINE
        for name, adapter in self.adapters.items():
            try:
                tool_list = adapter.discover_tools()
                if tool_list:
                    for tool in tool_list:
                        tool_name = tool.get('name')
                        if tool_name:
                            self.tool_map[tool_name] = name
                            self.tool_schemas[tool_name] = tool.get('inputSchema', {})
                    logger.info(f"Discovered tools from {name}: {[t['name'] for t in tool_list]}")
                else:
                    logger.warning(f"No tools discovered from {name}")
            except Exception as e:
                logger.error(f"Error discovering tools from {name}: {e}")

    def list_tools(self) -> List[Dict[str, Any]]:
        with self.lock:
            return [
                {"name": tool, "server": server, "inputSchema": self.tool_schemas.get(tool, {})}
                for tool, server in self.tool_map.items()
            ]

    def call_tool(self, tool_name: str, arguments: Dict) -> Dict:
        with self.lock:
            server = self.tool_map.get(tool_name)
            if not server:
                return {"error": f"Tool '{tool_name}' not found in any server"}
            adapter = self.adapters.get(server)
            if not adapter or not adapter.is_alive():
                return {"error": f"Server '{server}' is not connected"}
        try:
            response = adapter.call_tool(tool_name, arguments)
            if response and 'result' in response:
                return response['result']
            else:
                error = response.get('error', {}).get('message', 'Unknown error') if response else 'No response'
                return {"error": error}
        except Exception as e:
            return {"error": str(e)}

    def reload(self):
        """Reload the configuration and reconnect to all servers."""
        self._load_and_connect()

    # ---- Per‑server control ----
    def start_server(self, name: str) -> bool:
        """Start (or restart) a specific server by name."""
        with self.lock:
            # If already connected and alive, return True
            if name in self.adapters and self.adapters[name].is_alive():
                return True
            # Remove existing adapter if any
            self.adapters.pop(name, None)
            # Remove its tools from the map
            to_remove = [t for t, s in self.tool_map.items() if s == name]
            for t in to_remove:
                del self.tool_map[t]
                self.tool_schemas.pop(t, None)
            # Get config
            cfg = self._config.get(name)
            if not cfg:
                logger.error(f"No config found for server {name}")
                return False
            # Create adapter
            adapter = self._create_adapter(name, cfg)
            if not adapter:
                return False
            if adapter.connect():
                self.adapters[name] = adapter
                # Discover tools for this server
                tool_list = adapter.discover_tools()
                if tool_list:
                    for tool in tool_list:
                        tool_name = tool.get('name')
                        if tool_name:
                            self.tool_map[tool_name] = name
                            self.tool_schemas[tool_name] = tool.get('inputSchema', {})
                    logger.info(f"Started {name} – discovered {len(tool_list)} tools")
                else:
                    logger.warning(f"Started {name} but no tools discovered")
                return True
            else:
                logger.error(f"Failed to start {name}")
                return False

    def stop_server(self, name: str) -> bool:
        """Stop (disconnect) a specific server."""
        with self.lock:
            adapter = self.adapters.get(name)
            if not adapter:
                return False
            adapter.disconnect()
            del self.adapters[name]
            # Remove its tools from the map
            to_remove = [t for t, s in self.tool_map.items() if s == name]
            for t in to_remove:
                del self.tool_map[t]
                self.tool_schemas.pop(t, None)
            logger.info(f"Stopped {name}")
            return True

    def get_server_status(self, name: str) -> Dict:
        """Get status of a server: connected, tools count, etc."""
        with self.lock:
            adapter = self.adapters.get(name)
            if not adapter:
                return {"connected": False, "tools": []}
            # Get tools for this server
            server_tools = [t for t, s in self.tool_map.items() if s == name]
            return {
                "connected": adapter.is_alive(),
                "tools": server_tools,
                "tool_count": len(server_tools)
            }

    def shutdown(self):
        """Disconnect all servers."""
        for name, adapter in self.adapters.items():
            try:
                adapter.disconnect()
                logger.info(f"Disconnected {name}")
            except Exception as e:
                logger.error(f"Error disconnecting {name}: {e}")


# =============================================================================
# Flask Blueprint
# =============================================================================

from flask import Blueprint, request, jsonify, Response, stream_with_context
from extensions import limiter
from flask_login import login_required

router_bp = Blueprint('mcp_router', __name__, url_prefix='/router')
_router_instance = None

def init_router(config_path="mcp_servers.json"):
    global _router_instance
    _router_instance = MCPRouter(config_path)
    return _router_instance

@router_bp.before_request
@login_required
def exempt_router():
    pass

@router_bp.route('/tools', methods=['GET'])
@login_required
def list_tools():
    if not _router_instance:
        return jsonify({"error": "Router not initialized"}), 500
    return jsonify(_router_instance.list_tools())

@router_bp.route('/call', methods=['POST'])
@login_required
def call_tool():
    if not _router_instance:
        return jsonify({"error": "Router not initialized"}), 500
    data = request.json
    tool = data.get('tool')
    args = data.get('arguments', {})
    if not tool:
        return jsonify({"error": "Missing 'tool'"}), 400

    # Rate limiting
    if current_user.is_authenticated:
        limits = {
            "nmap": (3, 60),
            "gobuster": (2, 60),
            "sqlmap": (2, 120),
            "nikto": (2, 120),
            "hydra": (2, 60),
            "ffuf": (2, 60),
        }
        max_calls, period = limits.get(tool, (5, 60))
        if not tool_rate_limiter.is_allowed(current_user.id, tool, max_calls, period):
            return jsonify({"error": f"Rate limit exceeded for {tool}. Please wait."}), 429

    result = _router_instance.call_tool(tool, args)
    return jsonify(result)

@router_bp.route('/reload', methods=['POST'])
@login_required
def reload_router():
    if not _router_instance:
        return jsonify({"error": "Router not initialized"}), 500
    _router_instance.reload()
    return jsonify({"status": "reloaded", "tools": _router_instance.list_tools()})

@router_bp.route('/server/<name>/start', methods=['POST'])
@login_required
def start_server(name):
    if not _router_instance:
        return jsonify({"error": "Router not initialized"}), 500
    success = _router_instance.start_server(name)
    if success:
        return jsonify({"status": "started", "tools": _router_instance.list_tools()})
    else:
        return jsonify({"error": f"Failed to start server {name}"}), 500

@router_bp.route('/server/<name>/stop', methods=['POST'])
@login_required
def stop_server(name):
    if not _router_instance:
        return jsonify({"error": "Router not initialized"}), 500
    success = _router_instance.stop_server(name)
    if success:
        return jsonify({"status": "stopped"})
    else:
        return jsonify({"error": f"Failed to stop server {name}"}), 500

@router_bp.route('/server/<name>/status', methods=['GET'])
@login_required
@limiter.exempt
def server_status(name):
    if not _router_instance:
        return jsonify({"error": "Router not initialized"}), 500
    status = _router_instance.get_server_status(name)
    return jsonify(status) 
