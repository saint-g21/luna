#!/usr/bin/env python3
"""
client_v2.py — MCP Server with Session Tracking (FastMCP version)
=================================================================
Uses FastMCP (same as client0.py) to avoid pydantic compatibility issues.
"""

import os
import sys
import json
import secrets
from datetime import datetime
from typing import Dict, Any, List, Optional

import requests
from mcp.server.fastmcp import FastMCP
from config import config

PENTEST_API_KEY = os.environ.get("PENTEST_API_KEY", "")
#sys.stderr = open('/tmp/mcp_client.log', 'a')
KALI_API_URL = "http://127.0.0.1:22163"   # or use environment variable
# ============================================================================
# SESSION MEMORY (Prevents command repeats)
# ============================================================================

class SessionMemory:
    """Tracks executed commands per session to prevent repeats."""
    
    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}
    
    def get_or_create_session(self, session_id: str) -> Dict:
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "executed_commands": [],
                "findings": [],
                "current_phase": "reconnaissance",
                "created_at": datetime.utcnow().isoformat()
            }
        return self.sessions[session_id]
    
    def record_command(self, session_id: str, tool: str, command: str, success: bool):
        session = self.get_or_create_session(session_id)
        session["executed_commands"].append({
            "tool": tool,
            "command": command[:200],
            "success": success,
            "timestamp": datetime.utcnow().isoformat()
        })
        if len(session["executed_commands"]) > 100:
            session["executed_commands"] = session["executed_commands"][-100:]
    
    def was_command_executed(self, session_id: str, command_pattern: str) -> bool:
        session = self.get_or_create_session(session_id)
        for cmd in session["executed_commands"]:
            if command_pattern.lower() in cmd["command"].lower():
                return True
            if command_pattern.lower() in cmd["tool"].lower():
                return True
        return False
    
    def get_session_state(self, session_id: str) -> Dict:
        return self.get_or_create_session(session_id)
    
    def update_phase(self, session_id: str, phase: str):
        session = self.get_or_create_session(session_id)
        session["current_phase"] = phase
    
    def get_next_suggestions(self, session_id: str) -> List[str]:
        session = self.get_or_create_session(session_id)
        executed_tools = set(cmd["tool"] for cmd in session["executed_commands"])
        all_tools = ["nmap", "gobuster", "nikto", "sqlmap", "enum4linux", "wpscan", "hydra"]
        suggested = [t for t in all_tools if t not in executed_tools]
        
        phase = session["current_phase"]
        if phase == "reconnaissance":
            return ["nmap"] + suggested[:2]
        elif phase == "enumeration":
            return ["gobuster", "enum4linux", "nikto"]
        elif phase == "vulnerability":
            return ["sqlmap", "nikto", "wpscan"]
        elif phase == "exploitation":
            return ["hydra", "sqlmap"]
        return suggested[:3]

# Initialize memory
session_memory = SessionMemory()

# ============================================================================
# CONFIGURATION
# ============================================================================

SESSION_ID = os.environ.get("MCP_SESSION_ID", secrets.token_urlsafe(16))
KALI_API_URL = f"http://{config['kali_api']['host']}:{config['kali_api']['port']}"
REQUEST_TIMEOUT = 600000

def kali_post(endpoint: str, data: dict, session_id: str = None) -> dict:
    """POST to server.py with session tracking."""
    url = f"{KALI_API_URL}/{endpoint}"
    headers = {
        "Content-Type": "application/json",
        "X-Session-ID": session_id or SESSION_ID
    }
    if PENTEST_API_KEY:
        headers["Authorization"] = f"Bearer {PENTEST_API_KEY}"
    try:
        resp = requests.post(url, json=data, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e), "success": False}

# ============================================================================
# MCP SERVER SETUP (FastMCP)
# ============================================================================

mcp = FastMCP("kali_mcp")

# ============================================================================
# SESSION MEMORY TOOLS
# ============================================================================

@mcp.tool(name="get_session_state")
def get_session_state(session_id: str = None) -> dict:
    """Get current session state including executed commands and current phase."""
    sid = session_id or SESSION_ID
    state = session_memory.get_session_state(sid)
    return {
        "session_id": sid,
        "executed_commands": state["executed_commands"],
        "current_phase": state["current_phase"],
        "created_at": state["created_at"]
    }

@mcp.tool(name="record_command")
def record_command(tool: str, command: str, success: bool = True, session_id: str = None) -> dict:
    """Record that a command was executed (prevents repeats)."""
    sid = session_id or SESSION_ID
    session_memory.record_command(sid, tool, command, success)
    return {"status": "recorded", "session_id": sid}

@mcp.tool(name="was_command_executed")
def was_command_executed(command_pattern: str, session_id: str = None) -> dict:
    """Check if a command was already executed in this session."""
    sid = session_id or SESSION_ID
    executed = session_memory.was_command_executed(sid, command_pattern)
    return {"executed": executed, "session_id": sid}

@mcp.tool(name="get_next_suggestions")
def get_next_suggestions(session_id: str = None) -> dict:
    """Get suggested next tools based on session history."""
    sid = session_id or SESSION_ID
    suggestions = session_memory.get_next_suggestions(sid)
    return {"suggestions": suggestions, "session_id": sid}

@mcp.tool(name="update_phase")
def update_phase(phase: str, session_id: str = None) -> dict:
    """Update the current pentest phase."""
    valid_phases = ["reconnaissance", "enumeration", "vulnerability", "exploitation", "post_exploitation", "reporting"]
    if phase not in valid_phases:
        return {"error": f"Invalid phase. Choose from: {valid_phases}"}
    sid = session_id or SESSION_ID
    session_memory.update_phase(sid, phase)
    return {"status": "updated", "phase": phase, "session_id": sid}

# ============================================================================
# EXISTING TOOL ENDPOINTS (with auto-recording)
# ============================================================================

@mcp.tool(name="nmap")
def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "", session_id: str = None) -> dict:
    """Perform an Nmap scan on a target."""
    sid = session_id or SESSION_ID
    command = f"nmap {scan_type}"
    if ports:
        command += f" -p {ports}"
    if additional_args:
        command += f" {additional_args}"
    command += f" {target}"
    
    result = kali_post("api/tools/nmap", {
        "target": target, "scan_type": scan_type, "ports": ports, "additional_args": additional_args
    }, sid)
    
    session_memory.record_command(sid, "nmap", command, result.get("success", False))
    if result.get("success") and "open" in result.get("stdout", ""):
        session_memory.update_phase(sid, "enumeration")
    
    return result

@mcp.tool(name="gobuster")
def gobuster_scan(url: str, mode: str = "dir", wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt", additional_args: str = "", session_id: str = None) -> dict:
    """Perform gobuster directory enumeration."""
    sid = session_id or SESSION_ID
    command = f"gobuster {mode} -u {url} -w {wordlist}"
    if additional_args:
        command += f" {additional_args}"
    
    result = kali_post("api/tools/gobuster", {
        "url": url, "mode": mode, "wordlist": wordlist, "additional_args": additional_args
    }, sid)
    
    session_memory.record_command(sid, "gobuster", command, result.get("success", False))
    return result

@mcp.tool(name="sqlmap")
def sqlmap_scan(url: str, data: str = "", additional_args: str = "", session_id: str = None) -> dict:
    """Perform sqlmap SQL injection testing."""
    sid = session_id or SESSION_ID
    command = f"sqlmap -u {url} --batch"
    if data:
        command += f" --data={data}"
    if additional_args:
        command += f" {additional_args}"
    
    result = kali_post("api/tools/sqlmap", {
        "url": url, "data": data, "additional_args": additional_args
    }, sid)
    
    session_memory.record_command(sid, "sqlmap", command, result.get("success", False))
    if result.get("success") and "vulnerable" in result.get("stdout", "").lower():
        session_memory.update_phase(sid, "exploitation")
    
    return result

@mcp.tool(name="nikto")
def nikto_scan(target: str, additional_args: str = "", session_id: str = None) -> dict:
    """Perform nikto web vulnerability scan."""
    sid = session_id or SESSION_ID
    command = f"nikto -h {target}"
    if additional_args:
        command += f" {additional_args}"
    
    result = kali_post("api/tools/nikto", {
        "target": target, "additional_args": additional_args
    }, sid)
    
    session_memory.record_command(sid, "nikto", command, result.get("success", False))
    return result

@mcp.tool(name="wpscan")
def wpscan_analyze(url: str, additional_args: str = "", session_id: str = None) -> dict:
    """Perform wpscan WordPress analysis."""
    sid = session_id or SESSION_ID
    command = f"wpscan --url {url}"
    if additional_args:
        command += f" {additional_args}"
    
    result = kali_post("api/tools/wpscan", {
        "url": url, "additional_args": additional_args
    }, sid)
    
    session_memory.record_command(sid, "wpscan", command, result.get("success", False))
    return result

@mcp.tool(name="enum4linux")
def enum4linux_scan(target: str, additional_args: str = "-a", session_id: str = None) -> dict:
    """Perform enum4linux SMB enumeration."""
    sid = session_id or SESSION_ID
    command = f"enum4linux {additional_args} {target}"
    
    result = kali_post("api/tools/enum4linux", {
        "target": target, "additional_args": additional_args
    }, sid)
    
    session_memory.record_command(sid, "enum4linux", command, result.get("success", False))
    return result

@mcp.tool(name="hydra")
def hydra_attack(target: str, service: str, username: str = "", username_file: str = "",
                 password: str = "", password_file: str = "", additional_args: str = "", session_id: str = None) -> dict:
    """Perform hydra brute force attack."""
    sid = session_id or SESSION_ID
    command = f"hydra -t 4"
    if username:
        command += f" -l {username}"
    elif username_file:
        command += f" -L {username_file}"
    if password:
        command += f" -p {password}"
    elif password_file:
        command += f" -P {password_file}"
    command += f" {target} {service}"
    if additional_args:
        command += f" {additional_args}"
    
    result = kali_post("api/tools/hydra", {
        "target": target, "service": service, "username": username, "username_file": username_file,
        "password": password, "password_file": password_file, "additional_args": additional_args
    }, sid)
    
    session_memory.record_command(sid, "hydra", command, result.get("success", False))
    if result.get("success") and "password" in result.get("stdout", "").lower():
        session_memory.update_phase(sid, "post_exploitation")
    
    return result

# ============================================================================
# UTILITY TOOLS
# ============================================================================

@mcp.tool(name="curl")
def curl_request(url: str, method: str = "GET", headers: dict = {}, data: str = "", session_id: str = None) -> dict:
    """Perform HTTP requests with curl."""
    sid = session_id or SESSION_ID
    command = f"curl -X {method} '{url}'"
    for k, v in headers.items():
        command += f" -H '{k}: {v}'"
    if data:
        command += f" -d '{data}'"
    
    result = kali_post("api/tools/curl", {
        "url": url, "method": method, "headers": headers, "data": data
    }, sid)
    
    session_memory.record_command(sid, "curl", command, result.get("success", False))
    return result

@mcp.tool(name="netcat")
def netcat_check(host: str, port: int, session_id: str = None) -> dict:
    """Test connectivity with netcat (safe mode only)."""
    sid = session_id or SESSION_ID
    command = f"nc -vz {host} {port}"
    
    result = kali_post("api/tools/netcat", {"host": host, "port": port}, sid)
    session_memory.record_command(sid, "netcat", command, result.get("success", False))
    return result

@mcp.tool(name="read_file")
def read_file(path: str, max_lines: int = 1000, command: str = "cat", session_id: str = None) -> dict:
    """Read file contents safely."""
    sid = session_id or SESSION_ID
    result = kali_post("api/tools/read_file", {
        "path": path, "max_lines": max_lines, "command": command
    }, sid)
    return result

@mcp.tool(name="server_health")
def server_health(session_id: str = None) -> dict:
    """Check server health status."""
    return kali_post("health", {}, session_id or SESSION_ID)

@mcp.tool(name="session_info")
def session_info(session_id: str = None) -> dict:
    """Get current session information including memory."""
    sid = session_id or SESSION_ID
    state = session_memory.get_session_state(sid)
    return {
        "session_id": sid,
        "executed_tools": [c["tool"] for c in state["executed_commands"]],
        "current_phase": state["current_phase"],
        "total_commands": len(state["executed_commands"])
    }

@mcp.tool(name="clear_session")
def clear_session(session_id: str = None) -> dict:
    """Clear session memory (start fresh)."""
    sid = session_id or SESSION_ID
    if sid in session_memory.sessions:
        del session_memory.sessions[sid]
    return {"status": "cleared", "session_id": sid}

# ============================================================================
# MAIN
# ============================================================================

"""if __name__ == "__main__":
    print(f"[MCP v2] Session ID: {SESSION_ID[:16]}...", file=sys.stderr)
    print(f"[MCP v2] Session memory enabled - prevents command repeats", file=sys.stderr)
    print(f"MCP server started (stdio)", file=sys.stderr)

    # Ensure the API key is passed to the server
    if not PENTEST_API_KEY:
        print("WARNING: PENTEST_API_KEY not set! The Kali API will reject requests.", file=sys.stderr)
    
    mcp.run(transport='stdio', port='8000')

    #import uvicorn
    #uvicorn.run(mcp.sse_app(), host="127.0.0.1", port=8000, log_level="debug")
"""
if __name__ == "__main__":
    import uvicorn
    from fastapi import FastAPI
    from mcp.server.fastmcp import FastMCP
    import threading

    print(f"[MCP v2] Session ID: {SESSION_ID[:16]}...", file=sys.stderr)
    print(f"[MCP v2] Session memory enabled - prevents command repeats", file=sys.stderr)
    print(f"MCP server started (stdio)", file=sys.stderr)

    if not PENTEST_API_KEY:
        print("WARNING: PENTEST_API_KEY not set! The Kali API will reject requests.", file=sys.stderr)

    # Create a separate HTTP app for tool discovery
    http_app = FastAPI()

    @http_app.get("/tools")
    async def list_tools():
        # Hardcode the tool names (they are known from the @mcp.tool decorators)
        # Alternatively, you can extract them from mcp._tool_manager if needed.
        tools = [
            "nmap", "gobuster", "sqlmap", "nikto", "wpscan", "enum4linux",
            "hydra", "curl", "netcat", "read_file",
            "get_session_state", "record_command", "was_command_executed",
            "get_next_suggestions", "update_phase", "server_health",
            "session_info", "clear_session"
        ]
        return {"tools": [{"name": t} for t in tools]}

    # Start the HTTP server on port 8000 (or any free port)
    # We'll run it in a separate thread so the stdio MCP server can also run.
    def run_http():
        uvicorn.run(http_app, host="127.0.0.1", port=8000, log_level="warning")
    threading.Thread(target=run_http, daemon=True).start()
    
    import sys
    # Read all input (for debugging)
    data = sys.stdin.read()
    print(f"Received: {data}", file=sys.stderr)

    # Now start the stdio MCP server (this blocks)
    mcp.run(transport='stdio')
