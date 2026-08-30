#!/usr/bin/env python3
"""
Secure MCP Client v4.0 - With Authentication & Session Tracking
===============================================================

Changes from original:
- Added API key authentication header
- Added X-Session-ID header for session tracking
- All endpoints preserved exactly as before
- Automatic session initialization
"""

import os
import sys
import json
import logging
import asyncio
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path

import requests
from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Client configuration from environment."""
    
    # Server connection
    KALI_API_HOST = os.getenv("SECURE_SERVER_HOST", "127.0.0.1")
    KALI_API_PORT = int(os.getenv("SECURE_SERVER_PORT", "22163"))
    KALI_API_URL = f"http://{KALI_API_HOST}:{KALI_API_PORT}"
    
    # Authentication
    API_KEY = os.getenv("PENTEST_API_KEY", "")
    
    # Session
    SESSION_ID = os.getenv("MCP_SESSION_ID", None)
    
    # Timeouts
    REQUEST_TIMEOUT = int(os.getenv("COMMAND_TIMEOUT", "600"))
    
    @classmethod
    def get_session_id(cls) -> str:
        """Get or create session ID."""
        if cls.SESSION_ID:
            return cls.SESSION_ID
        # Generate a new session ID if not set
        import secrets
        return secrets.token_urlsafe(32)


# ============================================================================
# LOGGING (stderr only - critical for MCP stdio)
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr
)
logger = logging.getLogger(__name__)

# Redirect FastMCP's internal logger to stderr
mcp_logger = logging.getLogger("mcp")
mcp_logger.handlers = [logging.StreamHandler(sys.stderr)]
mcp_logger.setLevel(logging.INFO)


# ============================================================================
# SECURE API CLIENT
# ============================================================================

class SecureAPIClient:
    """Secure API client with authentication and session tracking."""
    
    def __init__(self):
        self.session_id = Config.get_session_id()
        self.api_key = Config.API_KEY
        self.base_url = Config.KALI_API_URL
        self.timeout = Config.REQUEST_TIMEOUT
        self._session_initialized = False
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers with authentication."""
        headers = {
            "Content-Type": "application/json",
            "X-Session-ID": self.session_id
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers
    
    async def init_session(self, output_dir: Optional[str] = None) -> bool:
        """Initialize session with server."""
        if self._session_initialized:
            return True
        
        try:
            response = await self._post_async("api/session/init", {
                "session_id": self.session_id,
                "output_dir": output_dir
            })
            
            if response and response.get("status") == "ok":
                self._session_initialized = True
                logger.info(f"Session initialized: {self.session_id[:16]}...")
                return True
            else:
                logger.error(f"Session init failed: {response}")
                return False
                
        except Exception as e:
            logger.error(f"Session init error: {e}")
            return False
    
    async def _post_async(self, endpoint: str, data: Dict) -> Optional[Dict]:
        """Async POST request to API."""
        import aiohttp
        
        url = f"{self.base_url}/{endpoint}"
        headers = self._get_headers()
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, 
                    json=data, 
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    elif resp.status == 401:
                        logger.error("Authentication failed - check PENTEST_API_KEY")
                        return {"error": "Authentication failed", "success": False}
                    elif resp.status == 429:
                        logger.error("Rate limit exceeded")
                        return {"error": "Rate limit exceeded", "success": False}
                    else:
                        text = await resp.text()
                        logger.error(f"API error {resp.status}: {text[:200]}")
                        return {"error": f"HTTP {resp.status}", "success": False}
        except asyncio.TimeoutError:
            logger.error(f"Timeout calling {url}")
            return {"error": "Request timeout", "success": False}
        except Exception as e:
            logger.error(f"Error calling {url}: {e}")
            return {"error": str(e), "success": False}
    
    def _post_sync(self, endpoint: str, data: Dict) -> Optional[Dict]:
        """Synchronous POST request (for MCP tools)."""
        url = f"{self.base_url}/{endpoint}"
        headers = self._get_headers()
        
        try:
            resp = requests.post(
                url, 
                json=data, 
                headers=headers,
                timeout=self.timeout
            )
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 401:
                logger.error("Authentication failed - check PENTEST_API_KEY")
                return {"error": "Authentication failed", "success": False}
            elif resp.status_code == 429:
                logger.error("Rate limit exceeded")
                return {"error": "Rate limit exceeded", "success": False}
            else:
                logger.error(f"API error {resp.status_code}: {resp.text[:200]}")
                return {"error": f"HTTP {resp.status_code}", "success": False}
        except requests.exceptions.Timeout:
            logger.error(f"Timeout calling {url}")
            return {"error": "Request timeout", "success": False}
        except Exception as e:
            logger.error(f"Error calling {url}: {e}")
            return {"error": str(e), "success": False}
    
    def _get_sync(self, endpoint: str) -> Optional[Dict]:
        """Synchronous GET request."""
        url = f"{self.base_url}/{endpoint}"
        headers = self._get_headers()
        
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            if resp.status_code == 200:
                return resp.json()
            else:
                return {"error": f"HTTP {resp.status_code}", "success": False}
        except Exception as e:
            return {"error": str(e), "success": False}


# ============================================================================
# MCP SERVER SETUP
# ============================================================================

mcp = FastMCP("kali_mcp_secure")
api_client = SecureAPIClient()


# ============================================================================
# SESSION INITIALIZATION TOOL
# ============================================================================

@mcp.tool(name="init_session")
def init_session(output_dir: str = "") -> dict:
    """
    Initialize the session with the server.
    Call this once before using other tools.
    
    Args:
        output_dir: Directory where outputs will be saved (optional)
    """
    # Run async init in sync context
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(api_client.init_session(output_dir or None))
    loop.close()
    
    if result:
        return {"status": "ok", "session_id": api_client.session_id}
    return {"status": "error", "message": "Session initialization failed"}


# ============================================================================
# SCANNING TOOLS
# ============================================================================

@mcp.tool(name="nmap_scan")
def nmap_scan(
    target: str, 
    scan_type: str = "-sV", 
    ports: str = "", 
    additional_args: str = ""
) -> dict:
    """
    Perform an Nmap scan on a target.
    
    Args:
        target: IP address or domain to scan
        scan_type: Nmap scan type (default: -sV)
        ports: Port specification (e.g., "80,443" or "1-1000")
        additional_args: Additional Nmap arguments
    """
    return api_client._post_sync("api/tools/nmap", {
        "target": target,
        "scan_type": scan_type,
        "ports": ports,
        "additional_args": additional_args
    })


@mcp.tool(name="gobuster_scan")
def gobuster_scan(
    url: str,
    mode: str = "dir",
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
    additional_args: str = ""
) -> dict:
    """Perform gobuster directory/file enumeration."""
    return api_client._post_sync("api/tools/gobuster", {
        "url": url,
        "mode": mode,
        "wordlist": wordlist,
        "additional_args": additional_args
    })


@mcp.tool(name="dirb_scan")
def dirb_scan(
    url: str,
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
    additional_args: str = ""
) -> dict:
    """Perform dirb web content scanning."""
    return api_client._post_sync("api/tools/dirb", {
        "url": url,
        "wordlist": wordlist,
        "additional_args": additional_args
    })


@mcp.tool(name="ffuf_scan")
def ffuf_scan(
    url: str,
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
    match_code: str = "200,204,301,302,307,401,403,405",
    filter_size: str = "",
    additional_args: str = ""
) -> dict:
    """Perform ffuf web fuzzing (URL must contain 'FUZZ')."""
    return api_client._post_sync("api/tools/ffuf", {
        "url": url,
        "wordlist": wordlist,
        "match_code": match_code,
        "filter_size": filter_size,
        "additional_args": additional_args
    })


@mcp.tool(name="nikto_scan")
def nikto_scan(target: str, additional_args: str = "") -> dict:
    """Perform nikto web vulnerability scan."""
    return api_client._post_sync("api/tools/nikto", {
        "target": target,
        "additional_args": additional_args
    })


@mcp.tool(name="sqlmap_scan")
def sqlmap_scan(
    url: str,
    data: str = "",
    additional_args: str = ""
) -> dict:
    """Perform sqlmap SQL injection testing."""
    return api_client._post_sync("api/tools/sqlmap", {
        "url": url,
        "data": data,
        "additional_args": additional_args
    })


@mcp.tool(name="wpscan_analyze")
def wpscan_analyze(url: str, additional_args: str = "") -> dict:
    """Perform wpscan WordPress analysis."""
    return api_client._post_sync("api/tools/wpscan", {
        "url": url,
        "additional_args": additional_args
    })


@mcp.tool(name="enum4linux_scan")
def enum4linux_scan(target: str, additional_args: str = "-a") -> dict:
    """Perform enum4linux SMB enumeration."""
    return api_client._post_sync("api/tools/enum4linux", {
        "target": target,
        "additional_args": additional_args
    })


# ============================================================================
# EXPLOITATION TOOLS
# ============================================================================

@mcp.tool(name="hydra_attack")
def hydra_attack(
    target: str,
    service: str,
    username: str = "",
    username_file: str = "",
    password: str = "",
    password_file: str = "",
    additional_args: str = ""
) -> dict:
    """Perform hydra brute force attack."""
    return api_client._post_sync("api/tools/hydra", {
        "target": target,
        "service": service,
        "username": username,
        "username_file": username_file,
        "password": password,
        "password_file": password_file,
        "additional_args": additional_args
    })


@mcp.tool(name="john_crack")
def john_crack(
    hash_file: str,
    wordlist: str = "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
    format_type: str = "",
    additional_args: str = ""
) -> dict:
    """Run John the Ripper hash cracking."""
    return api_client._post_sync("api/tools/john", {
        "hash_file": hash_file,
        "wordlist": wordlist,
        "format": format_type,
        "additional_args": additional_args
    })


# ============================================================================
# WIFI TOOLS
# ============================================================================

@mcp.tool(name="airmon_ng")
def airmon_ng(action: str, interface: str) -> dict:
    """Manage wireless interfaces with airmon-ng."""
    return api_client._post_sync("api/tools/airmon-ng", {
        "action": action,
        "interface": interface
    })


@mcp.tool(name="airodump_ng")
def airodump_ng(
    interface: str,
    write_file: str = "/tmp/airodump",
    channel: str = ""
) -> dict:
    """Capture wireless packets with airodump-ng."""
    return api_client._post_sync("api/tools/airodump-ng", {
        "interface": interface,
        "write_file": write_file,
        "channel": channel
    })


@mcp.tool(name="aircrack_ng")
def aircrack_ng(
    capture_file: str,
    wordlist: str = "/usr/share/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt"
) -> dict:
    """Crack WPA/WPA2 handshakes with aircrack-ng."""
    return api_client._post_sync("api/tools/aircrack-ng", {
        "capture_file": capture_file,
        "wordlist": wordlist
    })


@mcp.tool(name="wifite")
def wifite(
    additional_args: str = "--kill --dict /usr/share/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt"
) -> dict:
    """Run automated wireless auditing with wifite."""
    return api_client._post_sync("api/tools/wifite", {
        "additional_args": additional_args
    })


# ============================================================================
# UTILITY TOOLS
# ============================================================================

@mcp.tool(name="curl_request")
def curl_request(
    url: str,
    method: str = "GET",
    headers: dict = {},
    data: str = ""
) -> dict:
    """Perform HTTP requests with curl."""
    return api_client._post_sync("api/tools/curl", {
        "url": url,
        "method": method,
        "headers": headers,
        "data": data
    })


@mcp.tool(name="netcat_check")
def netcat_check(host: str, port: int) -> dict:
    """Test TCP connectivity with netcat."""
    return api_client._post_sync("api/tools/netcat", {
        "host": host,
        "port": port
    })


@mcp.tool(name="read_file")
def read_file(path: str, max_lines: int = 1000, command: str = "cat") -> dict:
    """
    Read file contents safely.
    
    Args:
        path: Absolute path to file
        max_lines: Maximum lines to read
        command: 'cat', 'head', or 'tail'
    """
    return api_client._post_sync("api/tools/read_file", {
        "path": path,
        "max_lines": max_lines,
        "command": command
    })


@mcp.tool(name="execute_command")
def execute_command(command: str) -> dict:
    """
    Execute a shell command (restricted to whitelisted commands only).
    Use with caution - only whitelisted commands are allowed.
    """
    return api_client._post_sync("api/command", {"command": command})


@mcp.tool(name="decrypt_output")
def decrypt_output(encrypted_data: str) -> dict:
    """Decrypt previously encrypted tool output."""
    return api_client._post_sync("api/decrypt", {"encrypted_data": encrypted_data})


# ============================================================================
# INFORMATION TOOLS
# ============================================================================

@mcp.tool(name="server_health")
def server_health() -> dict:
    """Check server health status."""
    return api_client._get_sync("health")


@mcp.tool(name="session_info")
def session_info() -> dict:
    """Get current session information."""
    return api_client._get_sync("api/session/info")


@mcp.tool(name="search_cve")
def search_cve(keyword: str) -> dict:
    """Search for CVEs related to a keyword."""
    return api_client._post_sync("api/cve/search", {"keyword": keyword})


@mcp.tool(name="clear_cache")
def clear_cache(tool_name: str = "", older_than_hours: int = 0) -> dict:
    """Clear command cache."""
    return api_client._post_sync("api/cache/clear", {
        "tool_name": tool_name,
        "older_than_hours": older_than_hours
    })


@mcp.tool(name="get_cache_stats")
def get_cache_stats() -> dict:
    """Get cache statistics."""
    return api_client._get_sync("api/cache/stats")


# ============================================================================
# SESSION MANAGEMENT TOOLS
# ============================================================================

@mcp.tool(name="session_cleanup")
def session_cleanup() -> dict:
    """Clean up old sessions."""
    return api_client._post_sync("api/session/cleanup", {})


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("Secure MCP Client v4.0")
    logger.info("=" * 60)
    logger.info(f"Server: {Config.KALI_API_URL}")
    logger.info(f"Session ID: {Config.get_session_id()[:16]}...")
    logger.info(f"Auth: {'Enabled' if Config.API_KEY else 'Disabled (WARNING!)'}")
    logger.info("=" * 60)
    
    # Note: Session initialization will happen on first tool call
    # or user can call init_session explicitly
    
    mcp.run()
