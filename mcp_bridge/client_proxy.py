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
sys.stderr = open('/tmp/mcp_client.log', 'a')
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

@mcp.tool(name="searchsploit")
def searchsploit(term: str, category: str = "", exact: bool = False, additional_args: str = "", session_id: str = None) -> dict:
    """Search Exploit-DB for exploits."""
    sid = session_id or SESSION_ID
    command = f"searchsploit {term}"
    if category:
        command += f" -c {category}"
    if exact:
        command += " -e"
    if additional_args:
        command += f" {additional_args}"
    result = kali_post("api/tools/searchsploit", {
        "term": term, "category": category, "exact": exact, "additional_args": additional_args
    }, sid)
    session_memory.record_command(sid, "searchsploit", command, result.get("success", False))
    return result

@mcp.tool(name="cve_search")
def cve_search(keyword: str = "", cve_id: str = "", cvss_min: float = None, cvss_max: float = None, cpe: str = "", session_id: str = None) -> dict:
    """Search for CVEs using NVD API with advanced filters."""
    sid = session_id or SESSION_ID
    result = kali_post("api/cve/search", {
        "keyword": keyword, "cve_id": cve_id, "cvss_min": cvss_min,
        "cvss_max": cvss_max, "cpe": cpe
    }, sid)
    # Record in session memory
    session_memory.record_command(sid, "cve_search", f"search {cve_id or keyword}", result.get("success", False))
    return result
    
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
    
@mcp.tool(name="amass")
def amass_enum(target: str, additional_args: str = "", session_id: str = None) -> dict:
    """Subdomain enumeration with Amass."""
    sid = session_id or SESSION_ID
    command = f"amass enum -d {target}"
    if additional_args:
        command += f" {additional_args}"
    result = kali_post("api/tools/amass", {"target": target, "additional_args": additional_args}, sid)
    session_memory.record_command(sid, "amass", command, result.get("success", False))
    return result

@mcp.tool(name="subfinder")
def subfinder_enum(target: str, additional_args: str = "", session_id: str = None) -> dict:
    """Subdomain enumeration with Subfinder."""
    sid = session_id or SESSION_ID
    command = f"subfinder -d {target}"
    if additional_args:
        command += f" {additional_args}"
    result = kali_post("api/tools/subfinder", {"target": target, "additional_args": additional_args}, sid)
    session_memory.record_command(sid, "subfinder", command, result.get("success", False))
    return result

@mcp.tool(name="nuclei")
def nuclei_scan(target: str, templates: str = "", severity: str = "", additional_args: str = "", session_id: str = None) -> dict:
    """Vulnerability scan with Nuclei."""
    sid = session_id or SESSION_ID
    command = f"nuclei -target {target}"
    if templates:
        command += f" -templates {templates}"
    if severity:
        command += f" -severity {severity}"
    if additional_args:
        command += f" {additional_args}"
    result = kali_post("api/tools/nuclei", {"target": target, "templates": templates, "severity": severity, "additional_args": additional_args}, sid)
    session_memory.record_command(sid, "nuclei", command, result.get("success", False))
    return result

@mcp.tool(name="masscan")
def masscan_scan(target: str, ports: str = "1-65535", rate: int = 1000, additional_args: str = "", session_id: str = None) -> dict:
    """High-speed port scan with Masscan."""
    sid = session_id or SESSION_ID
    command = f"masscan {target} -p{ports} --rate {rate}"
    if additional_args:
        command += f" {additional_args}"
    result = kali_post("api/tools/masscan", {"target": target, "ports": ports, "rate": rate, "additional_args": additional_args}, sid)
    session_memory.record_command(sid, "masscan", command, result.get("success", False))
    return result

@mcp.tool(name="wfuzz")
def wfuzz_scan(url: str, wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt", 
               payload: str = "FUZZ", filter_code: str = "", additional_args: str = "", session_id: str = None) -> dict:
    """Web fuzzing with Wfuzz."""
    sid = session_id or SESSION_ID
    command = f"wfuzz -w {wordlist} {url}"
    if filter_code:
        command += f" --hc {filter_code}"
    if additional_args:
        command += f" {additional_args}"
    result = kali_post("api/tools/wfuzz", {"url": url, "wordlist": wordlist, "payload": payload, "filter_code": filter_code, "additional_args": additional_args}, sid)
    session_memory.record_command(sid, "wfuzz", command, result.get("success", False))
    return result

@mcp.tool(name="hashcat")
def hashcat_crack(hash_file: str, wordlist: str = "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
                  hash_type: str = "0", additional_args: str = "", session_id: str = None) -> dict:
    """Password cracking with Hashcat (GPU accelerated)."""
    sid = session_id or SESSION_ID
    command = f"hashcat -m {hash_type} -a 0 {hash_file} {wordlist}"
    if additional_args:
        command += f" {additional_args}"
    result = kali_post("api/tools/hashcat", {"hash_file": hash_file, "wordlist": wordlist, "hash_type": hash_type, "additional_args": additional_args}, sid)
    session_memory.record_command(sid, "hashcat", command, result.get("success", False))
    return result
        
@mcp.tool(name="airodump_ng")
def airodump_ng(interface: str, bssid: str = "", channel: int = 0, output_file: str = "/tmp/airodump_output", additional_args: str = "", session_id: str = None) -> dict:
    """Capture Wi-Fi packets with airodump-ng."""
    sid = session_id or SESSION_ID
    command = f"airodump-ng {interface}"
    if bssid:
        command += f" --bssid {bssid}"
    if channel:
        command += f" -c {channel}"
    if output_file:
        command += f" -w {output_file}"
    if additional_args:
        command += f" {additional_args}"
    result = kali_post("api/tools/airodump-ng", {
        "interface": interface, "bssid": bssid, "channel": channel,
        "output_file": output_file, "additional_args": additional_args
    }, sid)
    session_memory.record_command(sid, "airodump-ng", command, result.get("success", False))
    return result

@mcp.tool(name="wifite")
def wifite_attack(target_bssid: str = "", target_essid: str = "", interface: str = "wlan0mon", attack_type: str = "wpa", additional_args: str = "", session_id: str = None) -> dict:
    """Automated Wi-Fi attack with Wifite."""
    sid = session_id or SESSION_ID
    command = f"wifite -i {interface}"
    if target_bssid:
        command += f" -b {target_bssid}"
    if target_essid:
        command += f" -e {target_essid}"
    if attack_type == "wpa":
        command += " --wpa"
    elif attack_type == "wps":
        command += " --wps"
    # 'all' is default
    if additional_args:
        command += f" {additional_args}"
    result = kali_post("api/tools/wifite", {
        "target_bssid": target_bssid, "target_essid": target_essid,
        "interface": interface, "attack_type": attack_type,
        "additional_args": additional_args
    }, sid)
    session_memory.record_command(sid, "wifite", command, result.get("success", False))
    return result

@mcp.tool(name="airmon_ng")
def airmon_ng(action: str, interface: str = "wlan0", session_id: str = None) -> dict:
    """Control Wi-Fi interface monitor mode (start/stop/check)."""
    sid = session_id or SESSION_ID
    command = f"airmon-ng {action} {interface}"
    result = kali_post("api/tools/airmon-ng", {"action": action, "interface": interface}, sid)
    session_memory.record_command(sid, "airmon-ng", command, result.get("success", False))
    return result

@mcp.tool(name="smbclient")
def smbclient_enum(host: str, share: str = "", username: str = "", password: str = "", additional_args: str = "", session_id: str = None) -> dict:
    """SMB share enumeration with smbclient."""
    sid = session_id or SESSION_ID
    command = f"smbclient -L {host}"
    if share:
        command = f"smbclient //{host}/{share} -N"
    if username:
        command += f" -U {username}"
    if password:
        command += f" -P {password}"
    if additional_args:
        command += f" {additional_args}"
    result = kali_post("api/tools/smbclient", {
        "host": host, "share": share, "username": username, "password": password,
        "additional_args": additional_args
    }, sid)
    session_memory.record_command(sid, "smbclient", command, result.get("success", False))
    return result

@mcp.tool(name="snmpwalk")
def snmpwalk_scan(target: str, community: str = "public", version: str = "2c", oid: str = "1.3.6.1.2.1.1", additional_args: str = "", session_id: str = None) -> dict:
    """SNMP MIB walk with snmpwalk."""
    sid = session_id or SESSION_ID
    command = f"snmpwalk -v {version} -c {community} {target} {oid}"
    if additional_args:
        command += f" {additional_args}"
    result = kali_post("api/tools/snmpwalk", {
        "target": target, "community": community, "version": version, "oid": oid,
        "additional_args": additional_args
    }, sid)
    session_memory.record_command(sid, "snmpwalk", command, result.get("success", False))
    return result

@mcp.tool(name="ldapsearch")
def ldapsearch_query(host: str, port: int = 389, base_dn: str = "", filter: str = "(objectClass=*)", attributes: str = "", bind_dn: str = "", bind_password: str = "", additional_args: str = "", session_id: str = None) -> dict:
    """LDAP query with ldapsearch."""
    sid = session_id or SESSION_ID
    command = f"ldapsearch -x -H ldap://{host}:{port}"
    if base_dn:
        command += f" -b {base_dn}"
    if filter:
        command += f" -s sub {filter}"
    if attributes:
        command += f" {attributes}"
    if bind_dn:
        command += f" -D {bind_dn}"
        if bind_password:
            command += f" -w {bind_password}"
    if additional_args:
        command += f" {additional_args}"
    result = kali_post("api/tools/ldapsearch", {
        "host": host, "port": port, "base_dn": base_dn, "filter": filter,
        "attributes": attributes, "bind_dn": bind_dn, "bind_password": bind_password,
        "additional_args": additional_args
    }, sid)
    session_memory.record_command(sid, "ldapsearch", command, result.get("success", False))
    return result

@mcp.tool(name="responder")
def responder_capture(interface: str = "eth0", additional_args: str = "", session_id: str = None) -> dict:
    """Start Responder to capture NetNTLM hashes."""
    sid = session_id or SESSION_ID
    command = f"responder -I {interface} --basic --lm --wpad"
    if additional_args:
        command += f" {additional_args}"
    result = kali_post("api/tools/responder", {"interface": interface, "additional_args": additional_args}, sid)
    session_memory.record_command(sid, "responder", command, result.get("success", False))
    return result

@mcp.tool(name="bloodhound")
def bloodhound_collect(domain: str, username: str, password: str, nameserver: str = "", collection_method: str = "all", additional_args: str = "", session_id: str = None) -> dict:
    """Collect Active Directory data for BloodHound."""
    sid = session_id or SESSION_ID
    command = f"bloodhound-python -d {domain} -u {username} -p {password} -c {collection_method} --zip"
    if nameserver:
        command += f" -ns {nameserver}"
    if additional_args:
        command += f" {additional_args}"
    result = kali_post("api/tools/bloodhound", {
        "domain": domain, "username": username, "password": password,
        "nameserver": nameserver, "collection_method": collection_method,
        "additional_args": additional_args
    }, sid)
    session_memory.record_command(sid, "bloodhound", command, result.get("success", False))
    return result

@mcp.tool(name="whatweb")
def whatweb_identify(target: str, additional_args: str = "", session_id: str = None) -> dict:
    """Web technology fingerprinting with whatweb."""
    sid = session_id or SESSION_ID
    command = f"whatweb {target}"
    if additional_args:
        command += f" {additional_args}"
    result = kali_post("api/tools/whatweb", {"target": target, "additional_args": additional_args}, sid)
    session_memory.record_command(sid, "whatweb", command, result.get("success", False))
    return result

@mcp.tool(name="cewl")
def cewl_generate(target: str, depth: int = 2, min_word_length: int = 3, additional_args: str = "", session_id: str = None) -> dict:
    """Generate custom wordlist with CeWL."""
    sid = session_id or SESSION_ID
    command = f"cewl {target} -d {depth} -m {min_word_length}"
    if additional_args:
        command += f" {additional_args}"
    result = kali_post("api/tools/cewl", {
        "target": target, "depth": depth, "min_word_length": min_word_length,
        "additional_args": additional_args
    }, sid)
    session_memory.record_command(sid, "cewl", command, result.get("success", False))
    return result

@mcp.tool(name="medusa")
def medusa_bruteforce(host: str, service: str, username: str = "", username_file: str = "", password: str = "", password_file: str = "", additional_args: str = "", session_id: str = None) -> dict:
    """Brute‑force with Medusa."""
    sid = session_id or SESSION_ID
    command = f"medusa -h {host} -s {service}"
    if username:
        command += f" -u {username}"
    elif username_file:
        command += f" -U {username_file}"
    if password:
        command += f" -p {password}"
    elif password_file:
        command += f" -P {password_file}"
    if additional_args:
        command += f" {additional_args}"
    result = kali_post("api/tools/medusa", {
        "host": host, "service": service, "username": username, "username_file": username_file,
        "password": password, "password_file": password_file, "additional_args": additional_args
    }, sid)
    session_memory.record_command(sid, "medusa", command, result.get("success", False))
    return result

@mcp.tool(name="dnsrecon")
def dnsrecon_enum(target: str, type: str = "std", additional_args: str = "", session_id: str = None) -> dict:
    """DNS enumeration with dnsrecon."""
    sid = session_id or SESSION_ID
    command = f"dnsrecon -d {target} -t {type}"
    if additional_args:
        command += f" {additional_args}"
    result = kali_post("api/tools/dnsrecon", {"target": target, "type": type, "additional_args": additional_args}, sid)
    session_memory.record_command(sid, "dnsrecon", command, result.get("success", False))
    return result

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print(f"[MCP v2] Session ID: {SESSION_ID[:16]}...", file=sys.stderr)
    print(f"[MCP v2] Session memory enabled - prevents command repeats", file=sys.stderr)
    print(f"MCP server started (stdio)", file=sys.stderr)

    # Ensure the API key is passed to the server
    if not PENTEST_API_KEY:
        print("WARNING: PENTEST_API_KEY not set! The Kali API will reject requests.", file=sys.stderr)
    

    import uvicorn
    uvicorn.run(mcp.sse_app(), host="127.0.0.1", port=8010, log_level="debug")
