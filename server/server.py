#!/usr/bin/env python3
"""
Kali API Server - Provides REST endpoints for penetration testing tools.
Features:
- Execution of Kali tools (nmap, gobuster, sqlmap, hydra, etc.)
- Command logging, caching, encryption, false positive detection.
- CVE search integration.
- Safe file reading via bash (cat/head/tail) and netcat connectivity tests.
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import traceback
import threading
import time
import uuid
from typing import Dict, Any, Optional, List
from flask import Flask, request, jsonify
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import requests
from config import config

# council
try:
    from council.orchestrator import LLMCouncil
    from knowledge.database import KnowledgeDB
    COUNCIL_AVAILABLE = True
    print("council started...")
except ImportError:
    COUNCIL_AVAILABLE = False
    print("Warning: Council/knowledge modules not found. Running without LLM council.", file=sys.stderr)
    
# Redirect stdout to stderr to avoid interfering with Flask's output
sys.stdout = sys.stderr

# encryption
if config["encryption"]["enabled"]:
    from crypto_utils import get_cipher, encrypt_value, decrypt_value
    cipher = get_cipher(config["encryption"]["key_file"])
else:
    cipher = None

#logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", stream=sys.stderr)
logger = logging.getLogger(__name__)

#configuration
API_PORT = int(os.environ.get("API_PORT", config["kali_api"]["port"]))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = config.get("command_timeout", 300)
KNOWLEDGE_DB_PATH = config["database_path"] ##
CHEATSHEET_FILE = config["cheatsheet_file"] ##

app = Flask(__name__)
db = None
council = None
SESSION_ID = None

# Tools whose output may contain sensitive data (passwords, hashes)
SENSITIVE_TOOLS = {"hydra_attack", "john_crack", "sqlmap_scan", "aircrack_ng"}

class CommandExecutor:
    """Executes a shell command with timeout and captures stdout/stderr asynchronously."""
    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False

    def _read_stdout(self):
        for line in iter(self.process.stdout.readline, ''):
            self.stdout_data += line

    def _read_stderr(self):
        for line in iter(self.process.stderr.readline, ''):
            self.stderr_data += line
	# execution
    def execute(self) -> Dict[str, Any]:
        logger.info(f"Executing command: {self.command}")
        try:
            self.process = subprocess.Popen(
                self.command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1
            )
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                self.stdout_thread.join()
                self.stderr_thread.join()
            except subprocess.TimeoutExpired:
                self.timed_out = True
                logger.warning("Command timed out. Terminating.")
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                self.return_code = -1
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data)
            }
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }

def execute_command(command: str) -> Dict[str, Any]:
    return CommandExecutor(command).execute()

def update_cheatsheet(tool_name: str, command: str, params: dict, stdout_snippet: str):
    """Append successful command to the cheatsheet markdown file."""
    try:
        with open(CHEATSHEET_FILE, "a") as f:
            f.write(f"## {tool_name} - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Command:** `{command}`\n")
            f.write(f"**Parameters:** {json.dumps(params)}\n")
            f.write(f"**Output excerpt:**\n```\n{stdout_snippet[:500]}\n```\n\n")
    except Exception as e:
        logger.error(f"Failed to update cheat sheet: {e}")

def log_and_execute(tool_name: str, command: str, params: dict, target: str, executor_func) -> Dict[str, Any]:
    """
    Wrapper for tool execution that handles:
    - Cache lookup
    - Execution & logging
    - Encryption of sensitive output
    - False positive detection
    - Cheatsheet update
    """
    global db, council

    # Check cache
    if db:
        cached = db.get_cached_result(tool_name, command, params)
        if cached:
            logger.info(f"Cache hit for {tool_name} on {target}")
            record_id = db.log_command(
                tool_name, command, params, target, SESSION_ID,
                cached["success"], cached["stdout"], cached["stderr"],
                cached["return_code"], False, False, 0.0,
                encrypted=(tool_name in SENSITIVE_TOOLS and config["encryption"]["enabled"])
            )
            cached["record_id"] = record_id
            return cached

    start = time.time()
    result = executor_func()
    execution_time = time.time() - start

    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")
    encrypted = False

    # Encrypt output for sensitive tools if enabled
    if tool_name in SENSITIVE_TOOLS and config["encryption"]["enabled"] and cipher:
        stdout = encrypt_value(cipher, stdout)
        stderr = encrypt_value(cipher, stderr)
        encrypted = True

    # Cache successful results
    if db and result.get("success"):
        ttl = 3600  # default 1 hour
        if "nmap" in tool_name and "-sV" in command:
            ttl = 86400  # 24h for service scans
        db.store_cached_result(tool_name, command, params, result, ttl_seconds=ttl, encrypted=encrypted)

    # Log to database
    if db:
        record_id = db.log_command(
            tool_name, command, params, target, SESSION_ID,
            result.get("success", False), stdout, stderr,
            result.get("return_code", -1),
            result.get("timed_out", False), result.get("partial_results", False),
            execution_time, encrypted=encrypted
        )
        result["record_id"] = record_id

        # Pattern-based false positive detection
        if result.get("success") and not encrypted:
            plain_stdout = result.get("stdout", "")
            pattern_match = db.match_expected_pattern(tool_name, plain_stdout)
            if pattern_match:
                result["pattern_match"] = pattern_match
                if pattern_match["outcome"] == "false_positive":
                    db.mark_false_positive(record_id, pattern_match["description"])
                    result["false_positive_warning"] = pattern_match["description"]
            elif council:
                fp_result = council.detect_false_positive(tool_name, command, plain_stdout)
                if fp_result.get("is_false_positive"):
                    db.mark_false_positive(record_id, fp_result["reason"])
                    result["false_positive_warning"] = fp_result["reason"]

    # Update cheatsheet (if not encrypted)
    if result.get("success"):
        update_cheatsheet(tool_name, command, params, stdout if not encrypted else "[encrypted]")

    # Decrypt for response if encrypted
    if encrypted:
        result["stdout"] = decrypt_value(cipher, stdout)
        result["stderr"] = decrypt_value(cipher, stderr)

    return result

# ----------------- Tool Endpoints -----------------

@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute arbitrary shell command (use with caution)."""
    params = request.json
    command = params.get("command", "")
    if not command:
        return jsonify({"error": "Command parameter is required"}), 400
    return jsonify(execute_command(command))

@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    params = request.json
    target = params.get("target", "")
    scan_type = params.get("scan_type", "-sV")
    ports = params.get("ports", "")
    additional_args = params.get("additional_args", "-T4")
    if not target:
        return jsonify({"error": "Target parameter is required"}), 400
    command = f"nmap {scan_type}"
    if ports:
        command += f" -p {ports}"
    if additional_args:
        command += f" {additional_args}"
    command += f" {target}"
    return jsonify(log_and_execute("nmap", command, params, target, lambda: execute_command(command)))

@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    params = request.json
    url = params.get("url", "")
    mode = params.get("mode", "dir")
    wordlist = params.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")
    additional_args = params.get("additional_args", "")
    if not url:
        return jsonify({"error": "URL parameter is required"}), 400
    command = f"gobuster {mode} -u {url} -w {wordlist}"
    if additional_args:
        command += f" {additional_args}"
    return jsonify(log_and_execute("gobuster", command, params, url, lambda: execute_command(command)))

@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    params = request.json
    url = params.get("url", "")
    wordlist = params.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")
    additional_args = params.get("additional_args", "")
    if not url:
        return jsonify({"error": "URL parameter is required"}), 400
    command = f"dirb {url} {wordlist}"
    if additional_args:
        command += f" {additional_args}"
    return jsonify(log_and_execute("dirb", command, params, url, lambda: execute_command(command)))

@app.route("/api/tools/ffuf", methods=["POST"])
def ffuf():
    params = request.json
    url = params.get("url", "")
    wordlist = params.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")
    match_code = params.get("match_code", "200,204,301,302,307,401,403,405")
    filter_size = params.get("filter_size", "")
    additional_args = params.get("additional_args", "")
    if not url:
        return jsonify({"error": "URL parameter is required"}), 400
    if "FUZZ" not in url:
        return jsonify({"error": "URL must contain 'FUZZ' keyword"}), 400
    command = f"ffuf -u {url} -w {wordlist} -mc {match_code}"
    if filter_size:
        command += f" -fs {filter_size}"
    if additional_args:
        command += f" {additional_args}"
    return jsonify(log_and_execute("ffuf", command, params, url, lambda: execute_command(command)))

@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    params = request.json
    target = params.get("target", "")
    additional_args = params.get("additional_args", "")
    if not target:
        return jsonify({"error": "Target parameter is required"}), 400
    command = f"nikto -h {target}"
    if additional_args:
        command += f" {additional_args}"
    return jsonify(log_and_execute("nikto", command, params, target, lambda: execute_command(command)))

@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    params = request.json
    url = params.get("url", "")
    data = params.get("data", "")
    additional_args = params.get("additional_args", "")
    if not url:
        return jsonify({"error": "URL parameter is required"}), 400
    command = f"sqlmap -u {url} --batch"
    if data:
        command += f" --data=\"{data}\""
    if additional_args:
        command += f" {additional_args}"
    return jsonify(log_and_execute("sqlmap", command, params, url, lambda: execute_command(command)))

@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    params = request.json
    target = params.get("target", "")
    service = params.get("service", "")
    username = params.get("username", "")
    username_file = params.get("username_file", "")
    password = params.get("password", "")
    password_file = params.get("password_file", "")
    additional_args = params.get("additional_args", "")
    if not target or not service:
        return jsonify({"error": "Target and service required"}), 400
    command = "hydra -t 4"
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
    return jsonify(log_and_execute("hydra", command, params, target, lambda: execute_command(command)))

@app.route("/api/tools/john", methods=["POST"])
def john():
    params = request.json
    hash_file = params.get("hash_file", "")
    wordlist = params.get("wordlist", "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt")
    format_type = params.get("format", "")
    additional_args = params.get("additional_args", "")
    if not hash_file:
        return jsonify({"error": "Hash file required"}), 400
    command = "john"
    if format_type:
        command += f" --format={format_type}"
    if wordlist:
        command += f" --wordlist={wordlist}"
    if additional_args:
        command += f" {additional_args}"
    command += f" {hash_file}"
    return jsonify(log_and_execute("john", command, params, hash_file, lambda: execute_command(command)))

@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    params = request.json
    url = params.get("url", "")
    additional_args = params.get("additional_args", "")
    if not url:
        return jsonify({"error": "URL required"}), 400
    command = f"wpscan --url {url}"
    if additional_args:
        command += f" {additional_args}"
    return jsonify(log_and_execute("wpscan", command, params, url, lambda: execute_command(command)))

@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    params = request.json
    target = params.get("target", "")
    additional_args = params.get("additional_args", "-a")
    if not target:
        return jsonify({"error": "Target required"}), 400
    command = f"enum4linux {additional_args} {target}"
    return jsonify(log_and_execute("enum4linux", command, params, target, lambda: execute_command(command)))

@app.route("/api/tools/curl", methods=["POST"])
def curl():
    params = request.json
    url = params.get("url", "")
    method = params.get("method", "GET")
    headers = params.get("headers", {})
    data = params.get("data", "")
    if not url:
        return jsonify({"error": "URL required"}), 400
    command = f"curl -X {method} '{url}'"
    for k, v in headers.items():
        command += f" -H '{k}: {v}'"
    if data:
        command += f" -d '{data}'"
    command += " -s -i"
    return jsonify(log_and_execute("curl", command, params, url, lambda: execute_command(command)))

# WiFi tools
@app.route("/api/tools/aircrack-ng", methods=["POST"])
def aircrack_ng():
    params = request.json
    capture_file = params.get("capture_file", "")
    wordlist = params.get("wordlist", "/usr/share/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt")
    if not capture_file:
        return jsonify({"error": "Capture file required"}), 400
    command = f"aircrack-ng -w {wordlist} {capture_file}"
    return jsonify(log_and_execute("aircrack-ng", command, params, capture_file, lambda: execute_command(command)))

@app.route("/api/tools/airodump-ng", methods=["POST"])
def airodump_ng():
    params = request.json
    interface = params.get("interface", "")
    write_file = params.get("write_file", "/tmp/airodump")
    channel = params.get("channel", "")
    if not interface:
        return jsonify({"error": "Interface required"}), 400
    command = f"airodump-ng -w {write_file} --output-format csv"
    if channel:
        command += f" -c {channel}"
    command += f" {interface}"
    return jsonify(log_and_execute("airodump-ng", command, params, interface, lambda: execute_command(command)))

@app.route("/api/tools/wifite", methods=["POST"])
def wifite():
    params = request.json
    additional_args = params.get("additional_args", "--kill --dict /usr/share/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt")
    command = f"wifite {additional_args}"
    return jsonify(log_and_execute("wifite", command, params, "", lambda: execute_command(command)))

@app.route("/api/tools/airmon-ng", methods=["POST"])
def airmon_ng():
    params = request.json
    action = params.get("action", "start")
    interface = params.get("interface", "")
    if not interface:
        return jsonify({"error": "Interface required"}), 400
    command = f"airmon-ng {action} {interface}"
    return jsonify(log_and_execute("airmon-ng", command, params, interface, lambda: execute_command(command)))

# NEW TOOLS: netcat and safe file reading
@app.route("/api/tools/netcat", methods=["POST"])
def netcat():
    """
    Perform a netcat connection test (e.g., port check, banner grab).
    Command format: nc -vz <host> <port>  or nc -v <host> <port>
    This endpoint only allows safe netcat usage (no reverse shells).
    """
    params = request.json
    host = params.get("host")
    port = params.get("port")
    mode = params.get("mode", "connect")  # 'connect' or 'listen' (listen is restricted)
    if not host or not port:
        return jsonify({"error": "host and port required"}), 400
    # Restrict to safe operations: only connect with -vz (verbose, no data, just scan)
    command = f"nc -vz {host} {port}"
    return jsonify(log_and_execute("netcat", command, params, host, lambda: execute_command(command)))

@app.route("/api/tools/read_file", methods=["POST"])
def read_file():
    """
    Read contents of a file using safe shell commands (cat, head, tail).
    No write operations allowed.
    """
    params = request.json
    filepath = params.get("path")
    max_lines = params.get("max_lines", 1000)
    command_type = params.get("command", "cat")  # 'cat', 'head', 'tail'
    if not filepath:
        return jsonify({"error": "path required"}), 400
    # Sanitize: only allow reading, not writing or redirection.
    if command_type == "head":
        command = f"head -n {max_lines} {filepath}"
    elif command_type == "tail":
        command = f"tail -n {max_lines} {filepath}"
    else:
        command = f"cat {filepath}"
    # Prevent modification: check for > or >>
    if ">" in command:
        return jsonify({"error": "Redirection not allowed"}), 403
    return jsonify(log_and_execute("read_file", command, params, filepath, lambda: execute_command(command)))
    
## llms & knowledge 
@app.route("/api/council/ask", methods=["POST"])
def council_ask():
    """Send a query to the LLM council and get a synthesized answer."""
    if not council:
        return jsonify({"error": "LLM Council not initialized"}), 500
    data = request.json
    query = data.get("query", "")
    context = {
        "target": data.get("target", ""),
        "tool_hint": data.get("tool_hint", "")
    }
    try:
        response = council.council_deliberation(query, context)
        return jsonify(response)
    except Exception as e:
        logger.error(f"Council error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/council/fp_detect", methods=["POST"])
def detect_fp():
    """Detect false positives in a command output."""
    if not council:
        return jsonify({"error": "LLM Council not initialized"}), 500
    data = request.json
    tool = data.get("tool")
    command = data.get("command")
    output = data.get("output")
    if not all([tool, command, output]):
        return jsonify({"error": "Missing fields: tool, command, output"}), 400
    result = council.detect_false_positive(tool, command, output)
    return jsonify(result)

@app.route("/api/knowledge/suggest", methods=["POST"])
def suggest_tools():
    """Suggest next tools based on past results."""
    if not council:
        return jsonify({"error": "LLM Council not initialized"}), 500
    data = request.json
    target = data.get("target", "")
    previous_results = data.get("previous_results", [])
    try:
        tools = council.suggest_next_tools(target, previous_results)
        return jsonify({"suggested_tools": tools})
    except Exception as e:
        logger.error(f"Suggestion error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/knowledge/mark_fp", methods=["POST"])
def mark_fp():
    """Manually mark a command execution as false positive."""
    if not db:
        return jsonify({"error": "Knowledge DB not initialized"}), 500
    data = request.json
    execution_id = data.get("execution_id")
    reason = data.get("reason", "")
    if not execution_id:
        return jsonify({"error": "execution_id required"}), 400
    db.mark_false_positive(execution_id, reason)
    return jsonify({"status": "ok"})

@app.route("/api/knowledge/add_pattern", methods=["POST"])
def add_pattern():
    """Add a false positive pattern to the knowledge base."""
    if not db:
        return jsonify({"error": "Knowledge DB not initialized"}), 500
    data = request.json
    tool = data.get("tool")
    pattern = data.get("pattern")
    description = data.get("description", "")
    if not tool or not pattern:
        return jsonify({"error": "tool and pattern required"}), 400
    db.add_false_positive_pattern(tool, pattern, description)
    return jsonify({"status": "ok"})


@app.route("/health", methods=["GET"])
def health_check():
    essential_tools = ["nmap", "gobuster", "ffuf", "nikto", "curl"]
    tools_status = {tool: execute_command(f"which {tool}")["success"] for tool in essential_tools}
    return jsonify({
        "status": "healthy",
        "tools_status": tools_status,
        "db_status": "ok" if db else "not initialized",
        "council_status": "ok" if council else "not initialized",
        "session_id": SESSION_ID
    })

@app.route("/api/cache/clear", methods=["POST"])
def clear_cache():
    if db:
        tool = request.json.get("tool_name", "")
        hours = request.json.get("older_than_hours", 0)
        db.clear_cache(tool, hours)
    return jsonify({"status": "ok"})

@app.route("/api/cache/stats", methods=["GET"])
def cache_stats():
    if db:
        stats = db.get_cache_stats()
        return jsonify(stats)
    return jsonify({"error": "Database not initialized"}), 500

# ----------------- CVE Endpoint -----------------
@app.route("/api/cve/search", methods=["POST"])
def search_cve():
    if not config["cve"]["enabled"]:
        return jsonify({"error": "CVE search disabled"}), 403

    params = request.json
    keyword = params.get("keyword", "")
    if not keyword:
        return jsonify({"error": "keyword required"}), 400

    if db:
        cached = db.get_cached_cve(keyword)
        if cached:
            return jsonify({"cves": cached, "from_cache": True})

    api_key = config["cve"]["nvd_api_key"]
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    try:
        import requests
        resp = requests.get(url, params={"keywordSearch": keyword, "resultsPerPage": 5}, headers=headers, timeout=30)
        if resp.status_code != 200:
            logger.error(f"NVD API error {resp.status_code}: {resp.text}")
            return jsonify({"error": f"NVD API error {resp.status_code}"}), 500

        data = resp.json()
        cves = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln["cve"]
            metrics = cve.get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
            cves.append({
                "id": cve["id"],
                "description": cve["descriptions"][0]["value"],
                "cvss_score": cvss_v3.get("baseScore"),
                "published": cve.get("published"),
            })
        if db:
            db.cache_cve_result(keyword, cves, config["cve"]["cache_ttl_hours"])
        return jsonify({"cves": cves, "from_cache": False})
    except Exception as e:
        logger.error(f"CVE search failed: {e}")
        return jsonify({"error": str(e)}), 500

def initialize_components():
    global db, council, SESSION_ID
    if COUNCIL_AVAILABLE:
        db = KnowledgeDB(
            KNOWLEDGE_DB_PATH,
            encryption_enabled=config["encryption"]["enabled"],
            cipher=cipher if config["encryption"]["enabled"] else None
        )
        council = LLMCouncil(KNOWLEDGE_DB_PATH)
    SESSION_ID = str(uuid.uuid4())
    logger.info(f"Session ID: {SESSION_ID}")

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--port", type=int, default=config["kali_api"]["port"])
    parser.add_argument("--ip", type=str, default=config["kali_api"]["host"])
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    API_PORT = args.port
    initialize_components()
    logger.info(f"Starting API on {args.ip}:{API_PORT}")
    app.run(host=args.ip, port=API_PORT, debug=args.debug)
