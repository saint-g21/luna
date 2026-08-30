#!/usr/bin/env python3
"""
Secure Kali API Server v4.0 - NO SHELL INJECTION
================================================

Security Features:
- NO shell=True anywhere
- Command validation and whitelisting
- API key authentication
- Rate limiting with burst protection
- Encrypted output storage with HMAC
- Path traversal prevention
- Session isolation
- Input sanitization
"""

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shlex
import signal
import sys
import time
import unicodedata
import ipaddress
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from functools import wraps

from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field, validator
import uvicorn

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Central configuration from environment."""
    
    # Server
    HOST = os.getenv("SECURE_SERVER_HOST", "127.0.0.1")
    PORT = int(os.getenv("SECURE_SERVER_PORT", "22163"))
    API_KEY = os.getenv("PENTEST_API_KEY", "")
    
    # Security
    MAX_REQUESTS_PER_SECOND = float(os.getenv("MAX_REQUESTS_PER_SECOND", "5"))
    MAX_BURST = int(os.getenv("MAX_BURST_REQUESTS", "10"))
    COMMAND_TIMEOUT = int(os.getenv("COMMAND_TIMEOUT", "600"))
    MAX_OUTPUT_SIZE_MB = int(os.getenv("MAX_OUTPUT_SIZE_MB", "10"))
    SESSION_TIMEOUT_HOURS = int(os.getenv("SESSION_TIMEOUT_HOURS", "24"))
    
    # Encryption
    ENCRYPTION_ENABLED = os.getenv("ENCRYPTION_ENABLED", "true").lower() == "true"
    
    # Database
    DATABASE_PATH = os.getenv("DATABASE_PATH", "knowledge.db")
    
    @classmethod
    def validate(cls):
        if not cls.API_KEY:
            print("WARNING: No PENTEST_API_KEY set in .env file!")
            print("Set this to a secure random string to enable authentication")
            return False
        return True


# ============================================================================
# SECURITY UTILITIES
# ============================================================================

class SecureCrypto:
    """Encryption with integrity verification."""
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.key = self._derive_key(session_id)
        self.cipher = Fernet(self.key)
        self.hmac_key = secrets.token_bytes(32)
    
    def _derive_key(self, seed: str) -> bytes:
        """Derive encryption key from session ID."""
        # Simple but secure key derivation
        key = seed.encode()
        for _ in range(100000):  # 100k iterations
            key = hashlib.sha256(key).digest()
        return base64.urlsafe_b64encode(key[:32])
    
    def encrypt_output(self, data: str, tool_name: str, target: str) -> str:
        """Encrypt output with metadata for verification."""
        metadata = {
            "tool": tool_name,
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "session": self.session_id,
            "hmac": self._compute_hmac(data),
            "size_bytes": len(data)
        }
        combined = json.dumps({"metadata": metadata, "data": data})
        return self.cipher.encrypt(combined.encode()).decode()
    
    def decrypt_output(self, encrypted: str) -> Tuple[Optional[str], bool]:
        """Decrypt and verify integrity. Returns (data, is_valid)."""
        try:
            decrypted = self.cipher.decrypt(encrypted.encode()).decode()
            obj = json.loads(decrypted)
            
            expected_hmac = self._compute_hmac(obj["data"])
            if not hmac.compare_digest(expected_hmac, obj["metadata"]["hmac"]):
                return None, False
            
            return obj["data"], True
        except Exception:
            return None, False
    
    def _compute_hmac(self, data: str) -> str:
        return hmac.new(self.hmac_key, data.encode(), hashlib.sha256).hexdigest()


class CommandValidator:
    """Validates all commands before execution (NO SHELL)."""
    
    # Whitelisted commands
    ALLOWED_COMMANDS = {
        "nmap": {
            "max_args": 20,
            "forbidden_flags": ["--interactive", "--unprivileged"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'
        },
        "gobuster": {
            "max_args": 15,
            "forbidden_flags": ["-o", "--output"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'
        },
        "dirb": {
            "max_args": 10,
            "forbidden_flags": [],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'
        },
        "ffuf": {
            "max_args": 15,
            "forbidden_flags": ["-o", "--output"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'
        },
        "nikto": {
            "max_args": 10,
            "forbidden_flags": [],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'
        },
        "sqlmap": {
            "max_args": 25,
            "forbidden_flags": ["--os-shell", "--os-pwn", "--sql-shell"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'
        },
        "hydra": {
            "max_args": 20,
            "forbidden_flags": [],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'
        },
        "john": {
            "max_args": 15,
            "forbidden_flags": [],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'
        },
        "wpscan": {
            "max_args": 15,
            "forbidden_flags": [],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'
        },
        "enum4linux": {
            "max_args": 10,
            "forbidden_flags": [],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'
        },
        "curl": {
            "max_args": 15,
            "forbidden_flags": ["-o", "--output", "-O", "--remote-name"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'
        },
        "aircrack-ng": {
            "max_args": 10,
            "forbidden_flags": [],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'
        },
        "airodump-ng": {
            "max_args": 10,
            "forbidden_flags": [],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'
        },
        "wifite": {
            "max_args": 10,
            "forbidden_flags": [],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'
        },
        "airmon-ng": {
            "max_args": 5,
            "forbidden_flags": [],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'
        },
        "nc": {
            "max_args": 10,
            "forbidden_flags": ["-e", "--exec", "-c"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'
        },
        "cat": {
            "max_args": 5,
            "forbidden_flags": [],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'
        },
        "head": {
            "max_args": 5,
            "forbidden_flags": [],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'
        },
        "tail": {
            "max_args": 5,
            "forbidden_flags": [],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'
        },
        "amass": {
            "max_args": 10,
            "forbidden_flags": ["-o", "--output", "-config"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'
        },
        "subfinder": {
            "max_args": 10,
            "forbidden_flags": ["-o", "--output"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,]+$'
        },
        "nuclei": {
            "max_args": 20,
            "forbidden_flags": ["-o", "--output", "-interactsh", "-t", "-templates"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'
        },
        "masscan": {
            "max_args": 15,
            "forbidden_flags": ["-o", "--output", "--output-format"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'
        },
        "wfuzz": {
            "max_args": 15,
            "forbidden_flags": ["-o", "--output"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'
        },
        "hashcat": {
            "max_args": 15,
            "forbidden_flags": ["-o", "--outfile", "--potfile-path", "--session", "--restore"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'
        },
        "searchsploit": {
            "max_args": 10,
            "forbidden_flags": ["-o", "--output", "--json"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'
        },
        "smbclient": {
            "max_args": 10,
            "forbidden_flags": ["-c", "--command", "-O", "--option", "-d", "--debuglevel"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'
        },
        "snmpwalk": {
            "max_args": 15,
            "forbidden_flags": ["-c", "--community", "-v", "--version", "-t", "--timeout"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'
        },
        "ldapsearch": {
            "max_args": 20,
            "forbidden_flags": ["-D", "--binddn", "-w", "--bindpw", "-y", "--passfile"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'
        },
        "responder": {
            "max_args": 10,
            "forbidden_flags": ["-w", "--wpad", "-F", "--force-wpad"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'
        },
        "bloodhound-python": {
            "max_args": 15,
            "forbidden_flags": ["-c", "--collectionmethod", "-ns", "--nameserver"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'
        },
        "whatweb": {
            "max_args": 15,
            "forbidden_flags": ["-o", "--output", "-a", "--aggression"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'
        },
        "cewl": {
            "max_args": 15,
            "forbidden_flags": ["-o", "--output", "-d", "--depth"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'
        },
        "medusa": {
            "max_args": 25,
            "forbidden_flags": ["-O", "--output", "-d", "--debug"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'
        },
        "dnsrecon": {
            "max_args": 15,
            "forbidden_flags": ["-c", "--csv", "-j", "--json", "-x", "--xml"],
            "allowed_pattern": r'^[a-zA-Z0-9\s\-\./:_,=]+$'
        }
    }
    
    # Dangerous patterns (command injection)
    DANGEROUS_PATTERNS = [
        r'[;&|`$]',                    # Shell metacharacters
        r'\${.*}',                      # Variable substitution
        r'\\x[0-9a-f]{2}',             # Hex encoding
        r'%[0-9a-f]{2}',               # URL encoding
        r'\.\./',                       # Path traversal
        r'base64\s+-d',                # Encoded commands
        r'curl.*\|.*sh',               # Pipe to shell
        r'wget.*\|.*sh',               # Pipe to shell
        r'/dev/tcp/',                   # Network shell
        r'python\s+-c',                # Python execution
        r'perl\s+-e',                  # Perl execution
        r'ruby\s+-e',                  # Ruby execution
        r'\{.*\}',                      # Brace expansion
    ]
    
    @classmethod
    def validate_target(cls, target: str) -> Tuple[bool, str]:
        """Validate target IP or domain."""
        if not target or len(target) > 255:
            return False, "Invalid target length"
        
        # Normalize Unicode (prevents homoglyph attacks)
        target = unicodedata.normalize('NFKC', target.strip())
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, target, re.IGNORECASE):
                return False, f"Dangerous pattern detected"
        
        # Try as IP address
        try:
            ipaddress.ip_address(target)
            return True, target
        except ValueError:
            pass
        
        # Try as domain
        domain_pattern = r'^[a-z0-9][a-z0-9\.-]+\.[a-z]{2,}$'
        if re.match(domain_pattern, target, re.IGNORECASE):
            return True, target
        
        return False, "Invalid target format (must be IP or domain)"
    
    @classmethod
    def validate_command_args(cls, tool: str, args: List[str]) -> Tuple[bool, str, List[str]]:
        """
        Validate command arguments.
        Returns: (is_valid, error_message, sanitized_args)
        """
        if tool not in cls.ALLOWED_COMMANDS:
            return False, f"Tool '{tool}' not in whitelist", []
        
        config = cls.ALLOWED_COMMANDS[tool]
        
        # Check argument count
        if len(args) > config["max_args"]:
            return False, f"Too many arguments (max {config['max_args']})", []
        
        # Check for forbidden flags
        for arg in args:
            for forbidden in config["forbidden_flags"]:
                if arg.startswith(forbidden):
                    return False, f"Forbidden flag: {forbidden}", []
        
        # Validate each argument
        sanitized = []
        for arg in args:
            # Check for dangerous patterns
            for pattern in cls.DANGEROUS_PATTERNS:
                if re.search(pattern, arg, re.IGNORECASE):
                    return False, f"Dangerous pattern in argument: {arg[:50]}", []
            
            # Check character whitelist
            if not re.match(config["allowed_pattern"], arg):
                # Allow paths with slashes
                if not (arg.startswith('/') or arg.startswith('./') or '.' in arg):
                    return False, f"Invalid characters in argument: {arg[:50]}", []
            
            sanitized.append(arg)
        
        return True, "", sanitized


class AntiPoisoningFilter:
    """Detects and removes poisoning attempts in tool outputs."""
    
    POISON_PATTERNS = [
        ("ansi_escape", r'\x1b\[[0-9;]*[a-zA-Z]', "medium"),
        ("null_byte", r'\x00', "critical"),
        ("backspace_override", r'.\x08', "medium"),
        ("injection_script", r'<script|javascript:|onload=', "high"),
        ("fake_success", r'(?i)success.*?but.*?not', "medium"),
        ("eval_call", r'eval\(|exec\(|system\(', "critical"),
        ("data_uri", r'data:[a-z]+/[a-z]+;base64,', "high"),
        ("carriage_return", r'\r[^\n]', "low"),
        ("unprintable", r'[\x00-\x08\x0b\x0c\x0e-\x1f]', "medium"),
    ]
    
    @classmethod
    def filter_output(cls, output: str) -> Tuple[str, List[Dict]]:
        """Filter output and return warnings."""
        warnings = []
        filtered = output
        
        for name, pattern, severity in cls.POISON_PATTERNS:
            matches = re.findall(pattern, filtered, re.IGNORECASE)
            if matches:
                warnings.append({
                    "name": name,
                    "severity": severity,
                    "count": len(matches)
                })
                filtered = re.sub(pattern, f'[{name}_removed]', filtered)
        
        # Remove null bytes completely
        filtered = filtered.replace('\x00', '')
        
        return filtered, warnings
    
    @classmethod
    def validate_output_integrity(cls, output: str) -> Tuple[bool, List[str]]:
        """Check if output appears legitimate."""
        issues = []
        
        # Check for unrealistic success rates
        if "found" in output.lower():
            success_matches = re.findall(r'(\d+)\s*(?:found|success)', output.lower())
            if success_matches:
                total = sum(int(m) for m in success_matches if m.isdigit())
                if total > 10000:
                    issues.append(f"Unusually high success count: {total}")
        
        # Check output size
        if len(output) > Config.MAX_OUTPUT_SIZE_MB * 1024 * 1024:
            issues.append(f"Output size exceeds {Config.MAX_OUTPUT_SIZE_MB}MB")
        
        # Check for binary data
        if any(ord(c) < 32 and c not in '\n\r\t' for c in output[:1000]):
            issues.append("Binary data detected in output")
        
        return len(issues) == 0, issues


class RateLimiter:
    """Rate limiting with token bucket algorithm."""
    
    def __init__(self, rate: float = 5.0, burst: int = 10):
        self.rate = rate  # tokens per second
        self.burst = burst
        self.tokens = burst
        self.last_refill = time.time()
        self.lock = asyncio.Lock()
    
    async def acquire(self) -> bool:
        """Acquire a token. Returns True if allowed."""
        async with self.lock:
            now = time.time()
            # Refill tokens based on time elapsed
            elapsed = now - self.last_refill
            refill = elapsed * self.rate
            self.tokens = min(self.burst, self.tokens + refill)
            self.last_refill = now
            
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False
    
    async def wait_and_acquire(self) -> None:
        """Wait until a token is available."""
        while not await self.acquire():
            await asyncio.sleep(0.1)


# ============================================================================
# PYDANTIC MODELS (Request Validation)
# ============================================================================

class NmapRequest(BaseModel):
    target: str
    scan_type: str = "-sV"
    ports: Optional[str] = None
    additional_args: str = ""
    
    @validator('target')
    def validate_target(cls, v):
        is_valid, msg = CommandValidator.validate_target(v)
        if not is_valid:
            raise ValueError(msg)
        return v
    
    @validator('ports')
    def validate_ports(cls, v):
        if v and not re.match(r'^[\d,-]+$', v):
            raise ValueError("Ports must be comma/hyphen separated numbers (e.g., '80,443' or '1-1000')")
        return v


class GobusterRequest(BaseModel):
    url: str
    mode: str = "dir"
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    additional_args: str = ""
    
    @validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError("URL must start with http:// or https://")
        # Basic URL validation
        if ' ' in v:
            raise ValueError("URL cannot contain spaces")
        return v
    
    @validator('wordlist')
    def validate_wordlist(cls, v):
        path = Path(v)
        if not path.exists():
            raise ValueError(f"Wordlist not found: {v}")
        size_mb = path.stat().st_size / (1024 * 1024)
        if size_mb > 100:
            raise ValueError(f"Wordlist too large: {size_mb:.1f}MB (max 100MB)")
        return v


class SqlmapRequest(BaseModel):
    url: str
    data: Optional[str] = None
    additional_args: str = ""
    
    @validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError("URL must start with http:// or https://")
        return v


class HydraRequest(BaseModel):
    target: str
    service: str
    username: Optional[str] = None
    username_file: Optional[str] = None
    password: Optional[str] = None
    password_file: Optional[str] = None
    additional_args: str = ""
    
    @validator('target')
    def validate_target(cls, v):
        is_valid, msg = CommandValidator.validate_target(v)
        if not is_valid:
            raise ValueError(msg)
        return v
    
    @validator('service')
    def validate_service(cls, v):
        allowed = ["ssh", "ftp", "http-get", "http-post", "https-get", "https-post", "smb", "rdp", "mysql", "postgresql"]
        if v not in allowed:
            raise ValueError(f"Service must be one of: {', '.join(allowed)}")
        return v
    
    @validator('username_file', 'password_file')
    def validate_file(cls, v):
        if v:
            path = Path(v)
            if not path.exists():
                raise ValueError(f"File not found: {v}")
            size_mb = path.stat().st_size / (1024 * 1024)
            if size_mb > 50:
                raise ValueError(f"Wordlist too large: {size_mb:.1f}MB (max 50MB)")
        return v


class DirbRequest(BaseModel):
    url: str
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    additional_args: str = ""
    
    @validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError("URL must start with http:// or https://")
        return v


class FfufRequest(BaseModel):
    url: str
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    match_code: str = "200,204,301,302,307,401,403,405"
    filter_size: str = ""
    additional_args: str = ""
    
    @validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError("URL must start with http:// or https://")
        if "FUZZ" not in v:
            raise ValueError("URL must contain 'FUZZ' keyword")
        return v


class NiktoRequest(BaseModel):
    target: str
    additional_args: str = ""
    
    @validator('target')
    def validate_target(cls, v):
        is_valid, msg = CommandValidator.validate_target(v)
        if not is_valid:
            raise ValueError(msg)
        return v


class WpscanRequest(BaseModel):
    url: str
    additional_args: str = ""
    
    @validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError("URL must start with http:// or https://")
        return v


class CurlRequest(BaseModel):
    url: str
    method: str = "GET"
    headers: Dict[str, str] = {}
    data: str = ""
    
    @validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError("URL must start with http:// or https://")
        return v
    
    @validator('method')
    def validate_method(cls, v):
        allowed = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
        if v.upper() not in allowed:
            raise ValueError(f"Method must be one of: {', '.join(allowed)}")
        return v.upper()


class ReadFileRequest(BaseModel):
    path: str
    max_lines: int = 1000
    command: str = "cat"
    
    @validator('path')
    def validate_path(cls, v):
        # Prevent path traversal
        if '..' in v:
            raise ValueError("Path traversal not allowed")
        if not v.startswith('/'):
            raise ValueError("Absolute path required")
        
        # Restrict to safe directories
        safe_dirs = ['/tmp', '/var/log', '/etc', '/usr/share']
        is_safe = any(v.startswith(sd) for sd in safe_dirs)
        if not is_safe:
            raise ValueError(f"Path must be in safe directories: {', '.join(safe_dirs)}")
        
        # Check if file exists
        if not Path(v).exists():
            raise ValueError(f"File not found: {v}")
        
        return v
    
    @validator('max_lines')
    def validate_max_lines(cls, v):
        if v < 1 or v > 10000:
            raise ValueError("max_lines must be between 1 and 10000")
        return v


class JohnRequest(BaseModel):
    hash_file: str
    wordlist: str = "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt"
    format_type: str = ""
    additional_args: str = ""
    
    @validator('hash_file')
    def validate_hash_file(cls, v):
        path = Path(v)
        if not path.exists():
            raise ValueError(f"Hash file not found: {v}")
        if path.stat().st_size > 10 * 1024 * 1024:
            raise ValueError("Hash file too large (>10MB)")
        return v


class NetcatRequest(BaseModel):
    host: str
    port: int
    
    @validator('host')
    def validate_host(cls, v):
        is_valid, msg = CommandValidator.validate_target(v)
        if not is_valid:
            raise ValueError(msg)
        return v
    
    @validator('port')
    def validate_port(cls, v):
        if v < 1 or v > 65535:
            raise ValueError("Port must be between 1 and 65535")
        return v
        
class Aircrack_ngRequest(BaseModel):
    output_file : str
    wordlist : str ="/usr/share/seclists/Usernames/cirt-default-usernames.txt"
    additional_args: str = ""
    
    @validator('output_file')
    def validate_output(cls, v):
        path = Path(v)
        if not path.exists():
            raise ValueError("Output file not found")
        return v

class AmassRequest(BaseModel):
    target: str
    additional_args: str = ""

    @validator('target')
    def validate_target(cls, v):
        is_valid, msg = CommandValidator.validate_target(v)
        if not is_valid:
            raise ValueError(msg)
        return v

class SubfinderRequest(BaseModel):
    target: str
    additional_args: str = ""

    @validator('target')
    def validate_target(cls, v):
        is_valid, msg = CommandValidator.validate_target(v)
        if not is_valid:
            raise ValueError(msg)
        return v

class NucleiRequest(BaseModel):
    target: str
    templates: Optional[str] = None   # e.g., "cves/,misconfigurations/"
    severity: Optional[str] = None    # low,medium,high,critical
    additional_args: str = ""

    @validator('target')
    def validate_target(cls, v):
        # nuclei accepts URLs or IPs
        if not v.startswith(('http://', 'https://')) and not re.match(r'^[0-9.]+$', v):
            raise ValueError("Target must be a URL or IP address")
        return v

    @validator('severity')
    def validate_severity(cls, v):
        if v and v not in ["low", "medium", "high", "critical"]:
            raise ValueError("Severity must be one of: low, medium, high, critical")
        return v

class MasscanRequest(BaseModel):
    target: str
    ports: str = "1-65535"
    rate: int = 1000
    additional_args: str = ""

    @validator('target')
    def validate_target(cls, v):
        # masscan accepts CIDR or IP ranges
        if '/' in v:
            try:
                ipaddress.ip_network(v, strict=False)
                return v
            except ValueError:
                raise ValueError("Invalid CIDR notation")
        else:
            is_valid, msg = CommandValidator.validate_target(v)
            if not is_valid:
                raise ValueError(msg)
            return v

    @validator('ports')
    def validate_ports(cls, v):
        if not re.match(r'^[\d,-]+$', v):
            raise ValueError("Ports must be comma/hyphen separated numbers")
        return v

    @validator('rate')
    def validate_rate(cls, v):
        if v < 1 or v > 100000:
            raise ValueError("Rate must be between 1 and 100,000 packets/sec")
        return v

class WfuzzRequest(BaseModel):
    url: str
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    payload: str = "FUZZ"
    filter_code: str = ""
    additional_args: str = ""

    @validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError("URL must start with http:// or https://")
        if "FUZZ" not in v:
            raise ValueError("URL must contain 'FUZZ' keyword (or custom payload)")
        return v

    @validator('wordlist')
    def validate_wordlist(cls, v):
        path = Path(v)
        if not path.exists():
            raise ValueError(f"Wordlist not found: {v}")
        size_mb = path.stat().st_size / (1024 * 1024)
        if size_mb > 100:
            raise ValueError(f"Wordlist too large: {size_mb:.1f}MB (max 100MB)")
        return v

class AirodumpNgRequest(BaseModel):
    interface: str
    bssid: Optional[str] = None
    channel: Optional[int] = None
    output_file: str = "/tmp/airodump_output"
    additional_args: str = ""

    @validator('interface')
    def validate_interface(cls, v):
        # Basic interface name check (e.g., wlan0, eth0)
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError("Invalid interface name")
        return v

    @validator('channel')
    def validate_channel(cls, v):
        if v is not None and (v < 1 or v > 165):
            raise ValueError("Channel must be between 1 and 165")
        return v

    @validator('output_file')
    def validate_output_file(cls, v):
        path = Path(v)
        # Ensure it's in a safe directory (e.g., /tmp)
        if not str(path.resolve()).startswith('/tmp'):
            raise ValueError("Output file must be in /tmp")
        # Add .cap extension if missing (airodump-ng expects .cap)
        if not v.endswith('.cap'):
            v = v + '.cap'
        return v


class WifiteRequest(BaseModel):
    target_bssid: Optional[str] = None
    target_essid: Optional[str] = None
    interface: str = "wlan0mon"
    attack_type: str = "wpa"  # wpa, wps, all
    additional_args: str = ""

    @validator('target_bssid')
    def validate_bssid(cls, v):
        if v and not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', v):
            raise ValueError("Invalid BSSID format (e.g., 00:11:22:33:44:55)")
        return v

    @validator('attack_type')
    def validate_attack_type(cls, v):
        allowed = ["wpa", "wps", "all"]
        if v not in allowed:
            raise ValueError(f"attack_type must be one of: {', '.join(allowed)}")
        return v


class AirmonNgRequest(BaseModel):
    action: str  # start, stop, check
    interface: str = "wlan0"

    @validator('action')
    def validate_action(cls, v):
        allowed = ["start", "stop", "check"]
        if v not in allowed:
            raise ValueError(f"action must be one of: {', '.join(allowed)}")
        return v

    @validator('interface')
    def validate_interface(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError("Invalid interface name")
        return v


class Enum4linuxRequest(BaseModel):
    target: str
    additional_args: str = "-a"

    @validator('target')
    def validate_target(cls, v):
        is_valid, msg = CommandValidator.validate_target(v)
        if not is_valid:
            raise ValueError(msg)
        return v

class HashcatRequest(BaseModel):
    hash_file: str
    wordlist: str = "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt"
    hash_type: str = "0"   # default MD5
    additional_args: str = ""

    @validator('hash_file')
    def validate_hash_file(cls, v):
        path = Path(v)
        if not path.exists():
            raise ValueError(f"Hash file not found: {v}")
        if path.stat().st_size > 10 * 1024 * 1024:
            raise ValueError("Hash file too large (>10MB)")
        return v

    @validator('wordlist')
    def validate_wordlist(cls, v):
        path = Path(v)
        if not path.exists():
            raise ValueError(f"Wordlist not found: {v}")
        size_mb = path.stat().st_size / (1024 * 1024)
        if size_mb > 100:
            raise ValueError(f"Wordlist too large: {size_mb:.1f}MB (max 100MB)")
        return v
        
class SearchsploitRequest(BaseModel):
    term: str
    category: Optional[str] = None  # e.g., "remote", "local", "dos"
    exact: bool = False
    additional_args: str = ""

    @validator('term')
    def validate_term(cls, v):
        if not v or len(v) < 2:
            raise ValueError("Search term must be at least 2 characters")
        # Prevent injection: only allow safe characters
        if not re.match(r'^[a-zA-Z0-9\s\-\._]+$', v):
            raise ValueError("Search term contains invalid characters")
        return v

    @validator('category')
    def validate_category(cls, v):
        if v and v not in ["remote", "local", "dos", "webapps", "hardware", "multiple"]:
            raise ValueError("Invalid category")
        return v


class CveSearchRequest(BaseModel):
    keyword: str = ""
    cve_id: Optional[str] = None
    cvss_min: Optional[float] = None
    cvss_max: Optional[float] = None
    cpe: Optional[str] = None

    @validator('cve_id')
    def validate_cve_id(cls, v):
        if v and not re.match(r'^CVE-\d{4}-\d{4,}$', v, re.IGNORECASE):
            raise ValueError("Invalid CVE ID format (e.g., CVE-2023-1234)")
        return v

    @validator('cvss_min', 'cvss_max')
    def validate_cvss(cls, v):
        if v is not None and (v < 0 or v > 10):
            raise ValueError("CVSS score must be between 0 and 10")
        return v
                
class SmbclientRequest(BaseModel):
    host: str
    share: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    additional_args: str = ""

    @validator('host')
    def validate_host(cls, v):
        is_valid, msg = CommandValidator.validate_target(v)
        if not is_valid:
            raise ValueError(msg)
        return v

class SnmpwalkRequest(BaseModel):
    target: str
    community: str = "public"
    version: str = "2c"   # 1, 2c, 3
    oid: str = "1.3.6.1.2.1.1"   # system info
    additional_args: str = ""

    @validator('target')
    def validate_target(cls, v):
        is_valid, msg = CommandValidator.validate_target(v)
        if not is_valid:
            raise ValueError(msg)
        return v

    @validator('version')
    def validate_version(cls, v):
        if v not in ["1", "2c", "3"]:
            raise ValueError("SNMP version must be 1, 2c, or 3")
        return v

class LdapsearchRequest(BaseModel):
    host: str
    port: int = 389
    base_dn: str = ""
    filter: str = "(objectClass=*)"
    attributes: str = ""
    bind_dn: str = ""
    bind_password: str = ""
    additional_args: str = ""

    @validator('host')
    def validate_host(cls, v):
        is_valid, msg = CommandValidator.validate_target(v)
        if not is_valid:
            raise ValueError(msg)
        return v

    @validator('port')
    def validate_port(cls, v):
        if v < 1 or v > 65535:
            raise ValueError("Port must be between 1 and 65535")
        return v

class ResponderRequest(BaseModel):
    interface: str = "eth0"
    additional_args: str = ""

    @validator('interface')
    def validate_interface(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError("Invalid interface name")
        return v

class BloodhoundRequest(BaseModel):
    domain: str
    username: str
    password: str
    nameserver: Optional[str] = None
    collection_method: str = "all"
    additional_args: str = ""

    @validator('domain')
    def validate_domain(cls, v):
        if not re.match(r'^[a-z0-9\.\-]+$', v, re.IGNORECASE):
            raise ValueError("Invalid domain format")
        return v

    @validator('collection_method')
    def validate_collection_method(cls, v):
        allowed = ["all", "session", "trusts", "acl", "objectprops", "group", "localadmin", "rdp", "dcom", "psremote"]
        if v not in allowed:
            raise ValueError(f"collection_method must be one of: {', '.join(allowed)}")
        return v

class WhatwebRequest(BaseModel):
    target: str
    additional_args: str = ""

    @validator('target')
    def validate_target(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError("Target must start with http:// or https://")
        return v

class CewlRequest(BaseModel):
    target: str
    depth: int = 2
    min_word_length: int = 3
    additional_args: str = ""

    @validator('target')
    def validate_target(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError("Target must start with http:// or https://")
        return v

    @validator('depth')
    def validate_depth(cls, v):
        if v < 1 or v > 10:
            raise ValueError("Depth must be between 1 and 10")
        return v

class MedusaRequest(BaseModel):
    host: str
    service: str
    username: str = ""
    username_file: str = ""
    password: str = ""
    password_file: str = ""
    additional_args: str = ""

    @validator('host')
    def validate_host(cls, v):
        is_valid, msg = CommandValidator.validate_target(v)
        if not is_valid:
            raise ValueError(msg)
        return v

    @validator('service')
    def validate_service(cls, v):
        allowed = ["ssh", "ftp", "http", "https", "smb", "rdp", "mysql", "postgresql", "telnet", "vnc"]
        if v not in allowed:
            raise ValueError(f"Service must be one of: {', '.join(allowed)}")
        return v

class DnsreconRequest(BaseModel):
    target: str
    type: str = "std"   # std, brt, axfr, etc.
    additional_args: str = ""

    @validator('target')
    def validate_target(cls, v):
        # can be domain or IP
        is_valid, msg = CommandValidator.validate_target(v)
        if not is_valid:
            # allow domain without IP validation
            if not re.match(r'^[a-z0-9][a-z0-9\.-]+\.[a-z]{2,}$', v, re.IGNORECASE):
                raise ValueError("Invalid domain/IP format")
        return v

    @validator('type')
    def validate_type(cls, v):
        allowed = ["std", "brt", "axfr", "srv", "zonewalk"]
        if v not in allowed:
            raise ValueError(f"Type must be one of: {', '.join(allowed)}")
        return v                
                
class SessionInitRequest(BaseModel):
    session_id: Optional[str] = None
    output_dir: Optional[str] = None


# ============================================================================
# SECURE COMMAND EXECUTOR
# ============================================================================

class SecureCommandExecutor:
    """Executes commands safely with argument lists (NO SHELL)."""
    
    def __init__(self):
        self.active_processes: Dict[int, asyncio.subprocess.Process] = {}
        self.output_limit = Config.MAX_OUTPUT_SIZE_MB * 1024 * 1024
    
    async def execute(
        self, 
        command_parts: List[str], 
        timeout: int = None,
        cwd: Optional[Path] = None,
        env: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Execute command with argument list (NO SHELL).
        
        Args:
            command_parts: List of command and arguments (e.g., ["nmap", "-sV", "192.168.1.1"])
            timeout: Maximum execution time in seconds
            cwd: Working directory
            env: Environment variables (will be sanitized)
        
        Returns:
            Dict with stdout, stderr, return_code, success
        """
        if not command_parts:
            return {
                "success": False, 
                "stdout": "", 
                "stderr": "Empty command", 
                "return_code": -1
            }
        
        timeout = timeout or Config.COMMAND_TIMEOUT
        
        # Validate command
        tool = command_parts[0]
        is_valid, error, sanitized_args = CommandValidator.validate_command_args(
            tool, command_parts[1:]
        )
        
        if not is_valid:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Validation failed: {error}",
                "return_code": -1
            }
        
        # Build safe command
        safe_command = [tool] + sanitized_args
        
        # Sanitize environment
        safe_env = os.environ.copy()
        if env:
            safe_env.update(env)
        
        # Remove dangerous environment variables
        dangerous_env_vars = [
            'BASH_ENV', 'ENV', 'LD_PRELOAD', 'LD_LIBRARY_PATH',
            'LD_DEBUG', 'NODE_OPTIONS', 'PERL5OPT', 'PYTHONPATH'
        ]
        for var in dangerous_env_vars:
            safe_env.pop(var, None)
        
        # Execute
        try:
            process = await asyncio.create_subprocess_exec(
                *safe_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(cwd) if cwd else None,
                env=safe_env,
                limit=self.output_limit
            )
            
            self.active_processes[process.pid] = process
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    process.kill()
                
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": f"Command timed out after {timeout} seconds",
                    "return_code": -1,
                    "timed_out": True
                }
            finally:
                self.active_processes.pop(process.pid, None)
            
            # Decode output
            stdout_str = stdout.decode('utf-8', errors='replace')
            stderr_str = stderr.decode('utf-8', errors='replace')
            
            # Filter for poisoning
            filtered_stdout, stdout_warnings = AntiPoisoningFilter.filter_output(stdout_str)
            filtered_stderr, stderr_warnings = AntiPoisoningFilter.filter_output(stderr_str)
            
            # Validate integrity
            is_clean, issues = AntiPoisoningFilter.validate_output_integrity(
                filtered_stdout + filtered_stderr
            )
            
            return {
                "success": process.returncode == 0,
                "stdout": filtered_stdout,
                "stderr": filtered_stderr,
                "return_code": process.returncode,
                "timed_out": False,
                "warnings": stdout_warnings + stderr_warnings,
                "integrity_issues": issues if not is_clean else []
            }
            
        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Execution error: {str(e)}",
                "return_code": -1,
                "timed_out": False
            }
    
    async def kill_all(self):
        """Terminate all running processes."""
        for pid, process in self.active_processes.items():
            try:
                process.terminate()
            except Exception:
                pass
        self.active_processes.clear()


# ============================================================================
# SESSION MANAGER
# ============================================================================

class SessionManager:
    """Manages active sessions with encryption and rate limiting."""
    
    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.rate_limiters: Dict[str, RateLimiter] = {}
    
    def create_session(self, session_id: Optional[str] = None) -> str:
        """Create a new session."""
        if not session_id:
            session_id = secrets.token_urlsafe(32)
        
        crypto = SecureCrypto(session_id) if Config.ENCRYPTION_ENABLED else None
        
        self.sessions[session_id] = {
            "created_at": datetime.utcnow(),
            "crypto": crypto,
            "output_dir": None,
            "last_activity": datetime.utcnow(),
            "tool_history": []
        }
        self.rate_limiters[session_id] = RateLimiter(
            rate=Config.MAX_REQUESTS_PER_SECOND,
            burst=Config.MAX_BURST
        )
        
        return session_id
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session data."""
        session = self.sessions.get(session_id)
        if session:
            session["last_activity"] = datetime.utcnow()
        return session
    
    def set_output_dir(self, session_id: str, output_dir: Path):
        """Set output directory for a session."""
        if session_id in self.sessions:
            self.sessions[session_id]["output_dir"] = output_dir
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "raw_outputs").mkdir(exist_ok=True)
            (output_dir / "encrypted").mkdir(exist_ok=True)
    
    async def check_rate_limit(self, session_id: str) -> bool:
        """Check if request is within rate limits."""
        limiter = self.rate_limiters.get(session_id)
        if not limiter:
            limiter = RateLimiter(
                rate=Config.MAX_REQUESTS_PER_SECOND,
                burst=Config.MAX_BURST
            )
            self.rate_limiters[session_id] = limiter
        return await limiter.acquire()
    
    def add_to_history(self, session_id: str, tool_name: str, command: str, success: bool):
        """Add tool execution to session history."""
        session = self.sessions.get(session_id)
        if session:
            session["tool_history"].append({
                "tool": tool_name,
                "command": command[:200],
                "success": success,
                "timestamp": datetime.utcnow().isoformat()
            })
            # Keep last 100 entries
            if len(session["tool_history"]) > 100:
                session["tool_history"] = session["tool_history"][-100:]
    
    def cleanup_old_sessions(self):
        """Remove sessions older than timeout."""
        cutoff = datetime.utcnow() - timedelta(hours=Config.SESSION_TIMEOUT_HOURS)
        to_remove = [
            sid for sid, data in self.sessions.items()
            if data["last_activity"] < cutoff
        ]
        for sid in to_remove:
            del self.sessions[sid]
            self.rate_limiters.pop(sid, None)
        
        # Also enforce maximum sessions
        if len(self.sessions) > 100:
            # Remove oldest sessions
            sorted_sessions = sorted(
                self.sessions.items(),
                key=lambda x: x[1]["last_activity"]
            )
            for sid, _ in sorted_sessions[:-100]:
                del self.sessions[sid]
                self.rate_limiters.pop(sid, None)


# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

# Create FastAPI app
app = FastAPI(
    title="Secure Pentest API",
    description="Secure API for penetration testing tools - NO SHELL INJECTION",
    version="4.0.0"
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:*", "http://127.0.0.1:*"],
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "::1"]
)

# Global components
executor = SecureCommandExecutor()
session_manager = SessionManager()
security = HTTPBearer(auto_error=False)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr
)
logger = logging.getLogger(__name__)


# ============================================================================
# AUTHENTICATION DEPENDENCIES
# ============================================================================

async def verify_auth(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Verify API key authentication."""
    if not Config.API_KEY:
        logger.warning("No API key configured - authentication disabled")
        return "no-auth"
    
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Use 'Authorization: Bearer <key>' header"
        )
    
    if credentials.credentials != Config.API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key"
        )
    
    return credentials.credentials


async def get_session_id(request: Request) -> str:
    """Get or create session ID from header."""
    session_id = request.headers.get("X-Session-ID")
    
    if not session_id:
        session_id = session_manager.create_session()
    else:
        existing = session_manager.get_session(session_id)
        if not existing:
            session_id = session_manager.create_session(session_id)
    
    # Check rate limit
    if not await session_manager.check_rate_limit(session_id):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Max {Config.MAX_REQUESTS_PER_SECOND} requests/second"
        )
    
    return session_id


# ============================================================================
# HEALTH AND STATUS ENDPOINTS
# ============================================================================

@app.get("/health")
async def health_check(auth: str = Depends(verify_auth)):
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "4.0.0",
        "secure_mode": True,
        "shell_execution": False,
        "encryption_enabled": Config.ENCRYPTION_ENABLED,
        "active_sessions": len(session_manager.sessions),
        "rate_limit": {
            "requests_per_second": Config.MAX_REQUESTS_PER_SECOND,
            "burst": Config.MAX_BURST
        }
    }


@app.get("/api/session/info")
async def session_info(
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Get current session information."""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {
        "session_id": session_id,
        "created_at": session["created_at"].isoformat(),
        "last_activity": session["last_activity"].isoformat(),
        "output_dir": str(session.get("output_dir")) if session.get("output_dir") else None,
        "encryption_enabled": Config.ENCRYPTION_ENABLED,
        "tool_count": len(session.get("tool_history", []))
    }


# ============================================================================
# SESSION MANAGEMENT ENDPOINTS
# ============================================================================

@app.post("/api/session/init")
async def init_session(
    request: SessionInitRequest,
    auth: str = Depends(verify_auth)
):
    """Initialize a session with output directory."""
    session_id = request.session_id
    output_dir = request.output_dir
    
    if not session_id:
        session_id = session_manager.create_session()
    else:
        existing = session_manager.get_session(session_id)
        if not existing:
            session_id = session_manager.create_session(session_id)
    
    if output_dir:
        output_path = Path(output_dir)
        if output_path.exists() or output_path.parent.exists():
            session_manager.set_output_dir(session_id, output_path)
    
    return {
        "session_id": session_id,
        "status": "ok",
        "encryption_enabled": Config.ENCRYPTION_ENABLED,
        "message": "Session initialized. Send X-Session-ID header with future requests."
    }


@app.post("/api/session/cleanup")
async def cleanup_sessions(auth: str = Depends(verify_auth)):
    """Manually trigger session cleanup."""
    old_count = len(session_manager.sessions)
    session_manager.cleanup_old_sessions()
    return {
        "status": "ok",
        "sessions_before": old_count,
        "sessions_after": len(session_manager.sessions)
    }


# ============================================================================
# TOOL EXECUTION ENDPOINTS
# ============================================================================

@app.post("/api/tools/nmap")
async def nmap_scan(
    request: NmapRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Execute nmap scan securely (NO SHELL)."""
    # Build command parts
    command_parts = ["nmap"]
    
    # Add scan type
    if request.scan_type:
        command_parts.extend(shlex.split(request.scan_type))
    
    # Add ports
    if request.ports:
        command_parts.extend(["-p", request.ports])
    
    # Add additional args
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))
    
    # Add target
    command_parts.append(request.target)
    
    logger.info(f"[{session_id[:8]}] nmap: {' '.join(command_parts)}")
    
    # Execute
    result = await executor.execute(command_parts, timeout=600)
    
    # Save to session
    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        
        # Save encrypted output
        if Config.ENCRYPTION_ENABLED and session.get("crypto"):
            crypto = session["crypto"]
            encrypted = crypto.encrypt_output(
                result["stdout"] + result["stderr"],
                "nmap",
                request.target
            )
            enc_file = output_dir / "encrypted" / f"nmap_{int(time.time())}.enc"
            enc_file.write_text(encrypted)
        
        # Save raw output (for compatibility)
        raw_file = output_dir / "raw_outputs" / f"nmap_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
    
    # Add to history
    session_manager.add_to_history(
        session_id, "nmap", " ".join(command_parts), result["success"]
    )
    
    return result


@app.post("/api/tools/gobuster")
async def gobuster_scan(
    request: GobusterRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Execute gobuster scan securely."""
    command_parts = ["gobuster", request.mode, "-u", request.url, "-w", request.wordlist]
    
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))
    
    logger.info(f"[{session_id[:8]}] gobuster: {' '.join(command_parts)}")
    
    result = await executor.execute(command_parts, timeout=600)
    
    # Save to session
    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"gobuster_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
        
        if Config.ENCRYPTION_ENABLED and session.get("crypto"):
            crypto = session["crypto"]
            encrypted = crypto.encrypt_output(
                result["stdout"] + result["stderr"],
                "gobuster",
                request.url
            )
            enc_file = output_dir / "encrypted" / f"gobuster_{int(time.time())}.enc"
            enc_file.write_text(encrypted)
    
    session_manager.add_to_history(
        session_id, "gobuster", " ".join(command_parts), result["success"]
    )
    
    return result


@app.post("/api/tools/dirb")
async def dirb_scan(
    request: DirbRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Execute dirb scan securely."""
    command_parts = ["dirb", request.url, request.wordlist]
    
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))
    
    logger.info(f"[{session_id[:8]}] dirb: {' '.join(command_parts)}")
    
    result = await executor.execute(command_parts, timeout=600)
    
    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"dirb_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
    
    session_manager.add_to_history(
        session_id, "dirb", " ".join(command_parts), result["success"]
    )
    
    return result


@app.post("/api/tools/ffuf")
async def ffuf_scan(
    request: FfufRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Execute ffuf scan securely."""
    command_parts = ["ffuf", "-u", request.url, "-w", request.wordlist, "-mc", request.match_code]
    
    if request.filter_size:
        command_parts.extend(["-fs", request.filter_size])
    
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))
    
    logger.info(f"[{session_id[:8]}] ffuf: {' '.join(command_parts)}")
    
    result = await executor.execute(command_parts, timeout=600)
    
    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"ffuf_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
    
    session_manager.add_to_history(
        session_id, "ffuf", " ".join(command_parts), result["success"]
    )
    
    return result


@app.post("/api/tools/nikto")
async def nikto_scan(
    request: NiktoRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Execute nikto scan securely."""
    command_parts = ["nikto", "-h", request.target]
    
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))
    
    logger.info(f"[{session_id[:8]}] nikto: {' '.join(command_parts)}")
    
    result = await executor.execute(command_parts, timeout=600)
    
    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"nikto_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
    
    session_manager.add_to_history(
        session_id, "nikto", " ".join(command_parts), result["success"]
    )
    
    return result


@app.post("/api/tools/sqlmap")
async def sqlmap_scan(
    request: SqlmapRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Execute sqlmap scan securely."""
    command_parts = ["sqlmap", "-u", request.url, "--batch"]
    
    if request.data:
        command_parts.extend(["--data", request.data])
    
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))
    
    logger.info(f"[{session_id[:8]}] sqlmap: {' '.join(command_parts)}")
    
    result = await executor.execute(command_parts, timeout=900)  # 15 min
    
    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"sqlmap_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
    
    session_manager.add_to_history(
        session_id, "sqlmap", " ".join(command_parts), result["success"]
    )
    
    return result


@app.post("/api/tools/hydra")
async def hydra_attack(
    request: HydraRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Execute hydra brute force securely."""
    command_parts = ["hydra", "-t", "4"]
    
    if request.username:
        command_parts.extend(["-l", request.username])
    elif request.username_file:
        command_parts.extend(["-L", request.username_file])
    
    if request.password:
        command_parts.extend(["-p", request.password])
    elif request.password_file:
        command_parts.extend(["-P", request.password_file])
    
    command_parts.extend([request.target, request.service])
    
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))
    
    logger.info(f"[{session_id[:8]}] hydra: {' '.join(command_parts)}")
    
    result = await executor.execute(command_parts, timeout=1800)  # 30 min
    
    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"hydra_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
    
    session_manager.add_to_history(
        session_id, "hydra", " ".join(command_parts), result["success"]
    )
    
    return result


@app.post("/api/tools/john")
async def john_crack(
    request: JohnRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Execute john the ripper securely."""
    command_parts = ["john"]
    
    if request.format_type:
        command_parts.extend([f"--format={request.format_type}"])
    
    if request.wordlist:
        command_parts.extend([f"--wordlist={request.wordlist}"])
    
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))
    
    command_parts.append(request.hash_file)
    
    logger.info(f"[{session_id[:8]}] john: {' '.join(command_parts)}")
    
    result = await executor.execute(command_parts, timeout=3600)  # 1 hour
    
    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"john_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
    
    session_manager.add_to_history(
        session_id, "john", " ".join(command_parts), result["success"]
    )
    
    return result


@app.post("/api/tools/wpscan")
async def wpscan_analyze(
    request: WpscanRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Execute wpscan securely."""
    command_parts = ["wpscan", "--url", request.url]
    
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))
    
    logger.info(f"[{session_id[:8]}] wpscan: {' '.join(command_parts)}")
    
    result = await executor.execute(command_parts, timeout=600)
    
    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"wpscan_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
    
    session_manager.add_to_history(
        session_id, "wpscan", " ".join(command_parts), result["success"]
    )
    
    return result


@app.post("/api/tools/enum4linux")
async def enum4linux_scan(
    request: Enum4linuxRequest,   # now uses the proper model
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Execute enum4linux SMB enumeration."""
    command_parts = ["enum4linux"]
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))
    command_parts.append(request.target)

    logger.info(f"[{session_id[:8]}] enum4linux: {' '.join(command_parts)}")
    result = await executor.execute(command_parts, timeout=300)

    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"enum4linux_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
        if Config.ENCRYPTION_ENABLED and session.get("crypto"):
            crypto = session["crypto"]
            encrypted = crypto.encrypt_output(result["stdout"] + result["stderr"], "enum4linux", request.target)
            enc_file = output_dir / "encrypted" / f"enum4linux_{int(time.time())}.enc"
            enc_file.write_text(encrypted)

    session_manager.add_to_history(session_id, "enum4linux", " ".join(command_parts), result["success"])
    return result

@app.post("/api/tools/curl")
async def curl_request(
    request: CurlRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Execute curl request securely."""
    command_parts = ["curl", "-X", request.method, "-s", "-i"]
    
    for key, value in request.headers.items():
        command_parts.extend(["-H", f"{key}: {value}"])
    
    if request.data:
        command_parts.extend(["-d", request.data])
    
    command_parts.append(request.url)
    
    logger.info(f"[{session_id[:8]}] curl: {' '.join(command_parts)}")
    
    result = await executor.execute(command_parts, timeout=120)
    
    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"curl_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
    
    return result


@app.post("/api/tools/netcat")
async def netcat_check(
    request: NetcatRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Test connectivity with netcat (safe mode only)."""
    command_parts = ["nc", "-vz", request.host, str(request.port)]
    
    logger.info(f"[{session_id[:8]}] netcat: {' '.join(command_parts)}")
    
    result = await executor.execute(command_parts, timeout=30)
    
    return result
    
    
@app.post("/api/tools/aircrack-ng")
async def aircrack_ng(
    request: Aircrack_ngRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    command_parts = ["aircrack-ng", request.wordlist, request.output_file]
    
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))
        
    logger.info(f"[{session_id[:8]} aircrack-ng: {' '.join(command_parts)}]")
    result = await executor.execute(command_parts, timeout=600)
    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"aircrack-ng_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
        
        
    session_manager.add_to_history(
        session_id, "aircrack-ng", " ".join(command_parts), result["success"]
    )
    
    return result  
      


@app.post("/api/tools/read_file")
async def read_file_secure(
    request: ReadFileRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Read file contents securely (no write operations)."""
    path = Path(request.path)
    
    # Verify file is within allowed bounds
    safe_dirs = ['/tmp', '/var/log', '/etc', '/usr/share']
    is_safe = any(str(path.resolve()).startswith(sd) for sd in safe_dirs)
    
    if not is_safe:
        raise HTTPException(
            status_code=403, 
            detail=f"Path not allowed. Must be in: {', '.join(safe_dirs)}"
        )
    
    # Check file size
    size = path.stat().st_size
    if size > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (>10MB)")
    
    try:
        if request.command == "head":
            lines = []
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                for i, line in enumerate(f):
                    if i >= request.max_lines:
                        break
                    lines.append(line.rstrip('\n'))
            content = '\n'.join(lines)
        elif request.command == "tail":
            # Read last N lines efficiently
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
                content = ''.join(lines[-request.max_lines:])
        else:  # cat
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
                # Limit output size
                if len(content) > 10 * 1024 * 1024:
                    content = content[:10 * 1024 * 1024] + "\n[TRUNCATED: File too large]"
        
        # Filter for poisoning
        filtered, warnings = AntiPoisoningFilter.filter_output(content)
        
        return {
            "success": True,
            "content": filtered,
            "path": str(path),
            "size_bytes": size,
            "warnings": warnings
        }
        
    except UnicodeDecodeError:
        # Try binary read for non-text files
        with open(path, 'rb') as f:
            binary_data = f.read(1024)  # Only first 1KB for binary
        return {
            "success": True,
            "content": f"[BINARY DATA - First 1KB in hex]\n{binary_data.hex()}",
            "path": str(path),
            "size_bytes": size,
            "is_binary": True
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "path": str(path)
        }


@app.post("/api/command")
async def generic_command(
    request: Request,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """
    Execute arbitrary command (use with extreme caution).
    This endpoint is restricted to whitelisted commands only.
    """
    data = await request.json()
    command = data.get("command", "")
    
    if not command:
        raise HTTPException(status_code=400, detail="Command required")
    
    # Parse command string into parts
    command_parts = shlex.split(command)
    
    if not command_parts:
        raise HTTPException(status_code=400, detail="Empty command")
    
    # Check if command is whitelisted
    tool = command_parts[0]
    if tool not in CommandValidator.ALLOWED_COMMANDS:
        raise HTTPException(
            status_code=403,
            detail=f"Command '{tool}' not in whitelist. Allowed: {', '.join(CommandValidator.ALLOWED_COMMANDS.keys())}"
        )
    
    logger.warning(f"[{session_id[:8]}] GENERIC COMMAND: {' '.join(command_parts)}")
    
    result = await executor.execute(command_parts, timeout=300)
    
    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"generic_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
    
    return result


@app.post("/api/decrypt")
async def decrypt_output(
    request: Request,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Decrypt previously encrypted output."""
    data = await request.json()
    encrypted = data.get("encrypted_data", "")
    
    if not Config.ENCRYPTION_ENABLED:
        raise HTTPException(status_code=400, detail="Encryption is disabled")
    
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    crypto = session.get("crypto")
    if not crypto:
        raise HTTPException(status_code=400, detail="No crypto for this session")
    
    decrypted, is_valid = crypto.decrypt_output(encrypted)
    
    if not is_valid:
        raise HTTPException(
            status_code=400, 
            detail="Integrity check failed - data may be tampered"
        )
    
    return {
        "success": True,
        "data": decrypted
    }
    
@app.post("/api/tools/amass")
async def amass_enum(
    request: AmassRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Subdomain enumeration with Amass."""
    command_parts = ["amass", "enum", "-d", request.target]
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))
    
    logger.info(f"[{session_id[:8]}] amass: {' '.join(command_parts)}")
    result = await executor.execute(command_parts, timeout=600)
    
    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"amass_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
        if Config.ENCRYPTION_ENABLED and session.get("crypto"):
            crypto = session["crypto"]
            encrypted = crypto.encrypt_output(result["stdout"] + result["stderr"], "amass", request.target)
            enc_file = output_dir / "encrypted" / f"amass_{int(time.time())}.enc"
            enc_file.write_text(encrypted)
    
    session_manager.add_to_history(session_id, "amass", " ".join(command_parts), result["success"])
    return result


@app.post("/api/tools/subfinder")
async def subfinder_enum(
    request: SubfinderRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Subdomain enumeration with Subfinder."""
    command_parts = ["subfinder", "-d", request.target]
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))
    
    logger.info(f"[{session_id[:8]}] subfinder: {' '.join(command_parts)}")
    result = await executor.execute(command_parts, timeout=300)
    
    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"subfinder_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
    
    session_manager.add_to_history(session_id, "subfinder", " ".join(command_parts), result["success"])
    return result


@app.post("/api/tools/nuclei")
async def nuclei_scan(
    request: NucleiRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Vulnerability scan with Nuclei."""
    command_parts = ["nuclei", "-target", request.target, "-silent"]
    
    if request.templates:
        command_parts.extend(["-templates", request.templates])
    if request.severity:
        command_parts.extend(["-severity", request.severity])
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))
    
    logger.info(f"[{session_id[:8]}] nuclei: {' '.join(command_parts)}")
    result = await executor.execute(command_parts, timeout=600)
    
    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"nuclei_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
        if Config.ENCRYPTION_ENABLED and session.get("crypto"):
            crypto = session["crypto"]
            encrypted = crypto.encrypt_output(result["stdout"] + result["stderr"], "nuclei", request.target)
            enc_file = output_dir / "encrypted" / f"nuclei_{int(time.time())}.enc"
            enc_file.write_text(encrypted)
    
    session_manager.add_to_history(session_id, "nuclei", " ".join(command_parts), result["success"])
    return result


@app.post("/api/tools/masscan")
async def masscan_scan(
    request: MasscanRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """High-speed port scan with Masscan."""
    command_parts = [
        "masscan", request.target,
        "-p", request.ports,
        "--rate", str(request.rate),
        "--wait", "0"
    ]
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))
    
    logger.info(f"[{session_id[:8]}] masscan: {' '.join(command_parts)}")
    result = await executor.execute(command_parts, timeout=300)
    
    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"masscan_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
    
    session_manager.add_to_history(session_id, "masscan", " ".join(command_parts), result["success"])
    return result


@app.post("/api/tools/wfuzz")
async def wfuzz_scan(
    request: WfuzzRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Web fuzzing with Wfuzz."""
    command_parts = [
        "wfuzz", "-w", request.wordlist,
        "--hc", request.filter_code if request.filter_code else "404",
        request.url.replace("FUZZ", f"FUZZ{request.payload}")  # wfuzz uses FUZZ by default
    ]
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))
    
    logger.info(f"[{session_id[:8]}] wfuzz: {' '.join(command_parts)}")
    result = await executor.execute(command_parts, timeout=600)
    
    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"wfuzz_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
    
    session_manager.add_to_history(session_id, "wfuzz", " ".join(command_parts), result["success"])
    return result

@app.post("/api/tools/airodump-ng")
async def airodump_ng(
    request: AirodumpNgRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Capture Wi-Fi packets with airodump-ng."""
    command_parts = ["airodump-ng", request.interface]
    if request.bssid:
        command_parts.extend(["--bssid", request.bssid])
    if request.channel:
        command_parts.extend(["-c", str(request.channel)])
    if request.output_file:
        command_parts.extend(["-w", request.output_file])
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))

    logger.info(f"[{session_id[:8]}] airodump-ng: {' '.join(command_parts)}")
    result = await executor.execute(command_parts, timeout=600)

    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"airodump-ng_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
        if Config.ENCRYPTION_ENABLED and session.get("crypto"):
            crypto = session["crypto"]
            encrypted = crypto.encrypt_output(result["stdout"] + result["stderr"], "airodump-ng", request.interface)
            enc_file = output_dir / "encrypted" / f"airodump-ng_{int(time.time())}.enc"
            enc_file.write_text(encrypted)

    session_manager.add_to_history(session_id, "airodump-ng", " ".join(command_parts), result["success"])
    return result


@app.post("/api/tools/wifite")
async def wifite_attack(
    request: WifiteRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Automated Wi-Fi attack with Wifite."""
    command_parts = ["wifite", "-i", request.interface, "-all"]
    if request.target_bssid:
        command_parts.extend(["-b", request.target_bssid])
    if request.target_essid:
        command_parts.extend(["-e", request.target_essid])
    if request.attack_type == "wpa":
        command_parts.append("--wpa")
    elif request.attack_type == "wps":
        command_parts.append("--wps")
    # "all" is default, no flag needed
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))

    logger.info(f"[{session_id[:8]}] wifite: {' '.join(command_parts)}")
    result = await executor.execute(command_parts, timeout=1800)  # 30 min

    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"wifite_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
        if Config.ENCRYPTION_ENABLED and session.get("crypto"):
            crypto = session["crypto"]
            encrypted = crypto.encrypt_output(result["stdout"] + result["stderr"], "wifite", request.interface)
            enc_file = output_dir / "encrypted" / f"wifite_{int(time.time())}.enc"
            enc_file.write_text(encrypted)

    session_manager.add_to_history(session_id, "wifite", " ".join(command_parts), result["success"])
    return result


@app.post("/api/tools/airmon-ng")
async def airmon_ng(
    request: AirmonNgRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Control Wi-Fi interface monitor mode with airmon-ng."""
    command_parts = ["airmon-ng", request.action, request.interface]
    if request.action == "start":
        # Optionally add a channel? We'll let user override via additional args, but we keep it simple.
        pass

    logger.info(f"[{session_id[:8]}] airmon-ng: {' '.join(command_parts)}")
    result = await executor.execute(command_parts, timeout=30)

    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"airmon-ng_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])

    session_manager.add_to_history(session_id, "airmon-ng", " ".join(command_parts), result["success"])
    return result

@app.post("/api/tools/hashcat")
async def hashcat_crack(
    request: HashcatRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Password cracking with Hashcat (GPU accelerated)."""
    command_parts = [
        "hashcat", "-m", request.hash_type,
        "-a", "0",
        request.hash_file,
        request.wordlist,
        "--force"
    ]
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))
    
    logger.info(f"[{session_id[:8]}] hashcat: {' '.join(command_parts)}")
    result = await executor.execute(command_parts, timeout=3600)  # 1 hour
    
    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"hashcat_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
        if Config.ENCRYPTION_ENABLED and session.get("crypto"):
            crypto = session["crypto"]
            encrypted = crypto.encrypt_output(result["stdout"] + result["stderr"], "hashcat", request.hash_file)
            enc_file = output_dir / "encrypted" / f"hashcat_{int(time.time())}.enc"
            enc_file.write_text(encrypted)
    
    session_manager.add_to_history(session_id, "hashcat", " ".join(command_parts), result["success"])
    return result

@app.post("/api/tools/smbclient")
async def smbclient_enum(
    request: SmbclientRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """SMB share enumeration with smbclient."""
    command_parts = ["smbclient", "-L", request.host]
    if request.share:
        command_parts = ["smbclient", f"//{request.host}/{request.share}", "-N"]   # -N for no password
    if request.username:
        command_parts.extend(["-U", request.username])
    if request.password:
        command_parts.extend(["-P", request.password])
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))

    logger.info(f"[{session_id[:8]}] smbclient: {' '.join(command_parts)}")
    result = await executor.execute(command_parts, timeout=120)

    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"smbclient_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
        if Config.ENCRYPTION_ENABLED and session.get("crypto"):
            crypto = session["crypto"]
            encrypted = crypto.encrypt_output(result["stdout"] + result["stderr"], "smbclient", request.host)
            enc_file = output_dir / "encrypted" / f"smbclient_{int(time.time())}.enc"
            enc_file.write_text(encrypted)

    session_manager.add_to_history(session_id, "smbclient", " ".join(command_parts), result["success"])
    return result


@app.post("/api/tools/snmpwalk")
async def snmpwalk_scan(
    request: SnmpwalkRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """SNMP MIB walk with snmpwalk."""
    command_parts = ["snmpwalk", "-v", request.version, "-c", request.community, request.target, request.oid]
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))

    logger.info(f"[{session_id[:8]}] snmpwalk: {' '.join(command_parts)}")
    result = await executor.execute(command_parts, timeout=120)

    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"snmpwalk_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
        if Config.ENCRYPTION_ENABLED and session.get("crypto"):
            crypto = session["crypto"]
            encrypted = crypto.encrypt_output(result["stdout"] + result["stderr"], "snmpwalk", request.target)
            enc_file = output_dir / "encrypted" / f"snmpwalk_{int(time.time())}.enc"
            enc_file.write_text(encrypted)

    session_manager.add_to_history(session_id, "snmpwalk", " ".join(command_parts), result["success"])
    return result


@app.post("/api/tools/ldapsearch")
async def ldapsearch_query(
    request: LdapsearchRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """LDAP query with ldapsearch."""
    command_parts = ["ldapsearch", "-x", "-H", f"ldap://{request.host}:{request.port}"]
    if request.base_dn:
        command_parts.extend(["-b", request.base_dn])
    if request.filter:
        command_parts.extend(["-s", "sub", request.filter])  # sub for subtree
    if request.attributes:
        command_parts.append(request.attributes)
    if request.bind_dn:
        command_parts.extend(["-D", request.bind_dn])
        if request.bind_password:
            command_parts.extend(["-w", request.bind_password])
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))

    logger.info(f"[{session_id[:8]}] ldapsearch: {' '.join(command_parts)}")
    result = await executor.execute(command_parts, timeout=120)

    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"ldapsearch_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
        if Config.ENCRYPTION_ENABLED and session.get("crypto"):
            crypto = session["crypto"]
            encrypted = crypto.encrypt_output(result["stdout"] + result["stderr"], "ldapsearch", request.host)
            enc_file = output_dir / "encrypted" / f"ldapsearch_{int(time.time())}.enc"
            enc_file.write_text(encrypted)

    session_manager.add_to_history(session_id, "ldapsearch", " ".join(command_parts), result["success"])
    return result


@app.post("/api/tools/responder")
async def responder_capture(
    request: ResponderRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Start Responder to capture NetNTLM hashes."""
    command_parts = ["responder", "-I", request.interface, "--basic", "--lm", "--wpad"]
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))

    logger.info(f"[{session_id[:8]}] responder: {' '.join(command_parts)}")
    # Responder runs forever; we need to limit runtime or background it.
    # For safety, we'll run with a timeout (e.g., 300s) and kill.
    result = await executor.execute(command_parts, timeout=300)  # 5 minutes

    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"responder_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
        if Config.ENCRYPTION_ENABLED and session.get("crypto"):
            crypto = session["crypto"]
            encrypted = crypto.encrypt_output(result["stdout"] + result["stderr"], "responder", request.interface)
            enc_file = output_dir / "encrypted" / f"responder_{int(time.time())}.enc"
            enc_file.write_text(encrypted)

    session_manager.add_to_history(session_id, "responder", " ".join(command_parts), result["success"])
    return result


@app.post("/api/tools/bloodhound")
async def bloodhound_collect(
    request: BloodhoundRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Collect Active Directory data for BloodHound."""
    command_parts = [
        "bloodhound-python",
        "-d", request.domain,
        "-u", request.username,
        "-p", request.password,
        "-c", request.collection_method,
        "--zip"
    ]
    if request.nameserver:
        command_parts.extend(["-ns", request.nameserver])
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))

    logger.info(f"[{session_id[:8]}] bloodhound: {' '.join(command_parts)}")
    result = await executor.execute(command_parts, timeout=600)  # 10 min

    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"bloodhound_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
        if Config.ENCRYPTION_ENABLED and session.get("crypto"):
            crypto = session["crypto"]
            encrypted = crypto.encrypt_output(result["stdout"] + result["stderr"], "bloodhound", request.domain)
            enc_file = output_dir / "encrypted" / f"bloodhound_{int(time.time())}.enc"
            enc_file.write_text(encrypted)

    session_manager.add_to_history(session_id, "bloodhound", " ".join(command_parts), result["success"])
    return result


@app.post("/api/tools/whatweb")
async def whatweb_identify(
    request: WhatwebRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Web technology fingerprinting with whatweb."""
    command_parts = ["whatweb", request.target]
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))

    logger.info(f"[{session_id[:8]}] whatweb: {' '.join(command_parts)}")
    result = await executor.execute(command_parts, timeout=120)

    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"whatweb_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
        if Config.ENCRYPTION_ENABLED and session.get("crypto"):
            crypto = session["crypto"]
            encrypted = crypto.encrypt_output(result["stdout"] + result["stderr"], "whatweb", request.target)
            enc_file = output_dir / "encrypted" / f"whatweb_{int(time.time())}.enc"
            enc_file.write_text(encrypted)

    session_manager.add_to_history(session_id, "whatweb", " ".join(command_parts), result["success"])
    return result


@app.post("/api/tools/cewl")
async def cewl_generate(
    request: CewlRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Generate custom wordlist with CeWL."""
    command_parts = ["cewl", request.target, "-d", str(request.depth), "-m", str(request.min_word_length)]
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))

    logger.info(f"[{session_id[:8]}] cewl: {' '.join(command_parts)}")
    result = await executor.execute(command_parts, timeout=300)

    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"cewl_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
        if Config.ENCRYPTION_ENABLED and session.get("crypto"):
            crypto = session["crypto"]
            encrypted = crypto.encrypt_output(result["stdout"] + result["stderr"], "cewl", request.target)
            enc_file = output_dir / "encrypted" / f"cewl_{int(time.time())}.enc"
            enc_file.write_text(encrypted)

    session_manager.add_to_history(session_id, "cewl", " ".join(command_parts), result["success"])
    return result


@app.post("/api/tools/medusa")
async def medusa_bruteforce(
    request: MedusaRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Brute‑force with Medusa."""
    command_parts = ["medusa", "-h", request.host, "-s", request.service]
    if request.username:
        command_parts.extend(["-u", request.username])
    elif request.username_file:
        command_parts.extend(["-U", request.username_file])
    if request.password:
        command_parts.extend(["-p", request.password])
    elif request.password_file:
        command_parts.extend(["-P", request.password_file])
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))

    logger.info(f"[{session_id[:8]}] medusa: {' '.join(command_parts)}")
    result = await executor.execute(command_parts, timeout=1800)  # 30 min

    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"medusa_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
        if Config.ENCRYPTION_ENABLED and session.get("crypto"):
            crypto = session["crypto"]
            encrypted = crypto.encrypt_output(result["stdout"] + result["stderr"], "medusa", request.host)
            enc_file = output_dir / "encrypted" / f"medusa_{int(time.time())}.enc"
            enc_file.write_text(encrypted)

    session_manager.add_to_history(session_id, "medusa", " ".join(command_parts), result["success"])
    return result


@app.post("/api/tools/dnsrecon")
async def dnsrecon_enum(
    request: DnsreconRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """DNS enumeration with dnsrecon."""
    command_parts = ["dnsrecon", "-d", request.target, "-t", request.type]
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))

    logger.info(f"[{session_id[:8]}] dnsrecon: {' '.join(command_parts)}")
    result = await executor.execute(command_parts, timeout=300)

    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"dnsrecon_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
        if Config.ENCRYPTION_ENABLED and session.get("crypto"):
            crypto = session["crypto"]
            encrypted = crypto.encrypt_output(result["stdout"] + result["stderr"], "dnsrecon", request.target)
            enc_file = output_dir / "encrypted" / f"dnsrecon_{int(time.time())}.enc"
            enc_file.write_text(encrypted)

    session_manager.add_to_history(session_id, "dnsrecon", " ".join(command_parts), result["success"])
    return result
    
# ============================================================================
# CVE ENDPOINT (Preserved from original)
# ============================================================================

@app.post("/api/cve/search")
async def search_cve_enhanced(
    request: CveSearchRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """
    Search for CVEs using NVD API with advanced filters.
    Supports CVE ID lookup, keyword, CVSS range, and CPE matching.
    """
    import requests

    # If CVE ID is provided, fetch it directly
    if request.cve_id:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={request.cve_id}"
    else:
        params = {"resultsPerPage": 20}
        if request.keyword:
            params["keywordSearch"] = request.keyword
        if request.cpe:
            params["cpeName"] = request.cpe
        if request.cvss_min is not None or request.cvss_max is not None:
            # NVD API uses 'cvssV3Severity' or 'cvssV2Severity' – but we can filter after.
            # We'll fetch and then filter locally for more flexibility.
            pass
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        try:
            resp = requests.get(url, params=params, timeout=30)
            if resp.status_code != 200:
                return {"cves": [], "error": f"NVD API error: {resp.status_code}"}
            data = resp.json()
        except Exception as e:
            return {"cves": [], "error": str(e)}

    # Parse results
    cves = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln["cve"]
        # Apply CVSS filter (if requested)
        if request.cvss_min is not None or request.cvss_max is not None:
            metrics = cve.get("metrics", {})
            # Prefer CVSS v3.1, then v3.0, then v2
            cvss_data = None
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
            elif "cvssMetricV2" in metrics:
                cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            if cvss_data:
                score = cvss_data.get("baseScore", 0)
                if request.cvss_min is not None and score < request.cvss_min:
                    continue
                if request.cvss_max is not None and score > request.cvss_max:
                    continue

        # Extract description
        desc = ""
        for d in cve.get("descriptions", []):
            if d["lang"] == "en":
                desc = d["value"][:300]
                break

        # Get CVSS score for display
        metrics = cve.get("metrics", {})
        cvss_score = None
        if "cvssMetricV31" in metrics:
            cvss_score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore")
        elif "cvssMetricV30" in metrics:
            cvss_score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore")
        elif "cvssMetricV2" in metrics:
            cvss_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore")

        cves.append({
            "id": cve["id"],
            "description": desc,
            "cvss_score": cvss_score,
            "published": cve.get("published", ""),
            "references": [ref["url"] for ref in cve.get("references", [])[:3]]
        })

    # Store in session history (CVE search is not a tool, but we can log it)
    session_manager.add_to_history(session_id, "cve_search", f"search {request.cve_id or request.keyword}", True)
    return {"cves": cves, "count": len(cves)}

@app.post("/api/tools/searchsploit")
async def searchsploit_search(
    request: SearchsploitRequest,
    session_id: str = Depends(get_session_id),
    auth: str = Depends(verify_auth)
):
    """Search exploit database with searchsploit."""
    command_parts = ["searchsploit", "--color"]
    if request.category:
        command_parts.extend(["-c", request.category])
    if request.exact:
        command_parts.append("-e")
    if request.additional_args:
        command_parts.extend(shlex.split(request.additional_args))
    command_parts.append(request.term)

    logger.info(f"[{session_id[:8]}] searchsploit: {' '.join(command_parts)}")
    result = await executor.execute(command_parts, timeout=60)

    session = session_manager.get_session(session_id)
    if session and session.get("output_dir"):
        output_dir = session["output_dir"]
        raw_file = output_dir / "raw_outputs" / f"searchsploit_{int(time.time())}.txt"
        raw_file.write_text(result["stdout"] + result["stderr"])
        if Config.ENCRYPTION_ENABLED and session.get("crypto"):
            crypto = session["crypto"]
            encrypted = crypto.encrypt_output(result["stdout"] + result["stderr"], "searchsploit", request.term)
            enc_file = output_dir / "encrypted" / f"searchsploit_{int(time.time())}.enc"
            enc_file.write_text(encrypted)

    session_manager.add_to_history(session_id, "searchsploit", " ".join(command_parts), result["success"])
    return result
    
# ============================================================================
# SHUTDOWN HANDLER
# ============================================================================

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("Shutting down server...")
    await executor.kill_all()
    logger.info("All processes terminated")


# ============================================================================
# MAIN
# ============================================================================

def parse_args():
    parser = argparse.ArgumentParser(description="Secure Pentest API Server")
    parser.add_argument("--host", type=str, default=Config.HOST)
    parser.add_argument("--port", type=int, default=Config.PORT)
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload (development only)")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    
    # Validate configuration
    Config.validate()
    
    print("=" * 70)
    print("SECURE PENTEST API SERVER v4.0")
    print("=" * 70)
    print(f"Host: {args.host}")
    print(f"Port: {args.port}")
    print(f"Shell Execution: DISABLED (secure mode)")
    print(f"Encryption: {'ENABLED' if Config.ENCRYPTION_ENABLED else 'DISABLED'}")
    print(f"Rate Limit: {Config.MAX_REQUESTS_PER_SECOND} req/sec (burst: {Config.MAX_BURST})")
    print(f"Auth: {'ENABLED' if Config.API_KEY else 'DISABLED (WARNING!)'}")
    print("=" * 70)
    print("\n⚠️  IMPORTANT: Set PENTEST_API_KEY in .env file for production!")
    print("=" * 70)
    
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info"
    )
