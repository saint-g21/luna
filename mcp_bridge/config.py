#!/usr/bin/env python3
"""
Central configuration loader with defaults and deep merge.
"""

import json
import os
from copy import deepcopy

DEFAULT_CONFIG = {
    "ollama": {
        "model": "llama3.2:1b",
        "base_url": "http://localhost:11434/v1",
        "timeout": 300
    },
    "kali_api": {
        "host": "127.0.0.1",
        "port": 22163
    },
    "mcp_server_command": ["fastmcp", "run", "client0.py"],
    "database_path": "knowledge.db",
    "cheatsheet_file": "pentest_cheatsheet.md",
    "cve": {
        "enabled": True,
        "nvd_api_key": "",
        "cache_ttl_hours": 24
    },
    "encryption": {
        "enabled": True,
        "key_file": ".encryption_key"
    },
    "autonomous": {
        "max_iterations": 15,
        "auto_continue": True,
        "session_memory_ttl_hours": 24
    },
    "command_timeout": 600  # seconds
}

def deep_merge(base, override):
    """Recursively merge override dict into base dict."""
    result = deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result

def load_config(config_path="config.json"):
    config = deepcopy(DEFAULT_CONFIG)
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            user_config = json.load(f)
            config = deep_merge(config, user_config)
    return config

# Global config instance
config = load_config()
