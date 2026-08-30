#!/usr/bin/env python3
"""
Encryption utilities using Fernet (symmetric).
"""

import os
from cryptography.fernet import Fernet

def get_cipher(key_file: str = ".encryption_key") -> Fernet:
    """Load or generate a Fernet key and return a cipher."""
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        # Restrict permissions on key file (Unix only)
        os.chmod(key_file, 0o600)
    return Fernet(key)

def encrypt_value(cipher: Fernet, value: str) -> str:
    """Encrypt a string and return base64 encoded bytes as string."""
    return cipher.encrypt(value.encode()).decode()

def decrypt_value(cipher: Fernet, value: str) -> str:
    """Decrypt a base64 encoded string back to plaintext."""
    return cipher.decrypt(value.encode()).decode()
