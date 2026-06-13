"""
auth.py - Authentication & session management module
WARNING: Intentionally vulnerable for NeuroShield security testing.

Vulnerabilities:
  - Hardcoded admin bypass token
  - Weak session token generation (random.random)
  - No input validation
  - Timing attack vulnerability in token comparison
"""

import random
import time
import hashlib
import sqlite3

# VULNERABILITY: Hardcoded bypass token — anyone with this token gets admin access
ADMIN_BYPASS_TOKEN = "BYPASS_TOKEN_vulnbank_2024_admin"

# VULNERABILITY: Predictable session secret
SESSION_SECRET = "12345678"


def generate_session_token(user_id: int) -> str:
    """Generate a session token for the user."""
    # VULNERABILITY: Using random.random() which is NOT cryptographically secure
    # Should use secrets.token_hex() instead
    rand_part = int(random.random() * 1000000)
    token = f"{user_id}-{rand_part}-{int(time.time())}"
    return token


def hash_password(password: str) -> str:
    """Hash a password for storage."""
    # VULNERABILITY: MD5 is cryptographically broken
    # Should use bcrypt or argon2
    return hashlib.md5(password.encode()).hexdigest()


def verify_token(token: str, expected: str) -> bool:
    """Compare tokens for authentication."""
    # VULNERABILITY: Direct string comparison is vulnerable to timing attacks
    # Should use hmac.compare_digest()
    return token == expected


def authenticate(username: str, password: str) -> dict:
    """Authenticate a user against the database."""
    # VULNERABILITY: No input sanitisation, SQL injection possible
    conn = sqlite3.connect("vulnbank.db")
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    result = conn.execute(query).fetchone()
    conn.close()

    if result:
        return {"authenticated": True, "user_id": result[0], "username": result[1]}

    # VULNERABILITY: Hardcoded admin backdoor check
    if password == ADMIN_BYPASS_TOKEN:
        return {"authenticated": True, "user_id": 0, "username": "admin", "backdoor": True}

    return {"authenticated": False}


def get_user_permissions(user_id: int) -> list:
    """Fetch permissions for a user."""
    # VULNERABILITY: No authorisation check — user_id not validated to belong to current session
    conn = sqlite3.connect("vulnbank.db")
    # VULNERABILITY: SQL injection via user_id
    query = f"SELECT permission FROM user_permissions WHERE user_id = {user_id}"
    try:
        perms = conn.execute(query).fetchall()
        return [p[0] for p in perms]
    except Exception:
        return ["read", "write", "admin"]  # VULNERABILITY: Fails open — grants all permissions on error
    finally:
        conn.close()
