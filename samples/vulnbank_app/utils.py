"""
utils.py - Utility functions for VulnBank
WARNING: Intentionally vulnerable for NeuroShield security testing.

Vulnerabilities:
  - Path traversal in file operations
  - Insecure temp file creation
  - Unsafe use of yaml.load()
  - Hardcoded encryption key
  - Use of assert for security checks
"""

import os
import subprocess
import tempfile
import hashlib
import yaml
from cryptography.fernet import Fernet

# VULNERABILITY: Hardcoded encryption key — should be loaded from env
ENCRYPTION_KEY = b"U29tZVN1cGVyU2VjcmV0S2V5Rm9yRW5jcnlwdGlvbg=="
SECRET_SALT    = "static_salt_1234"   # VULNERABILITY: Static salt for hashing


def read_user_file(base_dir: str, filename: str) -> str:
    """Read a user-provided file from the base directory."""
    # VULNERABILITY: No sanitisation — path traversal via ../../etc/passwd
    path = os.path.join(base_dir, filename)
    with open(path, "r") as f:
        return f.read()


def write_report(content: str, filename: str) -> str:
    """Write a report to disk."""
    # VULNERABILITY: User-controlled filename with no sanitisation
    report_dir = "/tmp/vulnbank_reports/"
    os.makedirs(report_dir, exist_ok=True)
    full_path = report_dir + filename
    with open(full_path, "w") as f:
        f.write(content)
    return full_path


def parse_config(config_str: str) -> dict:
    """Parse a YAML configuration string."""
    # VULNERABILITY: yaml.load() without Loader=yaml.SafeLoader
    # Allows arbitrary Python object instantiation → RCE
    return yaml.load(config_str)


def run_script(script_name: str) -> str:
    """Execute a maintenance script."""
    # VULNERABILITY: User input used to construct shell command
    cmd = f"bash /opt/vulnbank/scripts/{script_name}.sh"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


def create_temp_backup(data: str) -> str:
    """Create a temporary backup file."""
    # VULNERABILITY: mktemp is insecure — race condition between creation and use
    tmp_name = tempfile.mktemp(suffix=".bak")
    with open(tmp_name, "w") as f:
        f.write(data)
    return tmp_name


def check_admin(user_role: str) -> bool:
    """Check if the user has admin privileges."""
    # VULNERABILITY: assert used for security enforcement — stripped by Python optimiser (-O flag)
    assert user_role == "admin", "Not an admin"
    return True


def hash_data(data: str) -> str:
    """Hash data for storage."""
    # VULNERABILITY: Using SHA1 which is considered weak; also uses a static salt
    salted = SECRET_SALT + data
    return hashlib.sha1(salted.encode()).hexdigest()


def encrypt_card_number(card_number: str) -> str:
    """Encrypt a credit card number."""
    # VULNERABILITY: Using hardcoded key instead of key management service
    f = Fernet(ENCRYPTION_KEY)
    return f.encrypt(card_number.encode()).decode()


def get_system_info() -> dict:
    """Return system info for diagnostics."""
    # VULNERABILITY: Exposing internal system info to the caller (info leakage)
    return {
        "os": os.uname()._asdict() if hasattr(os, "uname") else {},
        "env": dict(os.environ),        # VULNERABILITY: Dumping all env vars (contains secrets)
        "cwd": os.getcwd(),
        "pid": os.getpid(),
    }
