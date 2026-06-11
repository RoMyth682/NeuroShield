import os
import pickle
import random
import sqlite3
import subprocess
import hashlib

# ── A03: Injection ────────────────────────────
def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Vulnerable: f-string in SQL query → SQL injection
    cursor.execute(f"SELECT * FROM users WHERE username='{username}'")
    return cursor.fetchall()

def run_report(filename):
    # Vulnerable: shell=True with user input → command injection
    subprocess.run("generate_report.sh " + filename, shell=True)

def evaluate_formula(expr):
    # Vulnerable: eval with user input → code injection
    return eval(expr)

# ── A02: Cryptographic Failures ───────────────
# Vulnerable: hardcoded secret
SECRET_KEY = "supersecret123"
API_KEY = "hardcoded-api-key-abc"

def hash_password(password):
    # Vulnerable: MD5 is broken for passwords
    return hashlib.md5(password.encode()).hexdigest()

def generate_token():
    # Vulnerable: not cryptographically secure
    return str(random.randint(100000, 999999))

# ── A08: Insecure Deserialization ─────────────
def load_session(data):
    # Vulnerable: pickle.loads on untrusted data → RCE
    return pickle.loads(data)

# ── A01: Broken Access Control ────────────────
def read_file(path):
    # Vulnerable: path traversal with user-controlled path
    with open(os.path.join("/var/data", path), "r") as f:
        return f.read()
