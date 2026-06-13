"""
VulnBank - Intentionally Vulnerable Banking Web Application
============================================================
PURPOSE: Security testing demo for NeuroShield.
WARNING: This file contains INTENTIONAL vulnerabilities for educational purposes.
         DO NOT deploy this in any real environment.

Vulnerabilities included:
  - SQL Injection (A03)
  - Command Injection (A03)
  - Hardcoded Secrets/Credentials (A02)
  - Path Traversal (A01)
  - Insecure Deserialization - pickle (A08)
  - Weak Cryptography - MD5 (A02)
  - Server-Side Request Forgery - SSRF (A10)
  - Debug mode enabled in production (A05)
  - XML External Entity - XXE (A05)
  - Broken Authentication - no rate limiting (A07)
"""

import hashlib
import os
import pickle
import sqlite3
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
from base64 import b64decode, b64encode
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# ─── VULNERABILITY: Hardcoded credentials and secrets ────────────────────────
SECRET_KEY        = "supersecret123"
DB_PASSWORD       = "admin123"
API_KEY           = "sk-live-abc123xyz987HARDCODED"
JWT_SECRET        = "jwt_secret_do_not_share"
AWS_ACCESS_KEY    = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET        = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

app.config["SECRET_KEY"] = SECRET_KEY
app.config["DEBUG"] = True   # VULNERABILITY: Debug mode in production


# ─── Database setup ────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect("vulnbank.db")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            balance REAL,
            email TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY,
            from_user TEXT,
            to_user TEXT,
            amount REAL,
            note TEXT
        )
    """)
    # Seed data
    conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 99999.0, 'admin@vulnbank.com')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2, 'alice', 'alice123', 5000.0, 'alice@example.com')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (3, 'bob',   'bob123',   1200.0, 'bob@example.com')")
    conn.commit()
    return conn


# ─── VULNERABILITY: SQL Injection ─────────────────────────────────────────────
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = get_db()
    # VULN: Direct string interpolation into SQL query — classic SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor = conn.execute(query)
    user = cursor.fetchone()

    if user:
        return jsonify({"status": "ok", "message": f"Welcome {user[1]}", "balance": user[3]})
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


# ─── VULNERABILITY: SQL Injection (search endpoint) ──────────────────────────
@app.route("/search")
def search_user():
    name = request.args.get("name", "")
    conn = get_db()
    # VULN: Unsanitised user input in SQL query
    results = conn.execute(f"SELECT id, username, email FROM users WHERE username LIKE '%{name}%'").fetchall()
    return jsonify({"results": results})


# ─── VULNERABILITY: Command Injection ─────────────────────────────────────────
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULN: User input passed directly to shell command
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT)
    return jsonify({"output": result.decode()})


# ─── VULNERABILITY: Command Injection (2nd instance) ─────────────────────────
@app.route("/report")
def generate_report():
    report_name = request.args.get("name", "report")
    # VULN: Unsanitised input used in os.system call
    os.system(f"echo Generating report: {report_name} >> /tmp/reports.log")
    return jsonify({"status": "report queued", "name": report_name})


# ─── VULNERABILITY: Path Traversal ────────────────────────────────────────────
@app.route("/download")
def download_file():
    filename = request.args.get("file", "")
    # VULN: No path sanitisation — allows reading any file on the system
    base_path = "/var/app/statements/"
    full_path = base_path + filename
    try:
        with open(full_path, "r") as f:
            content = f.read()
        return jsonify({"content": content})
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404


# ─── VULNERABILITY: Weak Cryptography (MD5) ───────────────────────────────────
@app.route("/reset-password", methods=["POST"])
def reset_password():
    email = request.form.get("email", "")
    new_password = request.form.get("new_password", "")
    # VULN: MD5 is cryptographically broken for password hashing
    hashed = hashlib.md5(new_password.encode()).hexdigest()
    conn = get_db()
    conn.execute(f"UPDATE users SET password = '{hashed}' WHERE email = '{email}'")
    conn.commit()
    return jsonify({"status": "password updated", "hash": hashed})


# ─── VULNERABILITY: Insecure Deserialization (pickle) ─────────────────────────
@app.route("/restore-session", methods=["POST"])
def restore_session():
    session_data = request.form.get("session", "")
    # VULN: Deserializing untrusted pickle data can lead to Remote Code Execution
    decoded = b64decode(session_data)
    user_obj = pickle.loads(decoded)
    return jsonify({"user": str(user_obj)})


# ─── VULNERABILITY: SSRF ──────────────────────────────────────────────────────
@app.route("/fetch-rate")
def fetch_exchange_rate():
    currency_url = request.args.get("url", "https://api.exchangerate.host/latest")
    # VULN: User-controlled URL fetched by the server — allows SSRF
    # Attacker can use: ?url=http://169.254.169.254/latest/meta-data/ (AWS metadata)
    response = urllib.request.urlopen(currency_url)
    return jsonify({"data": response.read().decode()})


# ─── VULNERABILITY: XXE (XML External Entity) ─────────────────────────────────
@app.route("/upload-statement", methods=["POST"])
def upload_statement():
    xml_data = request.data
    # VULN: Parses XML without disabling external entity processing
    # Allows reading local files via XXE: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    tree = ET.fromstring(xml_data)
    account = tree.find("account").text
    amount  = tree.find("amount").text
    return jsonify({"account": account, "amount": amount})


# ─── VULNERABILITY: Broken Authentication / No Rate Limiting ──────────────────
@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    otp = request.form.get("otp", "")
    # VULN: 4-digit OTP with no rate limiting → brute-forceable in 10,000 attempts
    correct_otp = "4821"
    if otp == correct_otp:
        return jsonify({"status": "verified", "token": "access_granted_token_abc123"})
    return jsonify({"status": "wrong otp"}), 400


# ─── VULNERABILITY: Sensitive data in logs ────────────────────────────────────
@app.route("/transfer", methods=["POST"])
def transfer():
    from_user = request.form.get("from")
    to_user   = request.form.get("to")
    amount    = request.form.get("amount")
    pin       = request.form.get("pin")
    # VULN: Logging sensitive PIN to stdout
    print(f"[TRANSFER] {from_user} -> {to_user} | Amount: {amount} | PIN: {pin}")
    conn = get_db()
    conn.execute(
        f"INSERT INTO transactions (from_user, to_user, amount, note) VALUES ('{from_user}', '{to_user}', {amount}, 'transfer')"
    )
    conn.commit()
    return jsonify({"status": "transferred", "amount": amount})


# ─── VULNERABILITY: Use of eval() on user input ───────────────────────────────
@app.route("/calculate")
def calculate():
    expr = request.args.get("expr", "1+1")
    # VULN: eval() on user-controlled input — Remote Code Execution
    result = eval(expr)
    return jsonify({"result": result})


# ─── VULNERABILITY: Reflected XSS ─────────────────────────────────────────────
@app.route("/welcome")
def welcome():
    name = request.args.get("name", "User")
    # VULN: User input rendered directly into HTML without escaping
    html = f"<html><body><h1>Welcome, {name}!</h1><p>Your VulnBank dashboard.</p></body></html>"
    return render_template_string(html)


if __name__ == "__main__":
    # VULNERABILITY: Running with debug=True and host=0.0.0.0 exposes the debugger
    app.run(host="0.0.0.0", port=5000, debug=True)
