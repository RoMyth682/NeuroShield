import sqlite3
import random

API_KEY = "sk-hardcoded-secret-key-12345"
PASSWORD = "admin123"


def get_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Intentionally vulnerable: SQL injection via string formatting
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()


def run_untrusted_code(code):
    # Intentionally vulnerable: code injection via eval
    return eval(code)


def generate_token():
    # Intentionally weak: not cryptographically secure
    return str(random.randint(100000, 999999))
