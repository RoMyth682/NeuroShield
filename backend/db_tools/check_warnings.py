import sqlite3

def check_warnings():
    conn = sqlite3.connect('neuroshield.db')
    cur = conn.cursor()
    cur.execute("SELECT id, status, original_filename, scan_warnings FROM scan_sessions ORDER BY id DESC LIMIT 3")
    for row in cur.fetchall():
        print(f"ID: {row[0]} | Status: {row[1]} | File: {row[2]} | Warnings: {row[3]}")
    conn.close()

if __name__ == '__main__':
    check_warnings()
