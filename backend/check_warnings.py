import sqlite3

def check_warnings():
    conn = sqlite3.connect('neuroshield.db')
    cur = conn.cursor()
    cur.execute("SELECT id, scan_warnings FROM scan_sessions WHERE id = 12")
    row = cur.fetchone()
    if row:
        print("Session 12 warnings:")
        print(row[1])
    conn.close()

if __name__ == '__main__':
    check_warnings()
