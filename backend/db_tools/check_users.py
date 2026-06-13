import sqlite3

def check_users():
    conn = sqlite3.connect('neuroshield.db')
    cur = conn.cursor()
    cur.execute("SELECT id, email, role FROM users")
    rows = cur.fetchall()
    print("Registered users:")
    for r in rows:
        print(f"ID: {r[0]} | Email: {r[1]} | Role: {r[2]}")
    conn.close()

if __name__ == '__main__':
    check_users()
