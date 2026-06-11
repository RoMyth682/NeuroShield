import sqlite3

def check_all():
    conn = sqlite3.connect('neuroshield.db')
    cur = conn.cursor()
    
    cur.execute("SELECT id, title, file_path FROM scan_findings WHERE session_id = 10")
    for f in cur.fetchall():
        print(f"Title: {f[1]} | File: {f[2]}")
        
    conn.close()

if __name__ == '__main__':
    check_all()
