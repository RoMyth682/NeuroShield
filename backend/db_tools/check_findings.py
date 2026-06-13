import sqlite3

def check_findings():
    conn = sqlite3.connect('neuroshield.db')
    cur = conn.cursor()
    
    cur.execute("SELECT id, title, file_path, severity, finding_type FROM scan_findings WHERE session_id = 18")
    rows = cur.fetchall()
    print(f"Session 18 has {len(rows)} findings:")
    for r in rows:
        print(f"Title: {r[1]} | File: {r[2]} | Severity: {r[3]} | Type: {r[4]}")
        
    conn.close()

if __name__ == '__main__':
    check_findings()
