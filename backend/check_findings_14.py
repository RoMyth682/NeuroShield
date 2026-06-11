import sqlite3

def check_session_14():
    conn = sqlite3.connect('neuroshield.db')
    cur = conn.cursor()
    
    # Session 14 details
    cur.execute("SELECT id, status, original_filename, scan_warnings FROM scan_sessions WHERE id = 14")
    row = cur.fetchone()
    if row:
        print(f"Session 14 Status: {row[1]} | Warnings: {row[3]}\n")
        
    # Findings count by type
    cur.execute("SELECT finding_type, COUNT(*) FROM scan_findings WHERE session_id = 14 GROUP BY finding_type")
    print("Findings breakdown by type:", cur.fetchall())
    
    # List distinct file paths in findings
    cur.execute("SELECT DISTINCT file_path FROM scan_findings WHERE session_id = 14")
    print("Files with findings:", [r[0] for r in cur.fetchall()])
    
    # List some findings
    cur.execute("SELECT id, title, file_path, severity, finding_type FROM scan_findings WHERE session_id = 14 LIMIT 20")
    print("\nFirst 20 findings:")
    for f in cur.fetchall():
        print(f"Title: {f[1]} | File: {f[2]} | Severity: {f[3]} | Type: {f[4]}")
        
    conn.close()

if __name__ == '__main__':
    check_session_14()
