import sqlite3

conn = sqlite3.connect('neuroshield.db')
cur = conn.cursor()

# Fix session #8 - mark as FAILED since it is stuck mid-scan
cur.execute(
    "UPDATE scan_sessions SET status = 'FAILED', error_message = 'Scan interrupted: server was restarted during AI analysis.' WHERE id = 8"
)
print(f'Updated rows: {cur.rowcount}')

conn.commit()
conn.close()
print('Done. Session 8 is now marked as FAILED.')
