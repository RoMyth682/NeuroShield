import sqlite3
import bcrypt

def reset_password():
    conn = sqlite3.connect('neuroshield.db')
    cur = conn.cursor()
    
    new_password = "romith123"
    hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    
    cur.execute("UPDATE users SET hashed_password = ? WHERE email = ?", (hashed, "bahadur.romith@gmail.com"))
    conn.commit()
    
    if cur.rowcount > 0:
        print("Success: Password reset to 'romith123' for bahadur.romith@gmail.com")
    else:
        print("Error: User not found.")
        
    conn.close()

if __name__ == '__main__':
    reset_password()
