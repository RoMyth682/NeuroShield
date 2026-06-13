"""Make a user an admin by email."""
import sys
from app.database import SessionLocal
from app.models.user import User, UserRole

email = sys.argv[1] if len(sys.argv) > 1 else "bahadur.romith@gmail.com"
db = SessionLocal()
user = db.query(User).filter(User.email == email).first()
if not user:
    print(f"User {email} not found")
else:
    user.role = UserRole.ADMIN
    db.commit()
    print(f"✅ {email} is now an admin. Log out and back in.")
db.close()
