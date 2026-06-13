from pathlib import Path
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.auth import require_admin
from app.config import settings
from app.database import get_db
from app.models.scan import ScanSession, ScanStatus
from app.models.user import User, UserRole
from app.schemas.auth import UserResponse

router = APIRouter(prefix="/api/admin", tags=["admin"])

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "owasp-semgrep.yaml"

def _user_with_scan_count(user: User, db: Session) -> dict:
    scan_count = db.query(func.count(ScanSession.id)).filter(ScanSession.user_id == user.id).scalar() or 0
    return {
        "id": user.id,
        "email": user.email,
        "role": user.role,
        "created_at": user.created_at,
        "scan_count": scan_count,
    }

@router.get("/stats")
def get_stats(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    total_scans = db.query(func.count(ScanSession.id)).scalar() or 0
    completed_scans = (
        db.query(func.count(ScanSession.id)).filter(ScanSession.status == ScanStatus.COMPLETED).scalar() or 0
    )
    total_users = db.query(func.count(User.id)).scalar() or 0
    failed_scans = (
        db.query(func.count(ScanSession.id)).filter(ScanSession.status == ScanStatus.FAILED).scalar() or 0
    )
    return {
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "failed_scans": failed_scans,
        "total_users": total_users,
    }

@router.get("/users")
def list_users(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return [_user_with_scan_count(u, db) for u in users]

@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    if user_id == admin.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete your own account")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Step 1: Get all scan session IDs for this user
    from app.models.scan import ScanFinding, ScanSession
    session_ids = [s.id for s in db.query(ScanSession.id).filter(ScanSession.user_id == user_id).all()]

    # Step 2: Delete all findings for those sessions
    if session_ids:
        db.query(ScanFinding).filter(ScanFinding.session_id.in_(session_ids)).delete(synchronize_session=False)

    # Step 3: Delete all scan sessions for this user
    db.query(ScanSession).filter(ScanSession.user_id == user_id).delete(synchronize_session=False)

    # Step 4: Delete the user
    db.delete(user)
    db.commit()

class RolePatch(BaseModel):
    # Patch model for changing a user's role. Developer is just a normal user with no special permissions.
    role: str  # "admin" or "developer"

@router.patch("/users/{user_id}/role")
def change_user_role(
    user_id: int,
    body: RolePatch,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    if user_id == admin.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot change your own role")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    try:
        user.role = UserRole(body.role)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid role: {body.role}")
    db.commit()
    return _user_with_scan_count(user, db)

@router.get("/scans")
def list_scans(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    sessions = (
        db.query(ScanSession, User.email)
        .join(User, ScanSession.user_id == User.id)
        .order_by(ScanSession.created_at.desc())
        .limit(settings.admin_scan_list_limit)
        .all()
    )
    return [
        {
            "id": s.id,
            "user_id": s.user_id,
            "user_email": email,
            "filename": s.original_filename,
            "status": s.status.value,
            "created_at": s.created_at,
            "completed_at": s.completed_at,
        }
        for s, email in sessions
    ]

@router.get("/rules")
def get_rules(_: User = Depends(require_admin)):
    if not RULES_PATH.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rules file not found")
    return {"content": RULES_PATH.read_text(encoding="utf-8")}


@router.put("/rules")
async def update_rules(file: UploadFile = File(...), _: User = Depends(require_admin)):
    content = await file.read()
    RULES_PATH.write_bytes(content)
    return {"message": "Scanning rules updated successfully"}
