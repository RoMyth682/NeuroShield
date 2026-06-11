from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth import require_admin
from app.database import get_db
from app.models.scan import ScanSession, ScanStatus
from app.models.user import User, UserRole
from app.schemas.auth import UserResponse

router = APIRouter(prefix="/api/admin", tags=["admin"])

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "owasp-semgrep.yaml"


@router.get("/stats")
def get_stats(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    total_scans = db.query(func.count(ScanSession.id)).scalar() or 0
    completed_scans = (
        db.query(func.count(ScanSession.id)).filter(ScanSession.status == ScanStatus.COMPLETED).scalar() or 0
    )
    total_users = db.query(func.count(User.id)).scalar() or 0
    return {
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "total_users": total_users,
    }


@router.get("/users", response_model=list[UserResponse])
def list_users(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    return db.query(User).order_by(User.created_at.desc()).all()


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    if user_id == admin.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete your own account")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    db.delete(user)
    db.commit()


@router.get("/scans")
def list_scans(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    sessions = db.query(ScanSession).order_by(ScanSession.created_at.desc()).limit(50).all()
    return [
        {
            "id": s.id,
            "user_id": s.user_id,
            "filename": s.original_filename,
            "status": s.status.value,
            "created_at": s.created_at,
            "completed_at": s.completed_at,
        }
        for s in sessions
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
