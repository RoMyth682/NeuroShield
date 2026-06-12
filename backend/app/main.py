from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth import hash_password
from app.config import settings
from app.database import Base, SessionLocal, engine
from app.models.scan import ScanSession, ScanStatus
from app.models.user import User, UserRole
from app.routers import admin, auth, scan, settings as settings_router


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    _migrate_schema()
    settings.upload_path.mkdir(parents=True, exist_ok=True)
    settings.reports_path.mkdir(parents=True, exist_ok=True)
    _seed_admin()
    _reset_stuck_scans()
    yield


def _migrate_schema():
    if not settings.database_url.startswith("sqlite"):
        return
    with engine.begin() as conn:
        columns = {row[1] for row in conn.execute(text("PRAGMA table_info(scan_sessions)"))}
        if "scan_warnings" not in columns:
            conn.execute(text("ALTER TABLE scan_sessions ADD COLUMN scan_warnings TEXT"))


def _seed_admin():
    db: Session = SessionLocal()
    try:
        if not db.query(User).filter(User.role == UserRole.ADMIN).first():
            admin_user = User(
                email=settings.admin_email,
                hashed_password=hash_password(settings.admin_password),
                role=UserRole.ADMIN,
            )
            db.add(admin_user)
            db.commit()
    finally:
        db.close()


def _reset_stuck_scans():
    """Mark any scan still in a running state as FAILED on startup.
    This cleans up scans that were interrupted by a server restart."""
    stuck_statuses = [
        ScanStatus.PENDING,
        ScanStatus.EXTRACTING,
        ScanStatus.SAST_RUNNING,
        ScanStatus.CVE_RUNNING,
        ScanStatus.AI_RUNNING,
    ]
    db: Session = SessionLocal()
    try:
        stuck = db.query(ScanSession).filter(ScanSession.status.in_(stuck_statuses)).all()
        for s in stuck:
            s.status = ScanStatus.FAILED
            s.error_message = "Scan was interrupted because the server restarted. Please re-upload and scan again."
        if stuck:
            db.commit()
            print(f"[startup] Reset {len(stuck)} stuck scan(s) to FAILED.")
    finally:
        db.close()


app = FastAPI(
    title=settings.app_name,
    description=settings.app_description,
    version=settings.app_version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(admin.router)
app.include_router(settings_router.router)


@app.get("/")
def root():
    return {
        "service": settings.app_name,
        "status": "running",
        "message": "This is the backend API. Open the web app or API docs below.",
        "docs": "/docs",
        "health": "/api/health",
    }


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "NeuroShield"}
