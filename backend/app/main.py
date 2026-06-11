from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth import hash_password
from app.config import settings
from app.database import Base, SessionLocal, engine
from app.models.user import User, UserRole
from app.routers import admin, auth, scan


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    _migrate_schema()
    settings.upload_path.mkdir(parents=True, exist_ok=True)
    settings.reports_path.mkdir(parents=True, exist_ok=True)
    _seed_admin()
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
                email="admin@neuroshield.local",
                hashed_password=hash_password("admin123"),
                role=UserRole.ADMIN,
            )
            db.add(admin_user)
            db.commit()
    finally:
        db.close()


app = FastAPI(
    title="NeuroShield API",
    description="Autonomous Code Security Intelligence Engine",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(admin.router)


@app.get("/")
def root():
    return {
        "service": "NeuroShield API",
        "status": "running",
        "message": "This is the backend API. Open the web app or API docs below.",
        "frontend": "http://localhost:5173",
        "docs": "/docs",
        "health": "/api/health",
    }


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "NeuroShield"}
