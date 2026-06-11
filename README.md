# NeuroShield — Autonomous Code Security Intelligence Engine

NeuroShield detects OWASP Top 10 vulnerabilities in uploaded source code, scans dependencies against CVE databases (OSV.dev / NVD), generates AI-powered remediation guidance via GPT-4o-mini, and exports professional PDF security reports.

Built per the NGIT Mini Project SRS specification.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 18, Vite, TypeScript, Axios |
| Backend | Python 3.10+, FastAPI (v0.136.3) |
| SAST | Bandit (Python), Semgrep (multi-language, v1.165.0) |
| CVE APIs | OSV.dev |
| AI | OpenAI GPT-4o-mini |
| PDF | ReportLab |
| Database | SQLite + SQLAlchemy |

## Prerequisites

- Python 3.10+
- Node.js 18+
- OpenAI API key

## Quick Start

### 1. Backend

```bash
cd backend
python -m venv .venv

# Activate virtual environment
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1
# On Windows (cmd):
.venv\Scripts\activate.bat
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
copy .env.example .env
# Edit .env and set your OPENAI_API_KEY
```

To run the backend server, use:
```bash
uvicorn app.main:app --port 8000
```
*Note: Avoid using the `--reload` flag during scans on Windows. Because Uvicorn monitors directory changes, file uploads or PDF report writes will trigger an automatic server reload, which interrupts active static analysis (Bandit/Semgrep) scans.*

API docs: http://127.0.0.1:8000/docs

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

App URL: http://localhost:5173

### 3. Default Admin Account

| Email | Password |
|-------|----------|
| admin@neuroshield.local | admin123 |

You can also register a developer account from the Register page.

## Testing with Sample Code

Vulnerable sample projects are included:

- **Python App**: `samples/vulnerable_app/` (Zip the folder and upload the .zip file, or upload `app.py` directly)
- **Go App**: `samples/vuln_go_app.go` (A newly created vulnerable Go file containing 9 real vulnerabilities including SQL Injection, Command Injection, Path Traversal, SSRF, Weak Crypto, and hardcoded secrets)
- **Java App**: `samples/VulnerableJavaApp.java`

## Project Structure

```
Neuroshield/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI entry point
│   │   ├── auth.py              # JWT + bcrypt authentication
│   │   ├── models/              # SQLAlchemy models
│   │   ├── routers/             # REST API endpoints
│   │   ├── services/            # SAST, CVE, AI, PDF, orchestrator
│   │   ├── rules/               # Semgrep OWASP rules
│   │   └── prompts/             # AI prompt templates
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── pages/               # React screens (Home, Auth, Upload, Analysis, Dashboard, Admin)
│       └── components/
└── samples/                     # Test codebases
    ├── vulnerable_app/          # Python sample app
    ├── vuln_go_app.go           # Go sample app
    └── VulnerableJavaApp.java   # Java sample app
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register developer account |
| POST | `/api/auth/login` | Login (returns JWT) |
| POST | `/api/scan/upload` | Upload code (ZIP or source file) |
| GET | `/api/scan/{id}/status` | Poll analysis progress |
| GET | `/api/scan/{id}/results` | Get findings |
| POST | `/api/scan/finding/{id}/explain` | Generate on-demand AI explanation |
| GET | `/api/scan/{id}/report` | Download PDF report |
| GET | `/api/admin/stats` | Admin usage statistics |
| GET | `/api/admin/users` | List users |
| DELETE | `/api/admin/users/{id}` | Delete user |

## SRS Feature Coverage

- User registration/login with bcrypt password hashing
- Role-based access (Admin / Developer)
- Drag-and-drop code upload (max 10 MB)
- Bandit + Semgrep static analysis (scans Python, JS, Go, PHP, Java, and Dockerfile)
- CVE scanning via requirements.txt and package.json
- GPT-4o-mini explanations (hybrid auto-explain for top 3 + on-demand for rest) with OWASP fallback
- Severity classification (Critical / High / Medium / Low)
- Filterable results dashboard with colour-coded badges
- PDF pentest-style report download (regenerated dynamically to keep on-demand explanations synced)
- Admin dashboard (stats, user management, scan history)

## Team

| Name | Roll No. | Module |
|------|----------|--------|
| B. Romith Singh | 245323733133 | SAST Engine, Backend API |
| Deepak Jhanwar | 245323733146 | CVE Scanner, NVD Integration |
| Ansh Sugandhi | 245323733131 | AI Explanation, PDF Report |

Guide: Mrs. S. Meghana — NGIT, Hyderabad
