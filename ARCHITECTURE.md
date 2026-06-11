# NeuroShield — Architecture & Project Summary

> **Autonomous Code Security Intelligence Engine**
> NGIT Mini Project — CSE Department

---

## 1. Project Overview

NeuroShield is a web application that analyzes uploaded source code for security vulnerabilities. It combines **static analysis (SAST)**, **CVE dependency scanning**, and **AI-powered remediation** into a single security dashboard with professional PDF report generation.

### Core Capabilities

- **SAST Scanning** — Bandit (Python) + Semgrep (multi-language) detect OWASP Top 10 patterns
- **CVE Detection** — Scans dependency manifests against OSV.dev and NVD databases
- **AI Explanations** — GPT-4o-mini explains vulnerabilities, describes exploitation scenarios, and suggests fixes
- **PDF Reports** — Downloadable penetration-test-style reports with executive summaries
- **Role-Based Access** — Admin and Developer roles with JWT authentication

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────┐
│                      Browser (React SPA)                  │
│              http://localhost:5173 (dev)                   │
│                                                           │
│  ┌─────────┐  ┌──────────┐  ┌───────┐  ┌─────────────┐  │
│  │  Home   │  │ Auth     │  │ Upload│  │ Dashboard    │  │
│  │  Page   │  │ (Login/  │  │ Page  │  │ (Results)    │  │
│  │         │  │ Register)│  │       │  │              │  │
│  └─────────┘  └──────────┘  └───────┘  └─────────────┘  │
│  ┌─────────┐  ┌──────────┐  ┌───────┐                   │
│  │ Analysis│  │ Admin    │  │Navbar │                   │
│  │ (Status)│  │ Dashboard│  │       │                   │
│  └─────────┘  └──────────┘  └───────┘                   │
│                                                           │
│  ┌────────────────────────────────────────────────────┐  │
│  │              AuthContext (JWT state)                │  │
│  └────────────────────────────────────────────────────┘  │
│                                                           │
│  ┌────────────────────────────────────────────────────┐  │
│  │              API Client (Axios)                     │  │
│  │         baseURL: /api → Vite Proxy → Backend        │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────┬───────────────────────────────────┘
                       │ HTTP (proxied in dev)
                       ▼
┌──────────────────────────────────────────────────────────┐
│              FastAPI Backend (port 8000)                   │
│                                                           │
│  ┌────────────────────────────────────────────────────┐  │
│  │              Main Entry Point (main.py)              │  │
│  │  • Lifespan: create tables, seed admin, mkdirs      │  │
│  │  • CORS middleware                                  │  │
│  │  • Router mounting: /api/auth, /api/scan, /api/admin│  │
│  └────────────────────────────────────────────────────┘  │
│                       │                                    │
│         ┌─────────────┼─────────────┐                      │
│         ▼             ▼             ▼                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                 │
│  │ Auth     │  │ Scan     │  │ Admin    │                 │
│  │ Router   │  │ Router   │  │ Router   │                 │
│  └──────────┘  └──────────┘  └──────────┘                 │
│       │              │              │                      │
│       ▼              ▼              ▼                      │
│  ┌────────────────────────────────────────────────────┐  │
│  │                  Services Layer                      │  │
│  │                                                     │  │
│  │  ┌────────────┐  ┌────────────┐  ┌───────────────┐ │  │
│  │  │ScanOrch-   │─▶│SASTScanner │  │ Bandit/Semgrep │ │  │
│  │  │  estrator  │  └────────────┘  └───────────────┘ │  │
│  │  │            │  ┌────────────┐  ┌───────────────┐ │  │
│  │  │ (orchestr- │─▶│CVEScanner  │  │ OSV.dev/NVD   │ │  │
│  │  │  ates the  │  └────────────┘  └───────────────┘ │  │
│  │  │  3-phase   │  ┌────────────┐  ┌───────────────┐ │  │
│  │  │  scan)     │─▶│AIExplainer │  │ OpenAI GPT-   │ │  │
│  │  │            │  └────────────┘  │ 4o-mini        │ │  │
│  │  │            │  ┌────────────┐  └───────────────┘ │  │
│  │  │            │─▶│ReportGen-  │  ┌───────────────┐ │  │
│  │  │            │  │  erator    │  │ ReportLab PDF │ │  │
│  │  └────────────┘  └────────────┘  └───────────────┘ │  │
│  │                                                     │  │
│  │  ┌─────────────────────────────────────────────┐   │  │
│  │  │           risk_scoring.py                    │   │  │
│  │  │   CVSS → Severity, Bandit → Severity, etc.  │   │  │
│  │  └─────────────────────────────────────────────┘   │  │
│  └────────────────────────────────────────────────────┘  │
│                       │                                    │
│                       ▼                                    │
│  ┌────────────────────────────────────────────────────┐  │
│  │           Data Layer (SQLAlchemy + SQLite)           │  │
│  │                                                     │  │
│  │  ┌─────────────┐  ┌─────────────┐                   │  │
│  │  │    User     │  │ ScanSession │                   │  │
│  │  │  (users)    │◀┤(scan_sessions)│                  │  │
│  │  └─────────────┘  └──────┬──────┘                   │  │
│  │                          │                           │  │
│  │                    ┌─────▼──────┐                    │  │
│  │                    │ScanFinding  │                    │  │
│  │                    │(scan_findings)                   │  │
│  │                    └────────────┘                    │  │
│  └────────────────────────────────────────────────────┘  │
│                                                           │
│  ┌────────────────────────────────────────────────────┐  │
│  │        Configuration (pydantic-settings)             │  │
│  │        Reads from .env or environment variables      │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

---

## 3. Tech Stack

### Backend (Python)

| Library | Version | Purpose |
|---------|---------|---------|
| FastAPI | 0.136.3 | Web framework / REST API |
| Uvicorn | 0.34.0 | ASGI server |
| SQLAlchemy | 2.0.36 | ORM / database abstraction |
| python-jose | 3.3.0 | JWT token creation and validation |
| bcrypt | 4.2.1 | Password hashing |
| pydantic-settings | 2.6.1 | Environment variable configuration |
| httpx | 0.28.1 | HTTP client for CVE API queries |
| openai | 1.57.4 | GPT-4o-mini AI explanations |
| bandit | 1.8.0 | Python SAST scanner |
| semgrep | 1.165.0 | Multi-language SAST scanner |
| reportlab | 4.2.5 | PDF report generation |
| python-multipart | 0.0.20 | File upload parsing |
| aiofiles | 24.1.0 | Async file operations |
| sse-starlette | ≥1.6.1 | Server-Sent Events (future use) |

### Frontend (JavaScript/TypeScript)

| Library | Version | Purpose |
|---------|---------|---------|
| React | 18.3.1 | UI framework |
| React Router | 7.1.1 | Client-side routing |
| Axios | 1.7.9 | HTTP client |
| Vite | 6.0.6 | Build tool / dev server |
| TypeScript | 5.7.2 | Type safety |
| @vitejs/plugin-react | 4.3.4 | Vite React plugin |

---

## 4. Backend Architecture

### 4.1 Directory Structure

```
backend/
├── .env.example              # Documented environment variables
├── requirements.txt          # Python dependencies
├── app/
│   ├── __init__.py
│   ├── config.py             # Settings class (pydantic-settings)
│   ├── database.py           # SQLAlchemy engine, session, base
│   ├── main.py               # FastAPI app entry point, lifespan, CORS
│   ├── auth.py               # JWT creation/validation, password hashing
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py           # User model + UserRole enum
│   │   └── scan.py           # ScanSession, ScanFinding, enums
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── auth.py           # Pydantic schemas for auth
│   │   └── scan.py           # Pydantic schemas for scan
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── auth.py           # POST /register, /login, GET /me
│   │   ├── scan.py           # POST /upload, GET /status, /results, /report, POST /explain
│   │   └── admin.py          # GET /stats, /users, /scans, /rules; PUT /rules, DELETE /users
│   ├── services/
│   │   ├── __init__.py
│   │   ├── orchestrator.py   # ScanOrchestrator — coordinates 3-phase analysis
│   │   ├── sast_scanner.py   # SASTScanner — Bandit + Semgrep integration
│   │   ├── cve_scanner.py    # CVEScanner — OSV.dev + NVD API queries
│   │   ├── ai_explainer.py   # AIExplainer — GPT-4o-mini integration + fallback
│   │   ├── report_generator.py  # ReportGenerator — PDF via ReportLab
│   │   └── risk_scoring.py   # Severity mapping functions
│   ├── rules/
│   │   ├── owasp-semgrep.yaml     # Core Semgrep rules (OWASP Top 10)
│   │   └── expanded-semgrep.yaml  # Expanded multi-language rules
│   └── prompts/
│       └── vulnerability_explanation.txt  # GPT system prompt template
```

### 4.2 Configuration (`config.py`)

All configuration is managed via `pydantic-settings` reading from `.env` or environment variables. Key categories:

| Category | Key Variables | Defaults |
|----------|---------------|----------|
| **Core** | `app_name`, `app_description`, `app_version` | NeuroShield API |
| **Security** | `secret_key`, `algorithm`, `access_token_expire_minutes` | HS256, 1440 min |
| **Database** | `database_url` | `sqlite:///./neuroshield.db` |
| **Admin** | `admin_email`, `admin_password` | `admin@neuroshield.local` / `admin123` |
| **CORS** | `cors_origins` (comma-separated) | `http://localhost:5173,http://127.0.0.1:5173` |
| **Upload** | `max_upload_size_mb`, `upload_dir`, `reports_dir` | 10 MB, `./uploads`, `./reports` |
| **AI** | `openai_api_key`, `openai_model`, `ai_temperature`, `ai_max_tokens`, `ai_timeout`, `ai_auto_explain_count`, `ai_max_workers` | gpt-4o-mini, 0.2, 800, 8s, 3, 5 |
| **SAST** | `bandit_timeout`, `semgrep_timeout`, `semgrep_default_config` | 25s, 60s, `p/security-audit` |
| **CVE** | `osv_api_url`, `nvd_api_url`, `cve_http_timeout`, `cve_max_packages`, `cve_description_max_length` | 15s, 50, 500 |
| **Admin** | `admin_scan_list_limit` | 50 |
| **Preview** | `preview_file_limit` | 100 |

### 4.3 Database Schema

#### `users` table
| Column | Type | Constraints |
|--------|------|-------------|
| `id` | Integer | PK, auto-increment |
| `email` | String(255) | UNIQUE, NOT NULL, indexed |
| `hashed_password` | String(255) | NOT NULL |
| `role` | Enum(admin, developer) | DEFAULT developer |
| `created_at` | DateTime | DEFAULT now() |

#### `scan_sessions` table
| Column | Type | Constraints |
|--------|------|-------------|
| `id` | Integer | PK, auto-increment |
| `user_id` | Integer | FK → users.id, NOT NULL |
| `status` | Enum(pending, extracting, sast_running, cve_running, ai_running, completed, failed) | DEFAULT pending |
| `original_filename` | String(512) | |
| `upload_path` | String(1024) | |
| `report_path` | String(1024) | NULLABLE |
| `error_message` | Text | NULLABLE |
| `scan_warnings` | Text | NULLABLE (JSON array) |
| `created_at` | DateTime | DEFAULT now() |
| `completed_at` | DateTime | NULLABLE |

#### `scan_findings` table
| Column | Type | Constraints |
|--------|------|-------------|
| `id` | Integer | PK, auto-increment |
| `session_id` | Integer | FK → scan_sessions.id, NOT NULL |
| `finding_type` | Enum(sast, cve) | NOT NULL |
| `title` | String(512) | |
| `file_path` | String(1024) | NULLABLE |
| `line_number` | Integer | NULLABLE |
| `severity` | Enum(critical, high, medium, low) | NOT NULL |
| `cwe_id` | String(32) | NULLABLE |
| `category` | String(128) | NULLABLE |
| `description` | Text | NULLABLE |
| `cvss_score` | Float | NULLABLE |
| `cve_id` | String(32) | NULLABLE |
| `package_name` | String(256) | NULLABLE |
| `package_version` | String(64) | NULLABLE |
| `code_snippet` | Text | NULLABLE |
| `ai_explanation` | Text | NULLABLE |
| `exploitation_scenario` | Text | NULLABLE |
| `fix_snippet` | Text | NULLABLE |

### 4.4 Auth System (`auth.py`)

- **Password Hashing**: bcrypt (`hash_password` / `verify_password`)
- **JWT Tokens**: python-jose encodes `{sub: user_id, role: role, exp: expiry}` with HS256
- **Token URL**: `/api/auth/login` (OAuth2PasswordBearer)
- **Token Expiry**: Configurable via `access_token_expire_minutes` (default 24 hours)
- **Auth Flow**:
  1. User logs in → receives JWT + user info
  2. Frontend stores JWT in `localStorage`
  3. Every API request includes `Authorization: Bearer <token>`
  4. Backend validates token via `get_current_user` dependency
  5. Admin routes protected by `require_admin` dependency

### 4.5 API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/auth/register` | Public | Register new developer account |
| `POST` | `/api/auth/login` | Public | Login, returns JWT + user profile |
| `GET` | `/api/auth/me` | JWT | Get current user info |
| `POST` | `/api/scan/upload` | JWT | Upload code file (ZIP or source) |
| `GET` | `/api/scan/{id}/status` | JWT | Poll scan progress |
| `GET` | `/api/scan/{id}/results` | JWT | Get findings (optional `?severity=` filter) |
| `POST` | `/api/scan/finding/{id}/explain` | JWT | Generate on-demand AI explanation |
| `GET` | `/api/scan/{id}/report` | JWT | Download PDF report |
| `GET` | `/api/admin/stats` | Admin | System usage statistics |
| `GET` | `/api/admin/users` | Admin | List all users |
| `DELETE` | `/api/admin/users/{id}` | Admin | Delete a user |
| `GET` | `/api/admin/scans` | Admin | List recent scans |
| `GET` | `/api/admin/rules` | Admin | Get current Semgrep rules |
| `PUT` | `/api/admin/rules` | Admin | Upload new Semgrep rules |
| `GET` | `/` | Public | Service info |
| `GET` | `/api/health` | Public | Health check |

### 4.6 Scan Pipeline (3 Phases)

The `ScanOrchestrator.run_analysis()` coordinates three sequential phases:

```
Phase 1: SAST SCAN
├── Bandit (Python .py files only)
│   └── Runs via subprocess: python -m bandit -r <dir> -f json
│   └── Timeout: configurable (default 25s)
├── Semgrep (all supported languages)
│   └── Runs via subprocess with custom rules
│   └── Rules: expanded-semgrep.yaml > owasp-semgrep.yaml > p/security-audit
│   └── Timeout: configurable (default 60s)
└── Output: SASTFinding[] with severity, CWE, OWASP category, code snippet

Phase 2: CVE SCAN
├── Parse dependency manifests:
│   ├── requirements.txt → PyPI ecosystem
│   ├── package.json → npm ecosystem
│   └── pom.xml → Maven ecosystem
├── Query OSV.dev API (primary)
├── Fallback: query NVD API (secondary)
├── Limit: configurable max packages (default 50)
└── Output: CVEFinding[] with CVSS score, severity, description

Phase 3: AI EXPLANATIONS
├── Top N most severe findings auto-explained (configurable, default 3)
├── Uses ThreadPoolExecutor (max workers configurable, default 5)
├── GPT-4o-mini with structured JSON response
├── Fallback: OWASP documentation reference when API is unavailable
└── Output: explanation, exploitation_scenario, fix_snippet for each finding
```

After all phases, a PDF report is generated and saved. Findings without auto-AI explanations can be explained on-demand via `POST /finding/{id}/explain`.

### 4.7 Severity Classification (`risk_scoring.py`)

| Source | Critical | High | Medium | Low |
|--------|----------|------|--------|-----|
| **CVSS Score** | ≥ 9.0 | ≥ 7.0 | ≥ 4.0 | < 4.0 |
| **Bandit** | — | HIGH | MEDIUM | LOW |
| **Semgrep** | — | ERROR | WARNING | INFO |
| **Fallback** | — | — | Used | — |

### 4.8 Supported Source File Extensions (SAST)

`.py`, `.js`, `.java`, `.ts`, `.jsx`, `.tsx`, `.php`, `.go`, `.rb`, `.cs`, `.c`, `.cpp`, `.h`, `.hpp`, `.html`, `.htm`, `.css`, `.scss`, `.json`, `.yaml`, `.yml`, `.xml`, `.sh`, `.bash`, `.ps1`, `.gradle`, `.kt`, `.kts`, `.dart`, `.swift`, `.rs`, `.erl`, `.ex`

Plus special filenames: `Dockerfile`, `Makefile`, `pom.xml`, `build.gradle`, `requirements.txt`, `package.json`, `Gemfile`, `Procfile`

### 4.9 Semgrep Rules

Two rule files in `app/rules/`:

- **`owasp-semgrep.yaml`** — Core rules: SQL injection, hardcoded secrets, eval(), insecure random
- **`expanded-semgrep.yaml`** — Comprehensive rules covering 6 languages:

| Language | Rule Count | Key Patterns |
|----------|-----------|--------------|
| Python | 12 | SQL injection, eval/exec, subprocess shell, pickle, YAML load, hardcoded secrets, insecure random, Flask debug, path traversal, MD5/SHA1 |
| JavaScript/TS | 6 | eval, innerHTML XSS, child_process exec, hardcoded secrets, prototype pollution, path traversal, SQL injection |
| Java | 6 | SQL injection, command injection, XXE (SAXParser), insecure random, hardcoded secrets, insecure deserialization |
| Go | 3 | SQL injection, command injection, hardcoded secrets |
| PHP | 3 | SQL injection, eval injection, system/shell_exec |
| Dockerfile | 2 | Root user, ADD vs COPY |

### 4.10 AI Prompt Template (`prompts/vulnerability_explanation.txt`)

The GPT model receives a structured prompt with finding details and is instructed to respond with valid JSON containing three keys:
- `explanation` — Plain-English vulnerability description
- `exploitation_scenario` — Step-by-step attack scenario
- `fix_snippet` — Corrected code (markdown code block)

---

## 5. Frontend Architecture

### 5.1 Directory Structure

```
frontend/
├── index.html                  # HTML entry point
├── package.json                # npm dependencies
├── tsconfig.json               # TypeScript config (strict mode)
├── vite.config.ts              # Vite config (proxy, port)
└── src/
    ├── main.tsx                 # React DOM render, BrowserRouter, AuthProvider
    ├── App.tsx                  # Route definitions
    ├── index.css                # Global CSS variables and base styles
    ├── api/
    │   └── client.ts            # Axios API client with JWT interceptor
    ├── context/
    │   └── AuthContext.tsx       # Authentication state management
    ├── components/
    │   ├── Navbar.tsx            # Top navigation bar + branding
    │   ├── Navbar.css
    │   ├── ProtectedRoute.tsx    # Route guard (redirects to /login)
    │   ├── SeverityBadge.tsx     # Color-coded severity pill
    │   └── SeverityBadge.css
    └── pages/
        ├── Home.tsx              # Landing page with hero + features
        ├── Home.css
        ├── Auth.tsx              # Login + Register forms
        ├── Auth.css
        ├── Upload.tsx            # Drag-and-drop file upload
        ├── Upload.css
        ├── Analysis.tsx          # Scan progress with stages + polling
        ├── Analysis.css
        ├── Dashboard.tsx         # Results view with filtering + AI explanations
        ├── Dashboard.css
        ├── Admin.tsx             # Admin panel (stats, users, scans)
        └── Admin.css
```

### 5.2 Routing

```
/              → Home (landing page)
/login         → Login form
/register      → Register form
/upload        → Upload source code (protected)
/analysis/:id  → Scan progress view (protected)
/results/:id   → Findings dashboard (protected)
/admin         → Admin dashboard (protected)
```

Protected routes redirect to `/login` if no JWT token is present.

### 5.3 Auth Context (`AuthContext.tsx`)

React Context managing:
- `user` — Current user object `{ id, email, role }`
- `loading` — Initial token validation state
- `login(email, password)` — Calls API, stores JWT in localStorage
- `register(email, password)` — Creates account, then auto-login
- `logout()` — Clears JWT from localStorage, resets user state

### 5.4 API Client (`client.ts`)

Axios instance with:
- `baseURL: "/api"` — Proxied by Vite dev server to backend
- Request interceptor attaches `Authorization: Bearer <token>` from localStorage
- Typed API functions for auth, scan, and admin operations
- All response types defined as TypeScript interfaces

### 5.5 Frontend Environment Variables (Vite)

| Variable | Default | Purpose |
|----------|---------|---------|
| `VITE_PORT` | `5173` | Dev server port |
| `VITE_API_PROXY_TARGET` | `http://127.0.0.1:8000` | Backend proxy target |
| `VITE_ALLOWED_EXTENSIONS` | `.py,.js,.java,.zip,.ts,.jsx,.tsx` | Allowed upload file types |
| `VITE_MAX_UPLOAD_MB` | `10` | Max upload size (MB) |
| `VITE_POLL_INTERVAL_MS` | `2000` | Scan status polling interval |

---

## 6. Data Flow — Complete Scan Lifecycle

```
User                           Frontend                     Backend                     External
────                           ────────                     ────────                     ────────

1. Register/Login ───────────▶ POST /auth/login ────────▶ Verify credentials
                             ◀── JWT token + User ◀─────── Create JWT

2. Upload code ─────────────▶ POST /scan/upload ───────▶ Save file to ./uploads/
                             │                          Create ScanSession (PENDING)
                             │                          Extract preview file list
                             │                          Schedule background task
                             ◀── session_id ◀────────────
                             
3. Navigate to               GET /scan/{id}/status ────▶ Return current status
   /analysis/{id} ◀───────── (polls every 2s) ◀─────────◀
                                                         │
                             ┌────────────────────────────┘
                             │  Background Task:
                             ▼
                    ┌─────────────────────┐
                    │ Phase 1: SAST Scan  │──▶ subprocess: bandit
                    │ status=SAST_RUNNING  │──▶ subprocess: semgrep
                    └─────────┬───────────┘
                              │
                    ┌─────────▼───────────┐
                    │ Phase 2: CVE Scan   │──▶ HTTP: OSV.dev API
                    │ status=CVE_RUNNING   │──▶ HTTP: NVD API (fallback)
                    └─────────┬───────────┘
                              │
                    ┌─────────▼───────────┐
                    │ Phase 3: AI         │──▶ HTTP: OpenAI API
                    │ status=AI_RUNNING    │   (top N findings)
                    └─────────┬───────────┘
                              │
                    ┌─────────▼───────────┐
                    │ Generate PDF Report  │──▶ ReportLab
                    │ status=COMPLETED     │
                    └─────────────────────┘

4. Auto-redirect to          GET /scan/{id}/results ───▶ Return findings +        ───▶ OpenAPI
   /results/{id} ◀────────── (with severity filter) ◀─── summary + AI data ◀─────── (on-demand)

5. (Optional)                POST /scan/finding/{id} ──▶ Generate AI explanation ──▶ OpenAI
   "Explain with AI" ◀───── ◀── Updated finding ◀─────── Regenerate PDF report

6. (Optional)                GET /scan/{id}/report ────▶ Regenerate PDF
   Download PDF ◀────────── ◀── neuroshield_report.pdf ◀ (always fresh)
```

---

## 7. Semgrep OWASP Rule Coverage

The expanded rules map to the OWASP Top 10 (2021):

| OWASP Category | Rules |
|----------------|-------|
| A01: Broken Access Control | py-path-traversal-open, js-path-traversal |
| A02: Cryptographic Failures | py-hardcoded-password, py-insecure-random, py-md5-sha1-usage, js-hardcoded-secret, go-hardcoded-secret, java-hardcoded-password, java-insecure-random |
| A03: Injection | py-sql-injection-execute, py-eval-injection, py-exec-injection, py-subprocess-shell-true, py-os-system-injection, js-eval-injection, js-innerhtml-xss, js-sql-injection-template, js-child-process-exec, js-prototype-pollution, java-sql-injection, java-command-injection, go-sql-injection, go-command-injection, php-sql-injection, php-eval-injection |
| A05: Security Misconfiguration | py-flask-debug-true, java-xxe-saxparser, dockerfile-user-root, dockerfile-add-instead-of-copy, java-insecure-deserialization |
| A06: Vulnerable & Outdated Components | CVE Scanner (Phase 2) |
| A08: Software & Data Integrity | py-pickle-deserialization, py-yaml-load-unsafe |

---

## 8. Sample Vulnerable Code

Located in `samples/vulnerable_app/`:

- **`app.py`** — Intentionally vulnerable Python with:
  - Hardcoded API key and password
  - SQL injection (string concatenation in query)
  - Code injection (eval on user input)
  - Weak random number generation (random.randint vs secrets)

- **`requirements.txt`** — Old package versions with known CVEs:
  - `flask==2.0.1`
  - `django==3.2.0`
  - `requests==2.25.0`

Additional multi-language samples in `samples/multilang/`:
- `vuln_go/main.go`, `vuln_java/Vuln.java`, `vuln_js/app.js`, `vuln_php/index.php`, `vuln_python/app.py`

---

## 9. Security Considerations

1. **JWT Authentication** — All scan and admin endpoints require valid JWT tokens
2. **Password Hashing** — bcrypt with auto-generated salts
3. **Role-Based Access** — Admin-only endpoints protected by `require_admin` dependency
4. **File Upload Validation** — Size-limited (configurable), path traversal prevented
5. **CORS** — Configurable allowed origins
6. **SQL Injection Protection** — SQLAlchemy ORM (parameterized queries)
7. **User Isolation** — Users can only access their own scan sessions (admins see all)
8. **AI API Key** — Optional; without it, SAST/CVE results still work

---

## 10. Environment Setup

### Backend `.env` File

```bash
# Required
SECRET_KEY=your-random-secret
OPENAI_API_KEY=sk-your-key-here    # Optional but needed for AI

# Optional overrides
DATABASE_URL=sqlite:///./neuroshield.db
ADMIN_EMAIL=admin@neuroshield.local
ADMIN_PASSWORD=admin123
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

Copy `backend/.env.example` to `backend/.env` and edit values.

### Running the Application

```bash
# Terminal 1 — Backend
cd backend
.venv\Scripts\activate
uvicorn app.main:app --port 8000

# Terminal 2 — Frontend
cd frontend
npm run dev
```

Open `http://localhost:5173` in browser. Default admin login: `admin@neuroshield.local` / `admin123`.

---

## 11. Project Team

| Name | Roll No. | Module |
|------|----------|--------|
| B. Romith Singh | 245323733133 | SAST Engine, Backend API |
| Deepak Jhanwar | 245323733146 | CVE Scanner, NVD Integration |
| Ansh Sugandhi | 245323733131 | AI Explanation, PDF Report |

**Guide:** Mrs. S. Meghana, Assistant Professor, Dept. of CSE — NGIT, Hyderabad
