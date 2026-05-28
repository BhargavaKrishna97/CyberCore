# CyberCore — AI-Powered Cyber Threat Intelligence Platform

A real-time ransomware detection and cyber threat intelligence platform built on Kali Linux using CEH tools.

---

## 🧱 Tech Stack

| Layer     | Technology                              |
|-----------|-----------------------------------------|
| Backend   | Flask, SQLAlchemy, Flask-JWT-Extended   |
| Database  | PostgreSQL                              |
| Frontend  | React + Vite + Tailwind CSS             |
| Security  | Nmap, YARA, VirusTotal API, AbuseIPDB API, Watchdog |
| Dev OS    | Kali Linux                              |

---

## 📁 Project Structure

```
CyberCore/
├── backend/
│   ├── app.py                  # App factory using create_app() pattern
│   ├── extensions.py           # Shared db and jwt instances (avoids circular imports)
│   ├── config.py               # Flask config — DB URI, JWT secret, API keys
│   ├── requirements.txt        # Python dependencies
│   ├── .env                    # Environment variables (never commit this)
│   ├── .env.example            # Template for .env
│   │
│   ├── models/
│   │   ├── scan_result.py      # Stores Nmap scan results
│   │   ├── threat.py           # Threat intelligence records
│   │   └── alert.py            # Ransomware/monitor alerts
│   │
│   ├── routes/
│   │   ├── scan_routes.py      # Nmap port scanning endpoints
│   │   ├── yara_routes.py      # YARA rule-based file scanning
│   │   ├── virustotal_routes.py# VirusTotal hash/file check
│   │   ├── abuseipdb_routes.py # AbuseIPDB IP reputation check
│   │   └── monitor_routes.py   # Real-time ransomware file monitor
│   │
│   └── yara_rules/             # Custom .yar YARA rule files
│
├── frontend/                   # React + Vite frontend (WIP)
├── .gitignore
└── README.md
```

---

## ⚙️ Backend Setup (Kali Linux)

```bash
# 1. Clone the repo
git clone https://github.com/BhargavaKrishna97/CyberCore.git
cd CyberCore/backend

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment variables
cp .env.example .env
nano .env   # fill in DB password, JWT secret, API keys

# 5. Run the backend
python app.py
```

Backend runs at: `http://localhost:5000`

---

## 🔑 Environment Variables (`.env`)

```env
DATABASE_URL=postgresql://postgres:<password>@localhost/cybercore
JWT_SECRET_KEY=your_jwt_secret
VIRUSTOTAL_API_KEY=your_vt_key
ABUSEIPDB_API_KEY=your_abuse_key
```

> ⚠️ Never commit `.env` — it's in `.gitignore`

---

## 🌐 API Endpoints

### Scan (Nmap)
| Method | Endpoint            | Description               |
|--------|---------------------|---------------------------|
| POST   | `/api/scan/`        | Run Nmap port scan        |
| GET    | `/api/scan/history` | Retrieve scan history     |

### YARA
| Method | Endpoint                 | Description                    |
|--------|--------------------------|--------------------------------|
| POST   | `/api/yara/scan-file`    | YARA scan a file by path       |
| POST   | `/api/yara/scan-upload`  | YARA scan an uploaded file     |

### VirusTotal
| Method | Endpoint                       | Description                  |
|--------|--------------------------------|------------------------------|
| POST   | `/api/virustotal/check-hash`   | Check SHA256 hash             |
| POST   | `/api/virustotal/upload`       | Upload file for analysis      |

### AbuseIPDB
| Method | Endpoint                       | Description                  |
|--------|--------------------------------|------------------------------|
| POST   | `/api/abuseipdb/check-ip`      | Check single IP reputation   |
| POST   | `/api/abuseipdb/check-block`   | Check CIDR block             |
| GET    | `/api/abuseipdb/threats`       | List stored threats          |

### Monitor (Ransomware Detection)
| Method | Endpoint                              | Description                    |
|--------|---------------------------------------|--------------------------------|
| POST   | `/api/monitor/start`                  | Start file system monitor      |
| POST   | `/api/monitor/stop`                   | Stop monitor                   |
| GET    | `/api/monitor/alerts`                 | List all alerts                |
| POST   | `/api/monitor/alerts/<id>/resolve`    | Resolve an alert               |

---

## 🔧 Key Fix — Circular Import Resolution

**Problem:** All route files were doing `from app import db`, which caused Python to try importing `app.py` before it finished loading — a circular import loop.

**Solution:** Created `extensions.py` as a neutral module that holds `db` and `jwt`. Neither `app.py` nor routes import from each other — both import from `extensions.py`.

```
Before (broken):
  app.py → imports routes → routes import app.py ❌ circular

After (fixed):
  extensions.py  (db, jwt — no project imports)
       ↑                ↑
   app.py          routes/*.py   ✅ no circular dependency
```

**`extensions.py`**
```python
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager

db  = SQLAlchemy()
jwt = JWTManager()
```

**`app.py`** uses `create_app()` factory pattern and registers all blueprints inside it, importing them only after `db` and `jwt` are initialized.

---

## 🚀 Git & GitHub (Kali Linux)

```bash
# First-time push setup
git remote set-url origin https://<username>:<PAT_TOKEN>@github.com/BhargavaKrishna97/CyberCore.git
git config --global credential.helper store

# Stage and push changes
git add backend/
git commit -m "your message here"
git push origin main
```

> GitHub no longer accepts passwords — use a **Personal Access Token (PAT)** from https://github.com/settings/tokens

---

## 👥 Team

| Member              | Role                              |
|---------------------|-----------------------------------|
| BhargavaKrishna97   | Backend + Security Tools (Flask)  |
| nrevathi17          | Frontend + Dashboard (React/Vite) |

---

## 📌 Status

- [x] Flask backend running on Kali Linux
- [x] PostgreSQL + SQLAlchemy models
- [x] Nmap, YARA, VirusTotal, AbuseIPDB routes
- [x] Real-time ransomware file monitor
- [x] Circular import fix via `extensions.py`
- [ ] JWT authentication
- [ ] React frontend integration
- [ ] Deployment
