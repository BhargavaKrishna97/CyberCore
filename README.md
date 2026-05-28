# CyberCore — AI-Powered Cyber Threat Intelligence Platform

A real-time ransomware detection and cyber threat intelligence platform using CEH tools.

## Tech Stack
- **Backend**: Flask, PostgreSQL, SQLAlchemy
- **Frontend**: React + Vite + Tailwind CSS
- **Security Tools**: Nmap, YARA, VirusTotal, AbuseIPDB, Watchdog

## Backend Setup (Kali Linux)

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in your API keys and DB password
python app.py
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/scan/ | Run Nmap port scan |
| GET  | /api/scan/history | Scan history |
| POST | /api/yara/scan-file | YARA scan a file path |
| POST | /api/yara/scan-upload | YARA scan uploaded file |
| POST | /api/virustotal/check-hash | Check SHA256 on VirusTotal |
| POST | /api/virustotal/upload | Upload file to VirusTotal |
| POST | /api/abuseipdb/check-ip | Check IP reputation |
| POST | /api/monitor/start | Start ransomware monitor |
| POST | /api/monitor/stop | Stop monitor |
| GET  | /api/monitor/alerts | List all alerts |

## Team
- Member 1: Frontend + Dashboard
- Member 2: Backend + Security Tools (this repo)
