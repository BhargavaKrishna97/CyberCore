import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg://postgres:password@localhost:5432/cyber_platform"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "jwt-dev-secret")

    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")

    REDIS_URL    = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    MONITOR_PATH = os.getenv("MONITOR_PATH", "/tmp/monitor_test")

    YARA_RULES_DIR = os.path.join(os.path.dirname(__file__), "yara_rules")
