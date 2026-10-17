import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env if present
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

APP_ENV = os.getenv("APP_ENV", "development")
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))

# Request Size Limits
MAX_INPUT_BYTES = int(os.getenv("MAX_INPUT_BYTES", "1048576"))  # 1MB
MAX_CONTENT_CHARS = int(os.getenv("MAX_CONTENT_CHARS", "20000"))

# Detection Risk Thresholds (0 to 100)
# 0 - 29: LOW (ALLOW)
# 30 - 69: MEDIUM (REVIEW)
# 70 - 100: HIGH (BLOCK)
RISK_THRESHOLD_MEDIUM = int(os.getenv("RISK_THRESHOLD_MEDIUM", "30"))
RISK_THRESHOLD_HIGH = int(os.getenv("RISK_THRESHOLD_HIGH", "70"))

# AI Provider Settings
AI_PROVIDER = os.getenv("AI_PROVIDER", "none").strip().lower()
AI_PROVIDER_API_KEY = os.getenv("AI_PROVIDER_API_KEY", "").strip()
AI_PROVIDER_BASE_URL = os.getenv("AI_PROVIDER_BASE_URL", "").strip()
AI_MODEL_NAME = os.getenv("AI_MODEL_NAME", "gpt-4o-mini").strip()

# Database
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR / 'firewall_audit.db'}")
SQLITE_DB_PATH = DATA_DIR / "firewall_audit.db"

# ==============================================================================
# Sender Domain Allowlist (TRUSTED_DOMAINS)
# ==============================================================================
# Configure via .env:  TRUSTED_DOMAINS=corp.example,partner.example,acme.test
#
# These are SAMPLE placeholder domains included for local testing ONLY.
# They do not belong to any real organisation. Replace with your actual
# internal or partner domain names before deploying in production.
#
# To add a trusted domain: append it (comma-separated) to TRUSTED_DOMAINS.
# To remove a domain:      remove it from the list.
# Domain matching is case-insensitive and exact (no wildcard/subdomain support).
_raw_trusted = os.getenv(
    "TRUSTED_DOMAINS",
    "corp.example,internal.example,partner.acme.test,security.local,trusted.org.test",
)
TRUSTED_DOMAINS: list[str] = [
    d.strip().lower() for d in _raw_trusted.split(",") if d.strip()
]
