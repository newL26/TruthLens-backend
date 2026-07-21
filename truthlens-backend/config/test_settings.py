"""
config/test_settings.py — Test settings using SQLite (no PostgreSQL required)
"""
from .settings import *  # noqa

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "test_db.sqlite3",
    }
}

# Use mock AI for all tests
AI_PROVIDER = "mock"
# Silence logs during tests
LOGGING["root"]["level"] = "WARNING"
