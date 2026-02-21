"""
config.py — Environment-Aware Configuration
============================================
Usage:
    from config import config_map
    app.config.from_object(config_map[env])

All values read from environment variables (populated via .env / Docker env).
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # ── Flask ───────────────────────────────────────────────
    SECRET_KEY  = os.environ.get('SECRET_KEY',  'change-me-in-production')
    DEBUG       = False
    TESTING     = False

    # ── MongoDB ─────────────────────────────────────────────
    MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
    MONGO_DB  = os.environ.get('MONGO_DB',  'secure_research_db')

    # ── JWT ─────────────────────────────────────────────────
    JWT_ACCESS_SECRET  = os.environ.get('JWT_ACCESS_SECRET',  'access_super_secret_change_in_prod')
    JWT_REFRESH_SECRET = os.environ.get('JWT_REFRESH_SECRET', 'refresh_super_secret_change_in_prod')

    # ── Redis ───────────────────────────────────────────────
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')

    # ── Flask-Caching ───────────────────────────────────────
    CACHE_TYPE              = 'RedisCache'
    CACHE_REDIS_URL         = REDIS_URL
    CACHE_DEFAULT_TIMEOUT   = 300          # 5 minutes

    # ── Flask-Limiter ───────────────────────────────────────
    RATELIMIT_STORAGE_URI   = REDIS_URL
    RATELIMIT_DEFAULT       = '200 per day;50 per hour'
    RATELIMIT_HEADERS_ENABLED = True

    # ── Cloud Storage (S3 / MinIO) ──────────────────────────
    STORAGE_BACKEND  = os.environ.get('STORAGE_BACKEND', 'minio')   # 'minio' | 's3'
    S3_BUCKET        = os.environ.get('S3_BUCKET', 'secure-research-files')
    AWS_ACCESS_KEY   = os.environ.get('AWS_ACCESS_KEY_ID',     'minioadmin')
    AWS_SECRET_KEY   = os.environ.get('AWS_SECRET_ACCESS_KEY', 'minioadmin')
    S3_ENDPOINT_URL  = os.environ.get('S3_ENDPOINT_URL', 'http://localhost:9000')  # MinIO default
    S3_REGION        = os.environ.get('AWS_REGION', 'us-east-1')

    # ── Email (OTP / MFA) ───────────────────────────────────
    EMAIL_ADDRESS = os.environ.get('EMAIL_ADDRESS', '')
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', '')

    # ── Security ────────────────────────────────────────────
    ADMIN_REGISTRATION_KEY   = os.environ.get('ADMIN_REGISTRATION_KEY', 'AdminSecret123!')
    MAX_LOGIN_ATTEMPTS       = int(os.environ.get('MAX_LOGIN_ATTEMPTS', '5'))
    LOCKOUT_DURATION_MINUTES = int(os.environ.get('LOCKOUT_DURATION_MINUTES', '15'))


class DevelopmentConfig(Config):
    DEBUG = True
    # Use in-memory cache & limiter so Redis isn't required for local dev
    CACHE_TYPE            = 'SimpleCache'
    RATELIMIT_STORAGE_URI = 'memory://'


class ProductionConfig(Config):
    DEBUG = False
    # In production, Redis is mandatory — enforce via docker-compose / env
    CACHE_TYPE = 'RedisCache'


class TestingConfig(Config):
    TESTING               = True
    MONGO_DB              = 'secure_research_test_db'
    CACHE_TYPE            = 'SimpleCache'
    RATELIMIT_STORAGE_URI = 'memory://'


config_map = {
    'development': DevelopmentConfig,
    'production':  ProductionConfig,
    'testing':     TestingConfig,
    'default':     DevelopmentConfig,
}
