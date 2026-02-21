"""
core/limiter.py   Rate Limiting & Brute-Force Protection
==========================================================
Uses Flask-Limiter with Redis storage (falls back to memory for dev).

Brute-force protection:
  - After MAX_LOGIN_ATTEMPTS failed logins, lock account for LOCKOUT_DURATION_MINUTES
  - Stored in MongoDB login_attempts collection
"""

import datetime
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logger = logging.getLogger(__name__)

# Singleton limiter   init_app() called from create_app()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
)


# -- Brute-Force Account Lockout -------------------------------- 

def record_failed_login(username: str, ip: str):
    """
    Increment failed login counter for username+ip.
    If >= MAX_LOGIN_ATTEMPTS, lock the account.
    """
    from flask import current_app
    from core.db import login_attempts as la_col, users as users_col

    max_attempts     = current_app.config.get('MAX_LOGIN_ATTEMPTS', 5)
    lockout_minutes  = current_app.config.get('LOCKOUT_DURATION_MINUTES', 15)
    now              = datetime.datetime.utcnow()

    la_col().update_one(
        {'username': username},
        {
            '$inc': {'attempts': 1},
            '$set': {'last_attempt': now, 'ip': ip},
            '$setOnInsert': {'created_at': now},
        },
        upsert=True,
    )

    doc = la_col().find_one({'username': username})
    if doc and doc.get('attempts', 0) >= max_attempts:
        locked_until = now + datetime.timedelta(minutes=lockout_minutes)
        users_col().update_one(
            {'username': username},
            {'$set': {'locked_until': locked_until}},
        )
        logger.warning(f"[BRUTE FORCE] Account locked: {username} (IP: {ip})")


def clear_failed_logins(username: str):
    """Reset attempt counter on successful login."""
    from core.db import login_attempts as la_col, users as users_col
    la_col().delete_one({'username': username})
    users_col().update_one({'username': username}, {'$unset': {'locked_until': ''}})


def is_account_locked(username: str) -> tuple[bool, str]:
    """
    Returns (is_locked, message).
    Checks the locked_until timestamp in MongoDB users collection.
    """
    from core.db import users as users_col
    user = users_col().find_one({'username': username}, {'locked_until': 1})
    if not user:
        return False, ''
    locked_until = user.get('locked_until')
    if locked_until and datetime.datetime.utcnow() < locked_until:
        remaining = int((locked_until - datetime.datetime.utcnow()).total_seconds() / 60) + 1
        return True, f'Account locked. Try again in {remaining} minute(s).'
    return False, ''
