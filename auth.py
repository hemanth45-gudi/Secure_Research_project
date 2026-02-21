"""
auth.py — JWT Authentication Module
====================================
Provides:
  - generate_tokens()       : Create access + refresh token pair
  - decode_access_token()   : Verify and decode access token
  - decode_refresh_token()  : Verify and decode refresh token
  - jwt_required            : Route decorator — enforces valid access token
                              Reads from cookie (browser nav) OR Authorization header (API)
  - role_required()         : Route decorator — enforces specific role(s)

TOKEN DELIVERY STRATEGY
-----------------------
Browser page navigations never send custom headers, so tokens stored only in
localStorage would never reach Flask. The fix: set an HttpOnly cookie on login
so the browser automatically delivers the JWT on every page request. API clients
can still use the Authorization: Bearer header — jwt_required checks both.

Priority: Authorization header → cookie
"""

import os
import datetime
import jwt
from functools import wraps
from flask import request, jsonify, redirect, url_for, g


# ============================================================
# 🔑 JWT SECRETS & EXPIRY CONFIG
# ============================================================
JWT_ACCESS_SECRET  = os.environ.get('JWT_ACCESS_SECRET',  'access_super_secret_change_in_prod')
JWT_REFRESH_SECRET = os.environ.get('JWT_REFRESH_SECRET', 'refresh_super_secret_change_in_prod')
JWT_ACCESS_EXPIRY  = datetime.timedelta(minutes=15)
JWT_REFRESH_EXPIRY = datetime.timedelta(days=7)
JWT_ALGORITHM      = 'HS256'

# Cookie name used for the access token
ACCESS_TOKEN_COOKIE = 'srp_access_token'


# ============================================================
# 🏭 TOKEN GENERATION
# ============================================================
def generate_tokens(username: str, role: str) -> dict:
    """
    Generate a JWT access token (15 min) and refresh token (7 days).
    Returns: { 'access_token': '<jwt>', 'refresh_token': '<jwt>' }
    """
    now = datetime.datetime.utcnow()

    access_payload = {
        'sub':  username,
        'role': role,
        'iat':  now,
        'exp':  now + JWT_ACCESS_EXPIRY,
        'type': 'access'
    }

    refresh_payload = {
        'sub':  username,
        'role': role,
        'iat':  now,
        'exp':  now + JWT_REFRESH_EXPIRY,
        'type': 'refresh'
    }

    access_token  = jwt.encode(access_payload,  JWT_ACCESS_SECRET,  algorithm=JWT_ALGORITHM)
    refresh_token = jwt.encode(refresh_payload, JWT_REFRESH_SECRET, algorithm=JWT_ALGORITHM)

    return {
        'access_token':  access_token,
        'refresh_token': refresh_token,
    }


# ============================================================
# 🔓 TOKEN DECODING / VALIDATION
# ============================================================
def decode_access_token(token: str) -> dict:
    """
    Decode and validate an access token.
    Raises jwt.ExpiredSignatureError or jwt.InvalidTokenError on failure.
    """
    payload = jwt.decode(token, JWT_ACCESS_SECRET, algorithms=[JWT_ALGORITHM])
    if payload.get('type') != 'access':
        raise jwt.InvalidTokenError('Not an access token')
    return payload


def decode_refresh_token(token: str) -> dict:
    """
    Decode and validate a refresh token.
    Raises jwt.ExpiredSignatureError or jwt.InvalidTokenError on failure.
    """
    payload = jwt.decode(token, JWT_REFRESH_SECRET, algorithms=[JWT_ALGORITHM])
    if payload.get('type') != 'refresh':
        raise jwt.InvalidTokenError('Not a refresh token')
    return payload


def _extract_token_from_request() -> str | None:
    """
    Extract access token from the request.
    Priority: Authorization: Bearer header → HttpOnly cookie

    Returns the raw token string, or None if not found.
    """
    # 1️⃣  Check Authorization header (API clients, fetch() calls)
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header.split(' ', 1)[1].strip()

    # 2️⃣  Fall back to HttpOnly cookie (browser page navigations)
    return request.cookies.get(ACCESS_TOKEN_COOKIE)


# ============================================================
# 🛡️  MIDDLEWARE DECORATORS
# ============================================================
def jwt_required(f):
    """
    Decorator: Protects a route by requiring a valid JWT access token.

    Token lookup order:
      1. Authorization: Bearer <token>   (API / fetch calls)
      2. Cookie srp_access_token         (browser page navigations)

    On success, sets:
        flask.g.current_user  → username (str)
        flask.g.current_role  → role     (str)

    On failure:
      - JSON response (API)    → 401
      - Page route (HTML)      → redirect to /login
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _extract_token_from_request()

        # Determine whether the caller expects HTML or JSON
        wants_json = (
            'application/json' in request.accept_mimetypes.values()
            or request.headers.get('Authorization', '').startswith('Bearer ')
        )

        if not token:
            if wants_json:
                return jsonify({'error': 'Missing token', 'code': 'TOKEN_MISSING'}), 401
            return redirect(url_for('login'))

        try:
            payload = decode_access_token(token)
        except jwt.ExpiredSignatureError:
            if wants_json:
                return jsonify({'error': 'Access token has expired', 'code': 'TOKEN_EXPIRED'}), 401
            # On cookie-based expiry, redirect to login for re-authentication
            resp = redirect(url_for('login'))
            resp.delete_cookie(ACCESS_TOKEN_COOKIE)
            return resp
        except jwt.InvalidTokenError as e:
            if wants_json:
                return jsonify({'error': f'Invalid token: {str(e)}', 'code': 'TOKEN_INVALID'}), 401
            resp = redirect(url_for('login'))
            resp.delete_cookie(ACCESS_TOKEN_COOKIE)
            return resp

        # Inject user info into Flask request context
        g.current_user = payload['sub']
        g.current_role = payload['role']

        return f(*args, **kwargs)
    return decorated


def role_required(required_roles: list):
    """
    Decorator: Enforces role-based access control.
    Must be used AFTER @jwt_required so that g.current_role is populated.

    Usage:
        @app.route('/admin')
        @jwt_required
        @role_required(['Admin'])
        def admin_panel():
            ...

    Returns 403 JSON or renders an access-denied page.
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'current_role') or g.current_role not in required_roles:
                wants_json = (
                    'application/json' in request.accept_mimetypes.values()
                    or request.headers.get('Authorization', '').startswith('Bearer ')
                )
                if wants_json:
                    return jsonify({
                        'error': f'Access denied. Required role(s): {required_roles}',
                        'code':  'INSUFFICIENT_ROLE'
                    }), 403
                # For browser requests, show a simple access-denied message
                from flask import flash
                flash(f'⛔ ACCESS DENIED. Required role: {", ".join(required_roles)}', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator
