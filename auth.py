"""
auth.py — JWT Authentication Module
====================================
Provides:
  - generate_tokens()       : Create access + refresh token pair
  - decode_access_token()   : Verify and decode access token
  - decode_refresh_token()  : Verify and decode refresh token
  - jwt_required            : Route decorator — enforces valid access token
  - role_required()         : Route decorator — enforces specific role(s)
"""

import os
import datetime
import jwt
from functools import wraps
from flask import request, jsonify, g, current_app


# ============================================================
# 🔑 JWT SECRETS & EXPIRY CONFIG
# ============================================================
JWT_ACCESS_SECRET  = os.environ.get('JWT_ACCESS_SECRET',  'access_super_secret_change_in_prod')
JWT_REFRESH_SECRET = os.environ.get('JWT_REFRESH_SECRET', 'refresh_super_secret_change_in_prod')
JWT_ACCESS_EXPIRY  = datetime.timedelta(minutes=15)
JWT_REFRESH_EXPIRY = datetime.timedelta(days=7)
JWT_ALGORITHM      = 'HS256'


# ============================================================
# 🏭 TOKEN GENERATION
# ============================================================
def generate_tokens(username: str, role: str) -> dict:
    """
    Generate a JWT access token (15 min) and refresh token (7 days).
    Returns:
        {
            'access_token':  '<jwt>',
            'refresh_token': '<jwt>',
        }
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


# ============================================================
# 🛡️  MIDDLEWARE DECORATORS
# ============================================================
def jwt_required(f):
    """
    Decorator: Protects a route by requiring a valid JWT access token.

    Reads the token from:
        Authorization: Bearer <token>

    On success, sets:
        flask.g.current_user  → username (str)
        flask.g.current_role  → role     (str)

    On failure, returns 401 JSON error.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid Authorization header', 'code': 'TOKEN_MISSING'}), 401

        token = auth_header.split(' ', 1)[1].strip()

        try:
            payload = decode_access_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Access token has expired', 'code': 'TOKEN_EXPIRED'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'error': f'Invalid token: {str(e)}', 'code': 'TOKEN_INVALID'}), 401

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

    Returns 403 JSON error if the user's role is not in required_roles.
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # g.current_role is set by jwt_required
            if not hasattr(g, 'current_role') or g.current_role not in required_roles:
                return jsonify({
                    'error': f'Access denied. Required role(s): {required_roles}',
                    'code':  'INSUFFICIENT_ROLE'
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
