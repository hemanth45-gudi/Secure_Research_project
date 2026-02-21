"""
api/auth_bp.py — Authentication REST API Blueprint
====================================================
Mounted at: /api/auth/

Endpoints:
  POST /api/auth/login      — credential check → tokens + cookie
  POST /api/auth/logout     — revoke refresh token + clear cookie
  POST /api/auth/refresh    — exchange refresh token → new access token
  POST /api/auth/register   — register new user (triggers OTP via email)
  POST /api/auth/verify     — verify OTP → complete registration
  GET  /api/auth/me         — current user info (jwt_required)

Security:
  - Rate limited: 5/min on login, 3/min on register
  - Brute force lockout after MAX_LOGIN_ATTEMPTS failures
  - Input validated via Marshmallow
"""

import base64
import datetime
import hashlib
import os
import random
import smtplib
import re
from email.message import EmailMessage

from flask import Blueprint, request, jsonify, g, current_app, session

from auth import (
    generate_tokens, decode_refresh_token, jwt_required,
    ACCESS_TOKEN_COOKIE,
)
from core.db       import users, refresh_tokens, logs, login_attempts
from core.limiter  import limiter, record_failed_login, clear_failed_logins, is_account_locked
from core.cache    import cache_user, get_cached_user, invalidate_user
from core.validators import LoginSchema, RegisterSchema, RefreshTokenSchema, validate_json

auth_bp = Blueprint('auth', __name__)


# ── Helpers ─────────────────────────────────────────────────

def _generate_salt() -> str:
    return base64.b64encode(os.urandom(16)).decode('utf-8')


def _hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((password + salt).encode()).hexdigest()


def _generate_rsa_keys():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_priv = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pem_pub = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_priv, pem_pub


def _send_otp_email(to_email: str, otp: str) -> bool:
    email_addr = current_app.config.get('EMAIL_ADDRESS', '')
    email_pass = current_app.config.get('EMAIL_PASSWORD', '')
    try:
        if not email_addr or not email_pass:
            print(f"\n[WARN EMAIL] Not configured. OTP: {otp}\n", flush=True)
            return True
        msg = EmailMessage()
        msg.set_content(f"Your Secure Research Portal OTP is: {otp}")
        msg['Subject'] = 'Login Verification Code'
        msg['From']    = email_addr
        msg['To']      = to_email
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(email_addr, email_pass)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"\n[ERROR EMAIL FAILED] {e} | OTP: {otp}\n", flush=True)
        return True  # Return True so registration can proceed even if email fails


def _make_token_response(access_token: str, refresh_token: str,
                          username: str, role: str, status: int = 200):
    """Build JSON response + set HttpOnly cookie."""
    resp = jsonify({
        'access_token':  access_token,
        'refresh_token': refresh_token,
        'username':      username,
        'role':          role,
    })
    resp.set_cookie(
        ACCESS_TOKEN_COOKIE,
        access_token,
        httponly  = True,
        samesite  = 'Lax',
        max_age   = 15 * 60,
        secure    = current_app.config.get('SESSION_COOKIE_SECURE', False),
        path      = '/',
    )
    return resp, status


# ── Routes ──────────────────────────────────────────────────

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
@validate_json(LoginSchema)
def login():
    """
    POST /api/auth/login
    Body: { "username": "...", "password": "..." }
    Returns: { access_token, refresh_token, username, role } + HttpOnly cookie
    """
    data     = g.validated_data
    username = data['username'].strip()
    password = data['password']
    ip       = request.remote_addr

    # Brute-force check
    locked, msg = is_account_locked(username)
    if locked:
        return jsonify({'error': msg, 'code': 'ACCOUNT_LOCKED'}), 429

    user = users().find_one({'username': username})
    if not user or user.get('hash') != _hash_password(password, user.get('salt', '')):
        record_failed_login(username, ip)
        return jsonify({'error': 'Invalid username or password', 'code': 'INVALID_CREDENTIALS'}), 401

    # Successful login
    clear_failed_logins(username)

    tokens  = generate_tokens(username, user['role'])
    now     = datetime.datetime.utcnow()

    # Store refresh token
    refresh_tokens().insert_one({
        'username':      username,
        'refresh_token': tokens['refresh_token'],
        'issued_at':     now,
        'expires_at':    now + datetime.timedelta(days=7),
    })

    # Cache user info
    cache_user(username, {'username': username, 'role': user['role'], 'email': user.get('email', '')})

    logs().insert_one({'user': username, 'action': 'JWT Login', 'time': str(datetime.datetime.now())})

    return _make_token_response(tokens['access_token'], tokens['refresh_token'], username, user['role'])


@auth_bp.route('/logout', methods=['POST'])
def logout():
    """
    POST /api/auth/logout
    Body: { "refresh_token": "..." }  (optional)
    Clears cookie + revokes refresh token from DB.
    """
    data          = request.get_json(silent=True) or {}
    refresh_token = data.get('refresh_token')

    if refresh_token:
        refresh_tokens().delete_one({'refresh_token': refresh_token})

    resp = jsonify({'message': 'Logged out successfully'})
    resp.delete_cookie(ACCESS_TOKEN_COOKIE, path='/')
    return resp, 200


@auth_bp.route('/refresh', methods=['POST'])
@limiter.limit("10 per minute")
@validate_json(RefreshTokenSchema)
def refresh():
    """
    POST /api/auth/refresh
    Body: { "refresh_token": "..." }
    Returns: { "access_token": "..." } + rotates cookie
    """
    import jwt as _jwt
    from auth import JWT_ACCESS_SECRET, JWT_ACCESS_EXPIRY, JWT_ALGORITHM

    rt = g.validated_data['refresh_token']

    try:
        payload = decode_refresh_token(rt)
    except Exception as e:
        return jsonify({'error': str(e), 'code': 'TOKEN_INVALID'}), 401

    stored = refresh_tokens().find_one({'refresh_token': rt})
    if not stored:
        return jsonify({'error': 'Refresh token revoked', 'code': 'TOKEN_REVOKED'}), 401

    now = datetime.datetime.utcnow()
    new_access_token = _jwt.encode(
        {'sub': payload['sub'], 'role': payload['role'],
         'iat': now, 'exp': now + JWT_ACCESS_EXPIRY, 'type': 'access'},
        JWT_ACCESS_SECRET, algorithm=JWT_ALGORITHM,
    )

    resp = jsonify({'access_token': new_access_token})
    resp.set_cookie(
        ACCESS_TOKEN_COOKIE, new_access_token,
        httponly=True, samesite='Lax', max_age=15*60,
        secure=current_app.config.get('SESSION_COOKIE_SECURE', False), path='/',
    )
    return resp, 200


@auth_bp.route('/register', methods=['POST'])
@limiter.limit("3 per minute")
@validate_json(RegisterSchema)
def register():
    """
    POST /api/auth/register
    Body: { username, email, password, role, admin_key? }
    Sends OTP to email — complete via POST /api/auth/verify
    """
    data      = g.validated_data
    username  = data['username']
    email     = data['email']
    password  = data['password']
    role      = data['role']
    admin_key = data.get('admin_key', '')

    # Validate admin key if role is Admin
    if role == 'Admin':
        expected = current_app.config.get('ADMIN_REGISTRATION_KEY', 'AdminSecret123!')
        if admin_key != expected:
            return jsonify({'error': 'Invalid Admin Registration Key', 'code': 'INVALID_ADMIN_KEY'}), 403

    # Check username unique
    if users().find_one({'username': username}):
        return jsonify({'error': 'Username already exists', 'code': 'USERNAME_TAKEN'}), 409

    # Generate and store OTP in session (OTP flow)
    otp = str(random.randint(100000, 999999))
    from flask import session
    session['pending_reg'] = {'username': username, 'email': email,
                              'password': password, 'role': role}
    session['otp']         = otp

    _send_otp_email(email, otp)

    return jsonify({
        'message': 'OTP sent to email. Verify at POST /api/auth/verify',
    }), 200


@auth_bp.route('/verify', methods=['POST'])
@limiter.limit("5 per minute")
def verify():
    """
    POST /api/auth/verify
    Body: { "otp": "123456" }
    Completes registration if OTP matches.
    """
    from flask import session
    data = request.get_json(silent=True) or {}
    otp  = data.get('otp', '').strip()

    if 'pending_reg' not in session or 'otp' not in session:
        return jsonify({'error': 'No pending registration', 'code': 'NO_PENDING_REG'}), 400

    if otp != session['otp']:
        return jsonify({'error': 'Invalid OTP', 'code': 'INVALID_OTP'}), 400

    reg      = session.pop('pending_reg')
    session.pop('otp', None)

    salt     = _generate_salt()
    priv_key, pub_key = _generate_rsa_keys()

    users().insert_one({
        'username':   reg['username'],
        'email':      reg['email'],
        'hash':       _hash_password(reg['password'], salt),
        'salt':       salt,
        'role':       reg['role'],
        'public_key': pub_key,
        'created_at': datetime.datetime.utcnow(),
    })

    logs().insert_one({
        'user':   reg['username'],
        'action': f"Registered as {reg['role']}",
        'time':   str(datetime.datetime.now()),
    })

    return jsonify({
        'message':     'Registration successful',
        'username':    reg['username'],
        'role':        reg['role'],
        'private_key': priv_key.decode('utf-8'),   # User must save this!
    }), 201


@auth_bp.route('/me', methods=['GET'])
@jwt_required
def me():
    """GET /api/auth/me — return current user profile."""
    username = g.current_user

    cached = get_cached_user(username)
    if cached:
        return jsonify(cached), 200

    user = users().find_one({'username': username}, {'hash': 0, 'salt': 0, 'public_key': 0})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    user.pop('_id', None)
    cache_user(username, user)
    return jsonify(user), 200
