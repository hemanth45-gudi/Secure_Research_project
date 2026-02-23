"""
api/v1/auth_bp.py   Authentication REST API (v1)
========================================================
Mounted at /api/auth/
"""

from flask import Blueprint, request, jsonify, g, current_app, session
from auth import jwt_required, ACCESS_TOKEN_COOKIE
from core.limiter import limiter
from core.validators import LoginSchema, RegisterSchema, RefreshTokenSchema, validate_json
from services.auth_service import AuthService
from services.user_service import UserService
from core.logging_config import log_audit_event

auth_bp = Blueprint('auth_v1', __name__)

def _make_token_response(tokens, username, role, status=200):
    resp = jsonify({
        'success': True,
        'data': {
            'access_token':  tokens['access_token'],
            'refresh_token': tokens['refresh_token'],
            'username':      username,
            'role':          role,
        }
    })
    resp.set_cookie(
        ACCESS_TOKEN_COOKIE, tokens['access_token'],
        httponly=True, samesite='Lax', max_age=15*60,
        secure=current_app.config.get('SESSION_COOKIE_SECURE', False), path='/',
    )
    return resp, status

@auth_bp.route('/register', methods=['POST'])
@limiter.limit("3 per minute")
@validate_json(RegisterSchema)
def register():
    """
    Register a new user
    ---
    tags: [Authentication]
    parameters:
      - in: body
        name: body
        schema:
          $ref: '#/definitions/Register'
    responses:
      201:
        description: User created successfully
      409:
        description: Username or email already exists
    """
    data = g.validated_data
    
    # Optional: check admin key if role is Admin
    if data['role'] == 'Admin':
        expected = current_app.config.get('ADMIN_REGISTRATION_KEY', 'AdminSecret123!')
        if data.get('admin_key') != expected:
            log_audit_event('register_failed_admin_key', user=data['username'], status='failure')
            return jsonify({'success': False, 'message': 'Invalid admin registration key', 'code': 'FORBIDDEN'}), 403

    try:
        priv_key = UserService.register_user(
            data['username'], data['email'], data['password'], data['role']
        )
        log_audit_event('user_registered', user=data['username'], details={'role': data['role']})
        return jsonify({
            'success': True,
            'message': 'User registered successfully. Store your private key safely.',
            'private_key': priv_key
        }), 201
    except Exception as e:
        log_audit_event('register_failed', user=data['username'], status='failure', details={'error': str(e)})
        raise

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
@validate_json(LoginSchema)
def login():
    """
    Login and get JWT tokens
    ---
    tags: [Authentication]
    parameters:
      - in: body
        name: body
        schema:
          $ref: '#/definitions/Login'
    responses:
      200:
        description: Success
      401:
        description: Invalid credentials
    """
    data     = g.validated_data
    username = data['username'].strip()
    password = data['password']
    
    try:
        tokens = AuthService.login(username, password, ip=request.remote_addr)
        user = UserService.get_user_by_username(username)
        log_audit_event('user_login', user=username)
        return _make_token_response(tokens, username, user['role'])
    except Exception as e:
        log_audit_event('login_failed', user=username, status='failure', details={'error': str(e)})
        raise

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """
    Logout and revoke refresh token
    ---
    tags: [Authentication]
    """
    data = request.get_json(silent=True) or {}
    AuthService.logout(data.get('refresh_token'))
    
    resp = jsonify({'message': 'Logged out successfully'})
    resp.delete_cookie(ACCESS_TOKEN_COOKIE, path='/')
    return resp, 200

@auth_bp.route('/refresh', methods=['POST'])
@limiter.limit("10 per minute")
@validate_json(RefreshTokenSchema)
def refresh():
    """
    Refresh access token
    ---
    tags: [Authentication]
    """
    rt = g.validated_data['refresh_token']
    tokens = AuthService.refresh_access_token(rt)
    
    # We need the username/role for the response and cookie
    payload = AuthService.decode_token(tokens['access_token'])
    return _make_token_response(tokens, payload['sub'], payload['role'])

@auth_bp.route('/me', methods=['GET'])
@jwt_required
def me():
    """
    Get current user profile
    ---
    tags: [Authentication]
    security:
      - BearerAuth: []
    """
    user = UserService.get_user_by_username(g.current_user)
    # Remove sensitive fields
    user.pop('hash', None)
    user.pop('salt', None)
    user.pop('_id', None)
    return jsonify(user), 200
