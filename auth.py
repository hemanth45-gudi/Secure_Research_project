"""
auth.py   Authentication Middleware & Decorators
========================================================
Provides jwt_required and role_required decorators.
Checks both Authorization header and srp_access_token cookie.
"""

from functools import wraps
from flask import request, jsonify, redirect, url_for, g, current_app, flash
from services.auth_service import AuthService

ACCESS_TOKEN_COOKIE = 'srp_access_token'

def _extract_token():
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header.split(' ', 1)[1].strip()
    return request.cookies.get(ACCESS_TOKEN_COOKIE)

def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _extract_token()
        wants_json = (
            'application/json' in request.accept_mimetypes.values()
            or request.headers.get('Authorization', '').startswith('Bearer ')
            or '/api/' in request.path
        )

        if not token:
            if wants_json:
                return jsonify({'success': False, 'message': 'Missing token', 'code': 'TOKEN_MISSING'}), 401
            return redirect(url_for('login'))

        try:
            payload = AuthService.decode_token(token)
            g.current_user = payload['sub']
            g.current_role = payload['role']
        except Exception as e:
            if wants_json:
                # AuthService.decode_token already raises UnauthorizedException 
                # but we catch it here for safety or to format it
                from core.exceptions import UnauthorizedException
                if isinstance(e, UnauthorizedException):
                    return jsonify({'success': False, 'message': e.message, 'code': e.code}), e.status_code
                return jsonify({'success': False, 'message': str(e), 'code': 'TOKEN_INVALID'}), 401
            
            resp = redirect(url_for('login'))
            resp.delete_cookie(ACCESS_TOKEN_COOKIE)
            flash("Session expired or invalid. Please login again.", "warning")
            return resp

        return f(*args, **kwargs)
    return decorated

def role_required(required_roles: list):
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
                        'success': False,
                        'message': f'Access denied. Required role(s): {required_roles}',
                        'code':  'INSUFFICIENT_ROLE'
                    }), 403
                
                flash(f'ACCESS DENIED. Required role: {", ".join(required_roles)}', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator

