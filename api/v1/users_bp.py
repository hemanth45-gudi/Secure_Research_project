"""
api/v1/users_bp.py   User Management REST API (v1)
========================================================
Mounted at /api/users/
"""

from flask import Blueprint, jsonify, g
from auth import jwt_required, role_required
from services.user_service import UserService

from core.logging_config import log_audit_event

users_bp = Blueprint('users_v1', __name__)

@users_bp.route('/', methods=['GET'])
@jwt_required
@role_required(['Admin'])
def list_users():
    """
    List all users (Admin only)
    ---
    tags: [Users]
    security:
      - BearerAuth: []
    """
    try:
        users = UserService.get_all_users()
        # Remove sensitive info
        for u in users.values():
            u.pop('hash', None)
            u.pop('salt', None)
            u.pop('_id', None)
        return jsonify({
            'success': True,
            'data': {'users': list(users.values())}
        }), 200
    except Exception as e:
        log_audit_event('admin_list_users_failed', status='failure', details={'error': str(e)})
        raise

@users_bp.route('/<username>', methods=['DELETE'])
@jwt_required
@role_required(['Admin'])
def delete_user(username):
    """
    Delete a user (Admin only)
    ---
    tags: [Users]
    security:
      - BearerAuth: []
    """
    try:
        UserService.delete_user(username)
        log_audit_event('admin_deleted_user', user=g.current_user, details={'target': username})
        return jsonify({
            'success': True,
            'message': f'User {username} deleted successfully'
        }), 200
    except Exception as e:
        log_audit_event('admin_delete_user_failed', status='failure', details={'target': username, 'error': str(e)})
        raise
