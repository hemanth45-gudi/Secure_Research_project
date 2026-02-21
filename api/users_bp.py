"""
api/users_bp.py   User Management API Blueprint
=================================================
Mounted at: /api/users/

Endpoints:
  GET    /api/users/             list all users (Admin only)
  GET    /api/users/me           current user's profile (any authenticated)
  DELETE /api/users/<username>   delete user + their datasets (Admin only)
  PATCH  /api/users/<username>/role   change user role (Admin only)
"""

import datetime
from flask import Blueprint, request, jsonify, g

from auth import jwt_required, role_required
from core.db    import users, datasets, logs, refresh_tokens
from core.cache import invalidate_user, get_cached_user, cache_user

users_bp = Blueprint('users', __name__)


@users_bp.route('/', methods=['GET'])
@jwt_required
@role_required(['Admin'])
def list_users():
    """GET /api/users/   list all users (without password hashes)."""
    all_users = list(
        users().find({}, {'hash': 0, 'salt': 0, 'public_key': 0})
    )
    for u in all_users:
        u['_id'] = str(u['_id'])
        # Sanitise locked_until
        if 'locked_until' in u:
            u['locked_until'] = str(u['locked_until'])
    return jsonify({'users': all_users, 'count': len(all_users)}), 200


@users_bp.route('/me', methods=['GET'])
@jwt_required
def me():
    """GET /api/users/me   current user profile (cached)."""
    username = g.current_user

    cached = get_cached_user(username)
    if cached:
        return jsonify(cached), 200

    user = users().find_one({'username': username}, {'hash': 0, 'salt': 0, 'public_key': 0})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    user.pop('_id', None)
    if 'locked_until' in user:
        user['locked_until'] = str(user['locked_until'])
    cache_user(username, user)
    return jsonify(user), 200


@users_bp.route('/<username>', methods=['DELETE'])
@jwt_required
@role_required(['Admin'])
def delete_user(username):
    """
    DELETE /api/users/<username>
    Removes user, their refresh tokens, and all datasets they own.
    """
    user = users().find_one({'username': username})
    if not user:
        return jsonify({'error': f'User {username} not found'}), 404

    # Prevent self-deletion
    if username == g.current_user:
        return jsonify({'error': 'Cannot delete your own account', 'code': 'SELF_DELETE'}), 400

    # Remove user data
    users().delete_one({'username': username})
    refresh_tokens().delete_many({'username': username})

    # Remove their datasets
    deleted_datasets = datasets().delete_many({'owner': username})

    invalidate_user(username)

    logs().insert_one({
        'user':   g.current_user,
        'action': f'Deleted user {username} + {deleted_datasets.deleted_count} dataset(s)',
        'time':   str(datetime.datetime.now()),
    })

    return jsonify({
        'message':          f'User {username} deleted',
        'datasets_removed': deleted_datasets.deleted_count,
    }), 200


@users_bp.route('/<username>/role', methods=['PATCH'])
@jwt_required
@role_required(['Admin'])
def change_role(username):
    """
    PATCH /api/users/<username>/role
    Body: { "role": "Admin" | "Researcher" | "Reviewer" }
    """
    VALID_ROLES = {'Admin', 'Researcher', 'Reviewer'}
    data = request.get_json(silent=True) or {}
    new_role = data.get('role', '')

    if new_role not in VALID_ROLES:
        return jsonify({
            'error': f'Invalid role. Must be one of: {sorted(VALID_ROLES)}',
            'code':  'INVALID_ROLE',
        }), 400

    result = users().update_one({'username': username}, {'$set': {'role': new_role}})
    if result.matched_count == 0:
        return jsonify({'error': f'User {username} not found'}), 404

    invalidate_user(username)

    logs().insert_one({
        'user':   g.current_user,
        'action': f'Changed role of {username} to {new_role}',
        'time':   str(datetime.datetime.now()),
    })
    return jsonify({'message': f"Role of {username} updated to {new_role}"}), 200
