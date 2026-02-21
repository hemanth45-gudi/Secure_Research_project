"""
api/admin_bp.py — Admin-Only API Blueprint
===========================================
Mounted at: /api/admin/

Endpoints:
  GET /api/admin/logs        — paginated audit log (Admin)
  GET /api/admin/stats       — system statistics (Admin)
  DELETE /api/admin/logs     — clear audit logs (Admin)
"""

import datetime
from flask import Blueprint, request, jsonify, g

from auth import jwt_required, role_required
from core.db import logs, users, datasets, refresh_tokens

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/logs', methods=['GET'])
@jwt_required
@role_required(['Admin'])
def get_logs():
    """
    GET /api/admin/logs
    Query params:
      ?page=1&per_page=50&user=<username>&action=<keyword>
    """
    page     = max(1, int(request.args.get('page', 1)))
    per_page = min(200, int(request.args.get('per_page', 50)))
    filter_user   = request.args.get('user', '').strip()
    filter_action = request.args.get('action', '').strip()

    query = {}
    if filter_user:
        query['user']   = filter_user
    if filter_action:
        query['action'] = {'$regex': filter_action, '$options': 'i'}

    total = logs().count_documents(query)
    skip  = (page - 1) * per_page

    all_logs = list(
        logs().find(query, {'_id': 0})
               .sort('time', -1)
               .skip(skip)
               .limit(per_page)
    )

    return jsonify({
        'logs':       all_logs,
        'total':      total,
        'page':       page,
        'per_page':   per_page,
        'pages':      (total + per_page - 1) // per_page,
    }), 200


@admin_bp.route('/logs', methods=['DELETE'])
@jwt_required
@role_required(['Admin'])
def clear_logs():
    """DELETE /api/admin/logs — clear all audit logs."""
    result = logs().delete_many({})
    logs().insert_one({
        'user':   g.current_user,
        'action': f'Cleared {result.deleted_count} audit log entries',
        'time':   str(datetime.datetime.now()),
    })
    return jsonify({'message': f'Cleared {result.deleted_count} log entries'}), 200


@admin_bp.route('/stats', methods=['GET'])
@jwt_required
@role_required(['Admin'])
def stats():
    """GET /api/admin/stats — system overview statistics."""
    now = datetime.datetime.now()

    total_users    = users().count_documents({})
    total_datasets = datasets().count_documents({})
    total_logs     = logs().count_documents({})
    active_tokens  = refresh_tokens().count_documents({})
    locked_users   = users().count_documents({
        'locked_until': {'$gt': now}
    })

    # Role breakdown
    role_pipeline = [
        {'$group': {'_id': '$role', 'count': {'$sum': 1}}}
    ]
    roles = {doc['_id']: doc['count'] for doc in users().aggregate(role_pipeline)}

    # Recent activity (last 24h)
    since = str(now - datetime.timedelta(hours=24))
    recent_logs = logs().count_documents({'time': {'$gte': since}})

    return jsonify({
        'users': {
            'total':          total_users,
            'locked':         locked_users,
            'by_role':        roles,
        },
        'datasets': {
            'total':          total_datasets,
        },
        'tokens': {
            'active_refresh': active_tokens,
        },
        'audit': {
            'total_logs':     total_logs,
            'last_24h':       recent_logs,
        },
        'timestamp': str(now),
    }), 200
