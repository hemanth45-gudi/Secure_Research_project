"""
api/v1/admin_bp.py   Admin REST API (v1)
========================================================
Mounted at /api/admin/
"""

from flask import Blueprint, jsonify
from auth import jwt_required, role_required
from core.db import logs as logs_col, users as users_col, datasets as ds_col

from core.logging_config import log_audit_event

admin_bp = Blueprint('admin_v1', __name__)

@admin_bp.route('/stats', methods=['GET'])
@jwt_required
@role_required(['Admin'])
def stats():
    """
    Get system statistics
    ---
    tags: [Admin]
    security:
      - BearerAuth: []
    """
    try:
        data = {
            'total_users': users_col().count_documents({}),
            'total_datasets': ds_col().count_documents({}),
            'total_logs': logs_col().count_documents({}),
        }
        return jsonify({
            'success': True,
            'data': data
        }), 200
    except Exception as e:
        log_audit_event('admin_stats_failed', status='failure', details={'error': str(e)})
        raise

@admin_bp.route('/logs', methods=['GET'])
@jwt_required
@role_required(['Admin'])
def get_logs():
    """
    Get system audit logs
    ---
    tags: [Admin]
    security:
      - BearerAuth: []
    """
    try:
        all_logs = list(logs_col().find().sort('timestamp', -1).limit(100))
        for l in all_logs:
            l.pop('_id', None)
            if 'timestamp' in l:
                l['timestamp'] = l['timestamp'].isoformat()
        
        return jsonify({
            'success': True,
            'data': {'logs': all_logs}
        }), 200
    except Exception as e:
        log_audit_event('admin_logs_failed', status='failure', details={'error': str(e)})
        raise

@admin_bp.route('/metrics/system', methods=['GET'])
@jwt_required
@role_required(['Admin'])
def system_metrics():
    """
    Get system performance metrics (CPU, RAM, DB Status)
    ---
    tags: [Admin]
    security:
      - BearerAuth: []
    responses:
      200:
        description: System performance data
    """
    import psutil
    import time
    from core.db import get_db
    
    try:
        # Check DB connection
        start_time = time.time()
        get_db().command('ping')
        db_latency = (time.time() - start_time) * 1000 # ms
        
        data = {
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            'db_latency_ms': round(db_latency, 2),
            'uptime_seconds': int(time.time() - psutil.boot_time())
        }
        return jsonify({
            'success': True,
            'data': data
        }), 200
    except Exception as e:
        log_audit_event('admin_metrics_failed', status='failure', details={'error': str(e)})
        raise
