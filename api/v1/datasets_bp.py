"""
api/v1/datasets_bp.py   Dataset REST API (v1)
========================================================
Mounted at /api/datasets/
"""

from flask import Blueprint, request, jsonify, g
from auth import jwt_required, role_required
from services.dataset_service import DatasetService
from core.validators import DatasetUploadSchema, validate_json
from core.logging_config import log_audit_event

datasets_bp = Blueprint('datasets_v1', __name__)

@datasets_bp.route('/', methods=['GET'])
@jwt_required
@role_required(['Reviewer', 'Admin'])
def list_datasets():
    """
    List all active datasets
    ---
    tags: [Datasets]
    security:
      - BearerAuth: []
    responses:
      200:
        description: List of datasets
    """
    datasets = DatasetService.get_all_active_datasets()
    return jsonify({
        'success': True,
        'data': {'datasets': datasets}
    }), 200

@datasets_bp.route('/upload', methods=['POST'])
@jwt_required
@role_required(['Researcher'])
def upload():
    """
    Upload a new dataset (Supports JSON metadata OR Multipart Form)
    """
    # 1. Get metadata (description)
    description = None
    if request.is_json:
        description = request.get_json().get('description')
    else:
        description = request.form.get('description')

    private_key_file = request.files.get('private_key')
    files = request.files.getlist('files[]')
    durations = request.form.getlist('durations[]')

    if not description or not private_key_file or not files:
        err_msg = 'Missing description, files or private key'
        log_audit_event('dataset_upload_failed', user=g.current_user, status='failure', details={'error': err_msg})
        return jsonify({'success': False, 'message': err_msg, 'code': 'BAD_REQUEST'}), 400

    try:
        pk_pem = private_key_file.read()
        count = DatasetService.upload_dataset(g.current_user, description, pk_pem, files, durations)
        
        log_audit_event('dataset_uploaded', user=g.current_user, details={'count': count})
        return jsonify({
            'success': True,
            'message': f'{count} file(s) uploaded successfully',
            'data': {'count': count}
        }), 201
    except Exception as e:
        log_audit_event('dataset_upload_failed', user=g.current_user, status='failure', details={'error': str(e)})
        raise

@datasets_bp.route('/<dataset_id>', methods=['DELETE'])
@jwt_required
@role_required(['Researcher', 'Admin'])
def delete_dataset(dataset_id):
    """
    Delete a dataset (Not fully implemented)
    """
    return jsonify({'success': False, 'message': 'Dataset deletion not fully implemented', 'code': 'NOT_IMPLEMENTED'}), 501
