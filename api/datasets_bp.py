"""
api/datasets_bp.py   Dataset REST API Blueprint
=================================================
Mounted at: /api/datasets/

Endpoints:
  GET    /api/datasets/                 list all datasets (Reviewer / Admin)
  POST   /api/datasets/upload           upload file(s) -> S3 (Researcher)
  GET    /api/datasets/<id>             get dataset metadata
  GET    /api/datasets/<id>/download/<filename>   pre-signed download URL
  DELETE /api/datasets/<id>             delete dataset (Admin or owner)

Security: all routes @jwt_required, role checked per operation.
Caching:  dataset list cached in Redis for 5 min.
Storage:  files stored encrypted in S3/MinIO.
"""

import base64
import datetime
import hashlib
import logging
from bson import ObjectId

from flask import Blueprint, request, jsonify, g
from werkzeug.utils import secure_filename

from auth import jwt_required, role_required
from core.db        import datasets, logs, users
from core.cache     import cache_datasets, get_cached_datasets, invalidate_datasets
from core.s3_storage import upload_file, generate_presigned_url, delete_file, ensure_bucket_exists

logger = logging.getLogger(__name__)

datasets_bp = Blueprint('datasets', __name__)


# -- Helpers ------------------------------------------------ 

def _sign_data(data_bytes: bytes, private_key_pem: bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization
    priv = serialization.load_pem_private_key(private_key_pem, password=None)
    sig  = priv.sign(
        data_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode()


def _verify_signature(data_bytes: bytes, sig_b64: str, pub_key_pem: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization
    try:
        pub = serialization.load_pem_public_key(pub_key_pem)
        pub.verify(
            base64.b64decode(sig_b64), data_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# -- Routes --------------------------------------------------

@datasets_bp.route('/', methods=['GET'])
@jwt_required
@role_required(['Reviewer', 'Admin'])
def list_datasets():
    """
    GET /api/datasets/
    Returns metadata for all active (non-expired) datasets.
    Response is cached for 5 minutes.
    """
    cache_key = 'all'
    cached = get_cached_datasets(cache_key)
    if cached:
        return jsonify({'datasets': cached, 'cached': True}), 200

    now  = datetime.datetime.now()
    result = []

    for ds in datasets().find():
        owner_doc = users().find_one({'username': ds['owner']}, {'public_key': 1})
        if not owner_doc:
            continue

        active_files = [
            {
                'filename':  f['filename'],
                'expiry':    str(f.get('expiry_time', '')),
                's3_key':    f.get('s3_key', ''),
                'signature': f.get('signature', ''),
            }
            for f in ds.get('files', [])
            if now < f.get('expiry_time', now)
        ]

        if active_files:
            result.append({
                'id':          str(ds['_id']),
                'owner':       ds['owner'],
                'description': ds.get('description', ''),
                'upload_time': str(ds.get('upload_time', '')),
                'files':       active_files,
            })

    cache_datasets(cache_key, result, timeout=300)
    logs().insert_one({'user': g.current_user, 'action': 'Listed datasets', 'time': str(datetime.datetime.now())})
    return jsonify({'datasets': result, 'cached': False}), 200


@datasets_bp.route('/upload', methods=['POST'])
@jwt_required
@role_required(['Researcher'])
def upload():
    """
    POST /api/datasets/upload
    Form-data:
      - description    (str)
      - private_key    (file, PEM)
      - files[]        (one or more files)
      - durations[]    (expiry in minutes, one per file)

    Files are encrypted with Fernet, then stored in S3/MinIO.
    Metadata (s3_key, signature, expiry) stored in MongoDB.
    """
    from cryptography.fernet import Fernet

    try:
        ensure_bucket_exists()
    except Exception as e:
        logger.warning(f"[UPLOAD] Bucket check failed: {e}   continuing without S3")

    description = request.form.get('description', '').strip()
    if not description:
        return jsonify({'error': 'description is required', 'code': 'BAD_REQUEST'}), 400

    private_key_file = request.files.get('private_key')
    if not private_key_file:
        return jsonify({'error': 'private_key file is required', 'code': 'BAD_REQUEST'}), 400

    private_key_pem = private_key_file.read()
    files_list      = request.files.getlist('files[]')
    durations       = request.form.getlist('durations[]')

    if not files_list:
        return jsonify({'error': 'At least one file is required', 'code': 'BAD_REQUEST'}), 400

    uploaded = []
    errors   = []

    for i, file in enumerate(files_list):
        if not file or file.filename == '':
            continue

        try:
            duration_min = int(durations[i]) if i < len(durations) else 60
        except (ValueError, IndexError):
            duration_min = 60

        try:
            raw_bytes = file.read()
            fn        = secure_filename(file.filename)

            # Sign with researcher's private key
            signature = _sign_data(raw_bytes, private_key_pem)

            # Encrypt with Fernet (AES-128-CBC)
            fernet_key  = Fernet.generate_key()
            enc_bytes   = Fernet(fernet_key).encrypt(raw_bytes)

            # Upload to S3/MinIO (stores encrypted bytes)
            s3_key = upload_file(enc_bytes, fn, g.current_user)

            expiry_time = datetime.datetime.now() + datetime.timedelta(minutes=duration_min)

            uploaded.append({
                'filename':          fn,
                's3_key':            s3_key,
                'fernet_key':        fernet_key.decode(),  # stored in MongoDB (not S3)
                'signature':         signature,
                'expiry_time':       expiry_time,
                'size_bytes':        len(raw_bytes),
                'content_type':      file.content_type or 'application/octet-stream',
            })

        except Exception as e:
            logger.error(f"[UPLOAD] Error processing {file.filename}: {e}")
            errors.append({'filename': file.filename, 'error': str(e)})

    if not uploaded:
        return jsonify({'error': 'No files could be uploaded', 'errors': errors}), 400

    dataset_id = datasets().insert_one({
        'owner':       g.current_user,
        'description': description,
        'files':       uploaded,
        'upload_time': datetime.datetime.now(),
    }).inserted_id

    invalidate_datasets('all')

    logs().insert_one({
        'user':   g.current_user,
        'action': f'Uploaded {len(uploaded)} file(s) -> dataset {dataset_id}',
        'time':   str(datetime.datetime.now()),
    })

    # Receipt
    ts      = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
    receipt = base64.b64encode(f"{g.current_user}_UPLOAD_{ts}".encode()).decode()

    return jsonify({
        'message':    f'{len(uploaded)} file(s) uploaded successfully',
        'dataset_id': str(dataset_id),
        'receipt':    receipt,
        'files':      [{'filename': u['filename'], 'size_bytes': u['size_bytes']} for u in uploaded],
        'errors':     errors,
    }), 201


@datasets_bp.route('/<dataset_id>', methods=['GET'])
@jwt_required
@role_required(['Reviewer', 'Admin', 'Researcher'])
def get_dataset(dataset_id):
    """GET /api/datasets/<id>   get dataset metadata."""
    try:
        oid = ObjectId(dataset_id)
    except Exception:
        return jsonify({'error': 'Invalid dataset ID'}), 400

    ds = datasets().find_one({'_id': oid})
    if not ds:
        return jsonify({'error': 'Dataset not found'}), 404

    # Researchers can only see their own datasets
    if g.current_role == 'Researcher' and ds['owner'] != g.current_user:
        return jsonify({'error': 'Access denied', 'code': 'INSUFFICIENT_ROLE'}), 403

    now = datetime.datetime.now()
    result = {
        'id':          str(ds['_id']),
        'owner':       ds['owner'],
        'description': ds.get('description', ''),
        'upload_time': str(ds.get('upload_time', '')),
        'files': [
            {
                'filename':    f['filename'],
                'expiry':      str(f.get('expiry_time', '')),
                'expired':     now >= f.get('expiry_time', now),
                'size_bytes':  f.get('size_bytes', 0),
            }
            for f in ds.get('files', [])
        ],
    }
    return jsonify(result), 200


@datasets_bp.route('/<dataset_id>/download/<filename>', methods=['GET'])
@jwt_required
@role_required(['Reviewer', 'Admin'])
def download_file(dataset_id, filename):
    """
    GET /api/datasets/<id>/download/<filename>
    Returns a time-limited pre-signed S3 URL for secure download.
    """
    try:
        oid = ObjectId(dataset_id)
    except Exception:
        return jsonify({'error': 'Invalid dataset ID'}), 400

    ds = datasets().find_one({'_id': oid})
    if not ds:
        return jsonify({'error': 'Dataset not found'}), 404

    file_doc = next(
        (f for f in ds.get('files', []) if f['filename'] == filename), None
    )
    if not file_doc:
        return jsonify({'error': 'File not found in dataset'}), 404

    if datetime.datetime.now() >= file_doc.get('expiry_time', datetime.datetime.now()):
        return jsonify({'error': 'File has expired', 'code': 'FILE_EXPIRED'}), 410

    s3_key = file_doc.get('s3_key')
    if not s3_key:
        return jsonify({'error': 'No S3 key for this file'}), 500

    expiry_seconds = int(request.args.get('expiry', 3600))
    url = generate_presigned_url(s3_key, expiry=expiry_seconds)

    if not url:
        return jsonify({'error': 'Could not generate download URL'}), 500

    logs().insert_one({
        'user':   g.current_user,
        'action': f'Downloaded {filename} from dataset {dataset_id}',
        'time':   str(datetime.datetime.now()),
    })

    return jsonify({
        'download_url':      url,
        'expires_in_seconds': expiry_seconds,
        'filename':          filename,
    }), 200


@datasets_bp.route('/<dataset_id>', methods=['DELETE'])
@jwt_required
def delete_dataset(dataset_id):
    """
    DELETE /api/datasets/<id>
    Admin can delete any dataset. Owner (Researcher) can delete their own.
    """
    try:
        oid = ObjectId(dataset_id)
    except Exception:
        return jsonify({'error': 'Invalid dataset ID'}), 400

    ds = datasets().find_one({'_id': oid})
    if not ds:
        return jsonify({'error': 'Dataset not found'}), 404

    # Only owner or Admin can delete
    if g.current_role not in ('Admin',) and ds['owner'] != g.current_user:
        return jsonify({'error': 'Access denied', 'code': 'INSUFFICIENT_ROLE'}), 403

    # Delete files from S3
    for f in ds.get('files', []):
        s3_key = f.get('s3_key')
        if s3_key:
            delete_file(s3_key)

    datasets().delete_one({'_id': oid})
    invalidate_datasets('all')

    logs().insert_one({
        'user':   g.current_user,
        'action': f'Deleted dataset {dataset_id}',
        'time':   str(datetime.datetime.now()),
    })
    return jsonify({'message': f'Dataset {dataset_id} deleted'}), 200
