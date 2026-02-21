"""
core/s3_storage.py — Cloud File Storage (S3 / MinIO)
======================================================
Abstracts file storage behind a simple interface.
Set STORAGE_BACKEND=minio (local dev) or STORAGE_BACKEND=s3 (AWS).

MinIO runs locally via docker-compose on port 9000.
AWS S3 uses real credentials from .env.

Key operations:
  - upload_file()            → store encrypted bytes
  - generate_presigned_url() → time-limited download link
  - delete_file()            → remove from bucket
  - ensure_bucket_exists()   → idempotent bucket creation
"""

import logging
import uuid
from typing import Optional

import boto3
from botocore.exceptions import ClientError
from flask import current_app

logger = logging.getLogger(__name__)


def _get_s3_client():
    """Build a boto3 S3 client from Flask app config."""
    cfg      = current_app.config
    backend  = cfg.get('STORAGE_BACKEND', 'minio')
    endpoint = cfg.get('S3_ENDPOINT_URL') if backend == 'minio' else None

    return boto3.client(
        's3',
        endpoint_url          = endpoint,
        aws_access_key_id     = cfg.get('AWS_ACCESS_KEY'),
        aws_secret_access_key = cfg.get('AWS_SECRET_KEY'),
        region_name           = cfg.get('S3_REGION', 'us-east-1'),
    )


def ensure_bucket_exists():
    """Create the configured bucket if it doesn't exist (idempotent)."""
    s3     = _get_s3_client()
    bucket = current_app.config['S3_BUCKET']
    try:
        s3.head_bucket(Bucket=bucket)
        logger.debug(f"[S3] Bucket already exists: {bucket}")
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ('404', 'NoSuchBucket'):
            s3.create_bucket(Bucket=bucket)
            logger.info(f"[S3] Created bucket: {bucket}")
        else:
            logger.error(f"[S3] Bucket check failed: {e}")
            raise


def upload_file(
    file_bytes:   bytes,
    filename:     str,
    owner:        str,
    content_type: str = 'application/octet-stream',
) -> str:
    """
    Upload file_bytes to S3/MinIO.

    Returns the S3 object key (not a URL).
    Key format: <owner>/<uuid>/<filename>

    Server-side encryption (AES-256) is applied on real S3.
    """
    s3      = _get_s3_client()
    bucket  = current_app.config['S3_BUCKET']
    backend = current_app.config.get('STORAGE_BACKEND', 'minio')
    s3_key  = f"{owner}/{uuid.uuid4().hex}/{filename}"

    extra_args: dict = {'ContentType': content_type}

    # AES-256 SSE on AWS S3 (MinIO doesn't require this header)
    if backend == 's3':
        extra_args['ServerSideEncryption'] = 'AES256'

    try:
        s3.put_object(
            Bucket=bucket,
            Key=s3_key,
            Body=file_bytes,
            **extra_args,
        )
        logger.info(f"[S3] Uploaded → {bucket}/{s3_key} ({len(file_bytes)} bytes)")
        return s3_key
    except ClientError as e:
        logger.error(f"[S3] Upload failed: {e}")
        raise


def generate_presigned_url(s3_key: str, expiry: int = 3600) -> Optional[str]:
    """
    Generate a pre-signed GET URL for secure, time-limited file download.

    Args:
        s3_key: The object key returned by upload_file()
        expiry: URL validity in seconds (default 1 hour)

    Returns:
        Pre-signed URL string, or None on error.
    """
    s3     = _get_s3_client()
    bucket = current_app.config['S3_BUCKET']
    try:
        url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket, 'Key': s3_key},
            ExpiresIn=expiry,
        )
        return url
    except ClientError as e:
        logger.error(f"[S3] Pre-signed URL error: {e}")
        return None


def delete_file(s3_key: str) -> bool:
    """Delete an object from the bucket. Returns True on success."""
    s3     = _get_s3_client()
    bucket = current_app.config['S3_BUCKET']
    try:
        s3.delete_object(Bucket=bucket, Key=s3_key)
        logger.info(f"[S3] Deleted: {bucket}/{s3_key}")
        return True
    except ClientError as e:
        logger.error(f"[S3] Delete failed: {e}")
        return False


def list_files(owner: Optional[str] = None) -> list[dict]:
    """List all files, optionally filtered by owner prefix."""
    s3      = _get_s3_client()
    bucket  = current_app.config['S3_BUCKET']
    prefix  = f"{owner}/" if owner else ''
    try:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        return [
            {
                'key':           obj['Key'],
                'size':          obj['Size'],
                'last_modified': obj['LastModified'].isoformat(),
            }
            for obj in resp.get('Contents', [])
        ]
    except ClientError as e:
        logger.error(f"[S3] List failed: {e}")
        return []
