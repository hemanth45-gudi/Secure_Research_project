"""
services/auth_service.py   Authentication & Identity Service
========================================================
Handles JWT generation/verification, password hashing, 
and interaction with the user collection.
"""

import os
import datetime
import hashlib
import base64
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from core.db import users as users_col, refresh_tokens as rt_col
from core.exceptions import UnauthorizedException, ConflictException

JWT_ACCESS_SECRET  = os.environ.get('JWT_ACCESS_SECRET',  'access_super_secret_change_in_prod')
JWT_REFRESH_SECRET = os.environ.get('JWT_REFRESH_SECRET', 'refresh_super_secret_change_in_prod')
JWT_ACCESS_EXPIRY  = datetime.timedelta(minutes=15)
JWT_REFRESH_EXPIRY = datetime.timedelta(days=7)
JWT_ALGORITHM      = 'HS256'

class AuthService:
    @staticmethod
    def hash_password(password, salt):
        return hashlib.sha256((password + salt).encode()).hexdigest()

    @staticmethod
    def generate_salt():
        return base64.b64encode(os.urandom(16)).decode('utf-8')

    @staticmethod
    def generate_rsa_keys():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key  = private_key.public_key()
        pem_private = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        pem_public = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem_private, pem_public

    @staticmethod
    def create_tokens(username, role):
        now = datetime.datetime.utcnow()
        access_payload = {
            'sub': username, 'role': role, 'iat': now,
            'exp': now + JWT_ACCESS_EXPIRY, 'type': 'access'
        }
        refresh_payload = {
            'sub': username, 'role': role, 'iat': now,
            'exp': now + JWT_REFRESH_EXPIRY, 'type': 'refresh'
        }
        access_token  = jwt.encode(access_payload,  JWT_ACCESS_SECRET,  algorithm=JWT_ALGORITHM)
        refresh_token = jwt.encode(refresh_payload, JWT_REFRESH_SECRET, algorithm=JWT_ALGORITHM)
        
        # Save refresh token to DB
        rt_col().insert_one({
            'username': username,
            'refresh_token': refresh_token,
            'issued_at': now,
            'expires_at': now + JWT_REFRESH_EXPIRY,
        })
        
        return {'access_token': access_token, 'refresh_token': refresh_token}

    @staticmethod
    def decode_token(token, secret_type='access'):
        secret = JWT_ACCESS_SECRET if secret_type == 'access' else JWT_REFRESH_SECRET
        try:
            payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
            if payload.get('type') != secret_type:
                raise UnauthorizedException("Invalid token type", {"code": "TOKEN_INVALID"})
            return payload
        except jwt.ExpiredSignatureError:
            raise UnauthorizedException("Token has expired", {"code": "TOKEN_EXPIRED"})
        except jwt.InvalidTokenError:
            raise UnauthorizedException("Invalid token", {"code": "TOKEN_INVALID"})

    @staticmethod
    def login(username, password, ip=None):
        from core.limiter import is_account_locked, record_failed_login, clear_failed_logins
        
        # 1. Check Lockout
        is_locked, msg = is_account_locked(username)
        if is_locked:
            raise UnauthorizedException(msg, {"code": "ACCOUNT_LOCKED"})

        # 2. Authenticate
        user = users_col().find_one({'username': username})
        if not user or user.get('hash') != AuthService.hash_password(password, user.get('salt', '')):
            record_failed_login(username, ip or 'unknown')
            raise UnauthorizedException("Invalid credentials", {"code": "INVALID_CREDENTIALS"})
        
        # 3. Success
        clear_failed_logins(username)
        return AuthService.create_tokens(username, user['role'])

    @staticmethod
    def logout(refresh_token):
        if refresh_token:
            rt_col().delete_one({'refresh_token': refresh_token})

    @staticmethod
    def refresh_access_token(refresh_token):
        payload = AuthService.decode_token(refresh_token, secret_type='refresh')
        stored = rt_col().find_one({'refresh_token': refresh_token})
        if not stored:
            raise UnauthorizedException("Refresh token revoked or invalid", {"code": "REFRESH_REVOKED"})
        
        # For simplicity, we just issue a new access token. 
        # In full production, you might rotate the refresh token too.
        new_tokens = AuthService.create_tokens(payload['sub'], payload['role'])
        rt_col().delete_one({'refresh_token': refresh_token}) # Rotate
        return new_tokens
