"""
services/user_service.py   User Management Service
========================================================
Handles user registration, deletion, and searching.
"""

import datetime
from core.db import users as users_col
from core.exceptions import ConflictException, NotFoundException
from services.auth_service import AuthService

class UserService:
    @staticmethod
    def get_user_by_username(username):
        user = users_col().find_one({'username': username})
        if not user:
            raise NotFoundException(f"User {username} not found")
        return user

    @staticmethod
    def register_user(username, email, password, role):
        if users_col().find_one({'username': username}):
            raise ConflictException(f"Username {username} already exists")
        
        if users_col().find_one({'email': email}):
            raise ConflictException(f"Email {email} already exists")
        
        salt = AuthService.generate_salt()
        priv_key, pub_key = AuthService.generate_rsa_keys()
        
        user_doc = {
            'username':   username,
            'email':      email,
            'hash':       AuthService.hash_password(password, salt),
            'salt':       salt,
            'role':       role,
            'public_key': pub_key,
            'created_at': datetime.datetime.utcnow(),
        }
        users_col().insert_one(user_doc)
        return priv_key.decode('utf-8')

    @staticmethod
    def delete_user(username):
        result = users_col().delete_one({'username': username})
        if result.deleted_count == 0:
            raise NotFoundException(f"User {username} not found")
        return True

    @staticmethod
    def get_all_users():
        return {u['username']: u for u in users_col().find()}
