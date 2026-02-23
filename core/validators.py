"""
core/validators.py   Input Validation with Marshmallow
========================================================
Defines schemas for all API request bodies.
The @validate_json(Schema) decorator validates the request
and stores cleaned data in flask.g.validated_data.
"""

from functools import wraps
from marshmallow import Schema, fields, validate, ValidationError, validates
from flask import request, jsonify, g


# -- Schemas ------------------------------------------------ 

class LoginSchema(Schema):
    username = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=50),
        error_messages={'required': 'Username is required'}
    )
    password = fields.Str(
        required=True,
        validate=validate.Length(min=8, max=128),
        error_messages={'required': 'Password is required'}
    )


def validate_password_strength(value):
    """Enforce at least one digit and one uppercase letter."""
    if not any(c.isdigit() for c in value):
        raise ValidationError('Password must contain at least one digit.')
    if not any(c.isupper() for c in value):
        raise ValidationError('Password must contain at least one uppercase letter.')

class RegisterSchema(Schema):
    username  = fields.Str(required=True, validate=validate.Length(min=3, max=50))
    email     = fields.Email(required=True)
    password  = fields.Str(
        required=True, 
        validate=[validate.Length(min=8, max=128), validate_password_strength]
    )
    role      = fields.Str(
        required=True,
        validate=validate.OneOf(['Admin', 'Researcher', 'Reviewer'])
    )
    admin_key = fields.Str(load_default='')


class RefreshTokenSchema(Schema):
    refresh_token = fields.Str(required=True)


class OTPVerifySchema(Schema):
    otp = fields.Str(required=True, validate=validate.Length(min=6, max=6))


class DatasetUploadSchema(Schema):
    description = fields.Str(required=True, validate=validate.Length(min=1, max=500))


class UserDeleteSchema(Schema):
    username = fields.Str(required=True)


# -- Decorator ------------------------------------------------

def validate_json(schema_class):
    """
    Decorator: validates JSON request body against schema_class.
    On success: stores validated data in g.validated_data.
    On failure: returns 422 with detailed error messages.

    Usage:
        @app.route('/login', methods=['POST'])
        @validate_json(LoginSchema)
        def login():
            data = g.validated_data  # clean, validated dict
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            schema = schema_class()
            raw    = request.get_json(silent=True) or {}
            try:
                g.validated_data = schema.load(raw)
            except ValidationError as err:
                return jsonify({
                    'success': False,
                    'message': 'Validation failed',
                    'details': err.messages,
                    'code': 'VALIDATION_ERROR'
                }), 422
            return f(*args, **kwargs)
        return decorated
    return decorator
