"""
core/exceptions.py   Centralized Exception Handling
========================================================
Defines custom application exceptions that can be caught 
globally to return standardized JSON responses.
"""

class BaseAppException(Exception):
    """Base class for all application-specific exceptions."""
    status_code = 500
    code = 'INTERNAL_ERROR'

    def __init__(self, message=None, details=None):
        super().__init__(message)
        self.message = message or "An internal server error occurred"
        self.details = details or {}

class UnauthorizedException(BaseAppException):
    status_code = 401
    code = 'UNAUTHORIZED'

class ForbiddenException(BaseAppException):
    status_code = 403
    code = 'FORBIDDEN'

class NotFoundException(BaseAppException):
    status_code = 404
    code = 'NOT_FOUND'

class ValidationException(BaseAppException):
    status_code = 422
    code = 'VALIDATION_ERROR'

    def __init__(self, details):
        super().__init__("Validation failed", details)

class ConflictException(BaseAppException):
    status_code = 409
    code = 'CONFLICT'
