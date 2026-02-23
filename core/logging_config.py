import logging
import logging.handlers
import os
import datetime
from flask import request, g

def setup_logging(app):
    """Sets up centralized logging for the application."""
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Standard logging format
    log_format = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    )

    # File handler for all logs
    file_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, 'app.log'),
        maxBytes=10*1024*1024, # 10MB
        backupCount=10
    )
    file_handler.setFormatter(log_format)
    file_handler.setLevel(logging.INFO)

    # Error-specific log file
    error_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, 'error.log'),
        maxBytes=10*1024*1024,
        backupCount=10
    )
    error_handler.setFormatter(log_format)
    error_handler.setLevel(logging.ERROR)

    # Add handlers to app logger
    app.logger.addHandler(file_handler)
    app.logger.addHandler(error_handler)
    app.logger.setLevel(logging.INFO)

    # Remove default handlers if they exist to keep it clean
    # for handler in app.logger.handlers[:]:
    #     if not isinstance(handler, (logging.handlers.RotatingFileHandler, logging.StreamHandler)):
    #         app.logger.removeHandler(handler)

    app.logger.info("Logging system initialized")

def log_audit_event(action, user=None, status='success', details=None):
    """
    Records an audit log entry in MongoDB for hypersensitive actions.
    """
    from core.db import logs as logs_col
    
    audit_entry = {
        'timestamp': datetime.datetime.utcnow(),
        'user': user or g.get('current_user', 'anonymous'),
        'action': action,
        'status': status,
        'ip_address': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'details': details or {}
    }
    
    try:
        logs_col().insert_one(audit_entry)
    except Exception as e:
        # Fallback to file logging if DB is down
        logging.error(f"Failed to write audit log to DB: {e}. Audit Entry: {audit_entry}")
