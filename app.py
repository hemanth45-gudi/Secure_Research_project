import os
import datetime
from flask import Flask, render_template, jsonify, g, request, redirect, url_for, flash, session
from flask_cors import CORS
from flasgger import Swagger
from dotenv import load_dotenv

load_dotenv()

from config import config_map
from core.limiter import limiter
from core.cache import cache
from core.db import init_db
from core.exceptions import BaseAppException
from auth import jwt_required, role_required, ACCESS_TOKEN_COOKIE
from core.metrics import metrics_tracker

def create_app(env: str = None) -> Flask:
    if env is None:
        env = os.environ.get('FLASK_ENV', 'development')

    app = Flask(__name__)
    cfg = config_map.get(env, config_map['default'])
    app.config.from_object(cfg)

    # -- Extensions ------------------------------------------
    from core.logging_config import setup_logging
    from prometheus_flask_exporter import PrometheusMetrics
    from flask_talisman import Talisman
    
    setup_logging(app)
    
    # Monitoring: Exposes /metrics
    metrics = PrometheusMetrics(app)
    metrics.info('app_info', 'Application info', version='1.0.0')
    
    # Security Headers
    Talisman(app, 
             content_security_policy=None, 
             force_https=(env == 'production'))  # Only force HTTPS in production
    
    init_db(app)
    limiter.init_app(app)
    cache.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    
    # -- Swagger ---------------------------------------------
    app.config['SWAGGER'] = {
        'title': 'Secure Research Dataset Sharing API',
        'uiversion': 3,
        'specs_route': '/api/docs',
        'static_url_path': '/flasgger_static',
        'specs': [
            {
                'endpoint': 'apispec_1',
                'route': '/api/v1/spec.json',
                'rule_filter': lambda rule: True,  # all in
                'model_filter': lambda tag: True,  # all in
            }
        ],
        'securityDefinitions': {
            'BearerAuth': {
                'type': 'apiKey',
                'name': 'Authorization',
                'in': 'header',
                'description': 'JWT Authorization header using the Bearer scheme. Example: "Bearer {token}"'
            }
        },
        'definitions': {
            'Login': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string'},
                    'password': {'type': 'string'}
                },
                'required': ['username', 'password']
            },
            'Register': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string'},
                    'email': {'type': 'string'},
                    'password': {'type': 'string'},
                    'role': {'type': 'string', 'enum': ['Admin', 'Researcher', 'Reviewer']},
                    'admin_key': {'type': 'string'}
                },
                'required': ['username', 'email', 'password', 'role']
            },
            'DatasetUpload': {
                'type': 'object',
                'properties': {
                    'description': {'type': 'string'}
                },
                'required': ['description']
            }
        }
    }
    Swagger(app)

    # -- Error Handlers --------------------------------------
    @app.errorhandler(BaseAppException)
    def handle_app_exception(error):
        app.logger.warning(f"App Exception [{error.code}]: {error.message}")
        return jsonify({
            'success': False,
            'message': error.message,
            'code': error.code,
            'details': error.details
        }), error.status_code

    @app.errorhandler(404)
    def not_found_error(error):
        return jsonify({
            'success': False,
            'message': 'Resource not found',
            'code': 'NOT_FOUND'
        }), 404

    @app.errorhandler(429)
    def ratelimit_handler(e):
        return jsonify({
            'success': False,
            'message': 'Rate limit exceeded',
            'code': 'TOO_MANY_REQUESTS',
            'details': str(e.description)
        }), 429

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        app.logger.error(f"Unexpected error: {error}", exc_info=True)
        return jsonify({
            'success': False,
            'message': 'An unexpected error occurred',
            'code': 'INTERNAL_ERROR'
        }), 500

    # -- API Blueprints -------------------------------------- 
    from api.v1.auth_bp import auth_bp
    from api.v1.datasets_bp import datasets_bp
    from api.v1.users_bp    import users_bp
    from api.v1.admin_bp    import admin_bp

    app.register_blueprint(auth_bp,     url_prefix='/api/v1/auth')
    app.register_blueprint(datasets_bp, url_prefix='/api/v1/datasets')
    app.register_blueprint(users_bp,    url_prefix='/api/v1/users')
    app.register_blueprint(admin_bp,    url_prefix='/api/v1/admin')


    # -- Page Routes (backward-compatible browser UI) -------- 
    _register_page_routes(app)

    @app.before_request
    def before_request():
        metrics_tracker.start_request()

    @app.after_request
    def after_request(response):
        metrics_tracker.end_request(response)
        return response

    @app.route('/api/v1/metrics/summary')
    @jwt_required
    def get_metrics_summary():
        return jsonify(metrics_tracker.get_summary())

    print(f"\n[[OK] APP] Started in '{env}' mode on port 5000\n", flush=True)
    return app

def _register_page_routes(app: Flask):
    """Register all existing browser-facing routes on the app instance."""
    from services.auth_service import AuthService
    from services.user_service import UserService
    from services.dataset_service import DatasetService
    from core.db import logs as logs_col, datasets as datasets_col_fn
    from core.email import send_otp_email
    import random

    @app.route('/')
    def home():
        return render_template('home.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            role = request.form['role']
            admin_key_input = request.form.get('admin_key', '').strip()

            import re
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_regex, email):
                flash('[WARN] Invalid Email Address!', 'danger')
                return redirect(url_for('register'))

            if len(password) < 8:
                flash('Password must be at least 8 characters.', 'warning')
                return redirect(url_for('register'))

            try:
                UserService.get_user_by_username(username)
                flash('Username already exists.', 'warning')
                return redirect(url_for('register'))
            except Exception: # NOT_FOUND is what we want
                pass

            if role == 'Admin':
                expected = app.config.get('ADMIN_REGISTRATION_KEY', 'AdminSecret123!')
                if admin_key_input != expected:
                    flash('Invalid Admin Registration Key.', 'danger')
                    return redirect(url_for('register'))

            otp = str(random.randint(100000, 999999))
            session['pending_reg'] = {
                'username': username, 'email': email,
                'password': password, 'role': role,
            }
            session['otp'] = otp
            send_otp_email(email, otp)
            flash('[OK] Verification Code Sent! Check your email.', 'info')
            return redirect(url_for('verify_email'))
        return render_template('register.html')

    @app.route('/verify_email', methods=['GET', 'POST'])
    def verify_email():
        if 'pending_reg' not in session or 'otp' not in session:
            flash('Session expired. Please register again.', 'danger')
            return redirect(url_for('register'))

        if request.method == 'POST':
            entered_otp = request.form['otp']
            if entered_otp == session['otp']:
                data = session['pending_reg']
                priv_key = UserService.register_user(data['username'], data['email'], 
                                                     data['password'], data['role'])
                
                session.pop('pending_reg', None)
                session.pop('otp', None)

                from core.logging_config import log_audit_event
                log_audit_event('user_registered', user=data['username'], details={'role': data['role']})

                return render_template('register_success.html',
                                       username=data['username'],
                                       role=data['role'],
                                       private_key=priv_key)
            else:
                flash('[ERROR] Invalid OTP. Please try again.', 'danger')
        return render_template('verify_email.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            try:
                tokens = AuthService.login(username, password, ip=request.remote_addr)
                from core.logging_config import log_audit_event
                log_audit_event('user_login', user=username)
                session.clear()
                resp = redirect(url_for('dashboard'))
                resp.set_cookie(
                    ACCESS_TOKEN_COOKIE,
                    tokens['access_token'],
                    httponly=True, samesite='Lax', max_age=15*60,
                    secure=app.config.get('SESSION_COOKIE_SECURE', False),
                    path='/',
                )
                return resp
            except Exception:
                flash('Invalid credentials!', 'danger')
        return render_template('login.html')

    @app.route('/dashboard')
    @jwt_required
    def dashboard():
        return render_template('dashboard.html', user=g.current_user, role=g.current_role)

    @app.route('/upload', methods=['GET', 'POST'])
    @jwt_required
    @role_required(['Researcher'])
    def upload_dataset():
        if request.method == 'POST':
            desc = request.form['description']
            private_key_file = request.files.get('private_key')
            if not private_key_file:
                flash("Private Key is required!", "danger")
                return redirect(url_for('upload_dataset'))

            pk_pem = private_key_file.read()
            files = request.files.getlist('files[]')
            durations = request.form.getlist('durations[]')

            try:
                count = DatasetService.upload_dataset(g.current_user, desc, pk_pem, files, durations)
                if count > 0:
                    from core.logging_config import log_audit_event
                    log_audit_event('dataset_uploaded', user=g.current_user, details={'count': count})
                    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
                    import base64
                    receipt = base64.b64encode(f"{g.current_user}_UPLOAD_{ts}".encode()).decode()
                    return render_template('upload_success_receipt.html', receipt=receipt)
            except Exception as e:
                flash(str(e), "danger")
        return render_template('upload.html')

    @app.route('/view_datasets')
    @jwt_required
    @role_required(['Reviewer'])
    def view_datasets():
        data = DatasetService.get_all_active_datasets()
        from core.logging_config import log_audit_event
        log_audit_event('view_datasets', user=g.current_user)
        return render_template('view_datasets.html', data=data)

    @app.route('/logs')
    @jwt_required
    @role_required(['Admin'])
    def view_logs():
        all_logs = list(logs_col().find())
        return render_template('view_logs.html', logs=all_logs)

    @app.route('/manage_users')
    @jwt_required
    @role_required(['Admin'])
    def manage_users():
        all_users = UserService.get_all_users()
        return render_template('manage_users.html', users=all_users)

    @app.route('/delete_user/<username>')
    @jwt_required
    @role_required(['Admin'])
    def delete_user(username):
        try:
            UserService.delete_user(username)
            flash(f'User {username} deleted.', 'success')
            from core.logging_config import log_audit_event
            log_audit_event('admin_deleted_user', user=g.current_user, details={'target': username})
        except Exception as e:
            flash(str(e), 'danger')
        return redirect(url_for('manage_users'))

    @app.route('/logout')
    def logout():
        username = getattr(g, 'current_user', 'Unknown')
        from core.logging_config import log_audit_event
        log_audit_event('user_logout', user=username)
        session.clear()
        resp = redirect(url_for('login'))
        resp.delete_cookie(ACCESS_TOKEN_COOKIE, path='/')
        return resp

    @app.route('/health')
    def health():
        from core.db import get_db
        try:
            get_db().command('ping')
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify({
            'status': 'healthy' if db_ok else 'degraded',
            'db': 'connected' if db_ok else 'disconnected',
            'timestamp': str(datetime.datetime.now()),
        }), 200 if db_ok else 503

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)
