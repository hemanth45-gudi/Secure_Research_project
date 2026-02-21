"""
app.py   Flask Application Factory
====================================
create_app(env) bootstraps the Flask app:
  1. Loads config from config.py
  2. Initialises extensions (limiter, cache, db)
  3. Registers API blueprints
  4. Registers all existing page routes (backward-compatible)

Run locally:
    python app.py

Run with Gunicorn (production):
    gunicorn "app:create_app('production')" --bind 0.0.0.0:5000
"""

import os
import base64
import datetime
import hashlib
import random
import smtplib
import re
from email.message import EmailMessage
from functools import wraps

from flask import (Flask, request, render_template, redirect,
                   url_for, session, flash, jsonify, g)
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

from auth import (
    generate_tokens, decode_access_token, decode_refresh_token,
    jwt_required, role_required, ACCESS_TOKEN_COOKIE
)
from config import config_map
from core.limiter import limiter
from core.cache   import cache
from core.email   import send_otp_email
from core.db      import init_db, users as users_col_fn, datasets as datasets_col_fn
from core.db      import logs as logs_col_fn, refresh_tokens as rt_col_fn


# ============================================================
# APP FACTORY
# ============================================================

def create_app(env: str = None) -> Flask:
    if env is None:
        env = os.environ.get('FLASK_ENV', 'development')

    app = Flask(__name__)
    cfg = config_map.get(env, config_map['default'])
    app.config.from_object(cfg)

    # -- Extensions ------------------------------------------
    try:
        limiter.init_app(app)
    except Exception as e:
        print(f"[[WARN] LIMITER] Init warning: {e}", flush=True)

    cache.init_app(app)

    # -- MongoDB -------------------------------------------- 
    init_db(app)

    # -- CORS (allow API clients) ---------------------------- 
    try:
        from flask_cors import CORS
        CORS(app, resources={r"/api/*": {"origins": "*"}})
    except ImportError:
        pass

    # -- API Blueprints -------------------------------------- 
    from api.auth_bp     import auth_bp
    from api.datasets_bp import datasets_bp
    from api.users_bp    import users_bp
    from api.admin_bp    import admin_bp

    app.register_blueprint(auth_bp,     url_prefix='/api/auth')
    app.register_blueprint(datasets_bp, url_prefix='/api/datasets')
    app.register_blueprint(users_bp,    url_prefix='/api/users')
    app.register_blueprint(admin_bp,    url_prefix='/api/admin')

    # -- Page Routes (backward-compatible browser UI) -------- 
    _register_page_routes(app)

    print(f"\n[[OK] APP] Started in '{env}' mode on port 5000\n", flush=True)
    return app


# ============================================================
# CRYPTO HELPERS (used by page routes only)
# ============================================================

def _generate_salt():
    return base64.b64encode(os.urandom(16)).decode('utf-8')


def _hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()


def _generate_rsa_keys():
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


def _sign_data(data_bytes, private_key_pem):
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(
        data_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode('utf-8')


def _verify_signature(data_bytes, signature_b64, public_key_pem):
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
        signature  = base64.b64decode(signature_b64)
        public_key.verify(
            signature, data_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False




# ============================================================
# PAGE ROUTES (template-rendered, backward-compatible)
# ============================================================

def _register_page_routes(app: Flask):
    """Register all existing browser-facing routes on the app instance."""

    from flask import current_app

    # -- Home ----------------------------------------------
    @app.route('/')
    def home():
        return render_template('home.html')

    # -- Register ------------------------------------------
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            username        = request.form['username']
            email           = request.form['email']
            password        = request.form['password']
            role            = request.form['role']
            admin_key_input = request.form.get('admin_key', '').strip()

            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_regex, email):
                flash('[WARN] Invalid Email Address!', 'danger')
                return redirect(url_for('register'))

            if len(password) < 8:
                flash('Password must be at least 8 characters.', 'warning')
                return redirect(url_for('register'))

            if users_col_fn().find_one({'username': username}):
                flash('Username already exists.', 'warning')
                return redirect(url_for('register'))

            if role == 'Admin':
                expected = current_app.config.get('ADMIN_REGISTRATION_KEY', 'AdminSecret123!')
                if admin_key_input != expected:
                    flash('  Invalid Admin Registration Key.', 'danger')
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

    # -- Verify Email (OTP) --------------------------------
    @app.route('/verify_email', methods=['GET', 'POST'])
    def verify_email():
        if 'pending_reg' not in session or 'otp' not in session:
            flash('Session expired. Please register again.', 'danger')
            return redirect(url_for('register'))

        if request.method == 'POST':
            entered_otp = request.form['otp']
            if entered_otp == session['otp']:
                data     = session['pending_reg']
                username = data['username']

                salt     = _generate_salt()
                priv_key, pub_key = _generate_rsa_keys()

                users_col_fn().insert_one({
                    'username':   username,
                    'email':      data['email'],
                    'hash':       _hash_password(data['password'], salt),
                    'salt':       salt,
                    'role':       data['role'],
                    'public_key': pub_key,
                    'created_at': datetime.datetime.utcnow(),
                })

                session.pop('pending_reg', None)
                session.pop('otp', None)

                logs_col_fn().insert_one({
                    'user':   username,
                    'action': f"Registered as {data['role']}",
                    'time':   str(datetime.datetime.now()),
                })

                return render_template('register_success.html',
                                       username=username,
                                       role=data['role'],
                                       private_key=priv_key.decode('utf-8'))
            else:
                flash('[ERROR] Invalid OTP. Please try again.', 'danger')

        return render_template('verify_email.html')

    # -- Login ---------------------------------------------
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            user     = users_col_fn().find_one({'username': username})

            if user and user.get('hash') == _hash_password(password, user.get('salt', '')):
                # JWT Token Generation
                tokens = generate_tokens(username, user['role'])
                now    = datetime.datetime.utcnow()

                # Store refresh token in DB
                rt_col_fn().insert_one({
                    'username':      username,
                    'refresh_token': tokens['refresh_token'],
                    'issued_at':     now,
                    'expires_at':    now + datetime.timedelta(days=7),
                })

                logs_col_fn().insert_one({
                    'user':   username,
                    'action': 'Logged In',
                    'time':   str(datetime.datetime.now()),
                })

                # Clear legacy session if any
                session.clear()

                # Redirect to dashboard and set HttpOnly JWT cookie
                resp = redirect(url_for('dashboard'))
                resp.set_cookie(
                    ACCESS_TOKEN_COOKIE,
                    tokens['access_token'],
                    httponly = True,
                    samesite = 'Lax',
                    max_age  = 15 * 60,
                    secure   = current_app.config.get('SESSION_COOKIE_SECURE', False),
                    path     = '/',
                )
                return resp
            else:
                flash('Invalid credentials!', 'danger')

        return render_template('login.html')

    # -- Dashboard ---------------------------------------- 
    @app.route('/dashboard')
    @jwt_required
    def dashboard():
        return render_template('dashboard.html',
                               user=g.current_user, role=g.current_role)

    # -- Upload (Researcher) ------------------------------ 
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

            private_key_pem = private_key_file.read()
            files_list      = request.files.getlist('files[]')
            durations       = request.form.getlist('durations[]')
            uploaded_data   = []

            for i, file in enumerate(files_list):
                if not file or file.filename == '':
                    continue
                try:
                    duration = int(durations[i])
                except (IndexError, ValueError):
                    duration = 1

                fb  = file.read()
                fn  = secure_filename(file.filename)

                aes  = Fernet.generate_key()
                enc  = Fernet(aes).encrypt(fb)

                try:
                    sig = _sign_data(fb, private_key_pem)
                except Exception as e:
                    flash("Invalid Private Key provided.", "danger")
                    return redirect(url_for('upload_dataset'))

                uploaded_data.append({
                    'filename':          fn,
                    'aes_key':           aes.decode(),
                    'encrypted_content': base64.b64encode(enc).decode(),
                    'signature':         sig,
                    'expiry_time':       datetime.datetime.now() + datetime.timedelta(minutes=duration),
                })

            if uploaded_data:
                datasets_col_fn().insert_one({
                    'owner':       g.current_user,
                    'description': desc,
                    'files':       uploaded_data,
                    'upload_time': datetime.datetime.now(),
                })
                logs_col_fn().insert_one({
                    'user':   g.current_user,
                    'action': f'Uploaded {len(uploaded_data)} files',
                    'time':   str(datetime.datetime.now()),
                })
                ts      = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
                receipt = base64.b64encode(f"{g.current_user}_UPLOAD_{ts}".encode()).decode()
                return render_template('upload_success_receipt.html', receipt=receipt)

        return render_template('upload.html')

    # -- View Datasets (Reviewer) --------------------------
    @app.route('/view_datasets')
    @jwt_required
    @role_required(['Reviewer'])
    def view_datasets():
        data = []
        for ds in datasets_col_fn().find():
            owner_doc = users_col_fn().find_one({'username': ds['owner']})
            if not owner_doc:
                continue
            public_key = owner_doc['public_key']
            files = []
            for f in ds.get('files', []):
                if datetime.datetime.now() < f.get('expiry_time', datetime.datetime.now()):
                    try:
                        dec   = Fernet(f['aes_key'].encode()).decrypt(
                                    base64.b64decode(f['encrypted_content']))
                        valid = _verify_signature(dec, f['signature'], public_key)
                        files.append({
                            'filename':        f['filename'],
                            'signature_valid': valid,
                            'download_data':   base64.b64encode(dec).decode(),
                            'expiry':          f.get('expiry_time'),
                        })
                    except Exception as e:
                        print(f"Decrypt error: {e}")
            if files:
                data.append({
                    'id':          str(ds['_id']),
                    'owner':       ds['owner'],
                    'description': ds.get('description', ''),
                    'files':       files,
                    'status':      'active',
                })
        logs_col_fn().insert_one({
            'user':   g.current_user,
            'action': 'Viewed datasets',
            'time':   str(datetime.datetime.now()),
        })
        return render_template('view_datasets.html', data=data)

    # -- View Logs (Admin) -------------------------------- 
    @app.route('/logs')
    @jwt_required
    @role_required(['Admin'])
    def view_logs():
        all_logs = list(logs_col_fn().find())
        return render_template('view_logs.html', logs=all_logs)

    # -- Manage Users (Admin) ------------------------------
    @app.route('/manage_users')
    @jwt_required
    @role_required(['Admin'])
    def manage_users():
        all_users = {u['username']: u for u in users_col_fn().find()}
        return render_template('manage_users.html', users=all_users)

    # -- Delete User (Admin) ------------------------------ 
    @app.route('/delete_user/<username>')
    @jwt_required
    @role_required(['Admin'])
    def delete_user(username):
        result = users_col_fn().delete_one({'username': username})
        if result.deleted_count > 0:
            flash(f'User {username} deleted.', 'success')
            logs_col_fn().insert_one({
                'user':   g.current_user,
                'action': f'Deleted user {username}',
                'time':   str(datetime.datetime.now()),
            })
        else:
            flash(f'User {username} not found.', 'danger')
        return redirect(url_for('manage_users'))

    # -- Logout --------------------------------------------
    @app.route('/logout')
    def logout():
        username = getattr(g, 'current_user', 'Unknown')
        logs_col_fn().insert_one({
            'user':   username,
            'action': 'Logged Out',
            'time':   str(datetime.datetime.now()),
        })
        session.clear()
        resp = redirect(url_for('login'))
        resp.delete_cookie(ACCESS_TOKEN_COOKIE, path='/')
        return resp

    # -- Health Check --------------------------------------
    @app.route('/health')
    def health():
        from core.db import get_db
        try:
            get_db().command('ping')
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify({
            'status':    'healthy' if db_ok else 'degraded',
            'db':        'connected' if db_ok else 'disconnected',
            'timestamp': str(datetime.datetime.now()),
        }), 200 if db_ok else 503


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)