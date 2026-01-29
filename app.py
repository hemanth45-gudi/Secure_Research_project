import os
import base64
import datetime
import hashlib
import random
import smtplib 
import re
from email.message import EmailMessage
from flask import Flask, request, render_template, redirect, url_for, session, flash
from functools import wraps
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet 
from pymongo import MongoClient

app = Flask(__name__)
app.secret_key = 'super_secret_lab_key' 

# ========================================================
# 🍃 MONGODB CONFIGURATION
# ========================================================
try:
    client = MongoClient('mongodb://localhost:27017/')
    db = client['secure_research_db']
    users_col = db['users']
    datasets_col = db['datasets']
    logs_col = db['logs']
    print("\n[✅ MONGODB] Connected successfully!\n", flush=True)
except Exception as e:
    print(f"\n[❌ MONGODB ERROR] {e}\n", flush=True)

# ========================================================
# 🔑 ADMIN SECURITY CONFIGURATION
# ========================================================
ADMIN_REGISTRATION_KEY = "AdminSecret123!" 

# ========================================================
# 📧 EMAIL CONFIGURATION
# ========================================================
EMAIL_ADDRESS = "hemanth.gudi45@gmail.com" 
EMAIL_PASSWORD = "nvjx jnvi luol brtk"     

# ==========================================
# 🔐 CRYPTO FUNCTIONS
# ==========================================
def generate_salt():
    return base64.b64encode(os.urandom(16)).decode('utf-8')

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # Export Private Key (PEM format)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.PKCS8, 
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Export Public Key (PEM format)
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_private, pem_public

def sign_data(data_bytes, private_key_pem):
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(
        data_bytes, 
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), 
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(data_bytes, signature_b64, public_key_pem):
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature, 
            data_bytes, 
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), 
            hashes.SHA256()
        )
        return True
    except Exception: 
        return False

def role_required(required_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session: 
                return redirect(url_for('login'))
            if session.get('role') not in required_roles:
                flash("⛔ ACCESS DENIED.", "danger")
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ==========================================
# 📧 EMAIL SENDING FUNCTION
# ==========================================
# Multi-Factor Authentication
def send_email_otp(to_email, otp):
    try:
        if "xxxx" in EMAIL_PASSWORD: 
            print(f"\n[⚠️ SIMULATION] Email not configured. OTP: {otp}\n", flush=True)
            return True
            
        msg = EmailMessage()
        msg.set_content(f"Your Secure Research Portal OTP is: {otp}")
        msg['Subject'] = 'Login Verification Code'
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email

        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"\n[✅ EMAIL SENT] OTP sent to {to_email}\n", flush=True)
        return True
    except Exception as e:
        print(f"\n[❌ EMAIL FAILED] Error: {e}", flush=True)
        print(f"[⚠️ FALLBACK] OTP is: {otp}\n", flush=True)
        return False

# ==========================================
# 🚦 ROUTES
# ==========================================
@app.route('/')
def home(): 
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])

def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Email Validation
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            flash('⚠️ Invalid Email Address! Please enter a valid email (e.g., user@example.com).', 'danger')
            return redirect(url_for('register'))
            
        role = request.form['role']
        admin_key_input = request.form.get('admin_key', '').strip()
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'warning')
            return redirect(url_for('register'))

        if users_col.find_one({'username': username}):
            flash('Username already exists.', 'warning')
            return redirect(url_for('register'))

        # Check Admin Key ONLY if role is Admin
        if role == 'Admin':
            if admin_key_input != ADMIN_REGISTRATION_KEY:
                flash('⛔ ACCESS DENIED: Incorrect Admin Registration Key.', 'danger')
                return redirect(url_for('register'))

# Multi-Factor Authentication
        # --- OTP GENERATION & SESSION STORAGE ---
        otp = str(random.randint(100000, 999999))
        
        # Store temporary data in session (NOT users DB yet)
        session['pending_reg'] = {
            'username': username,
            'email': email,
            'password': password, 
            'role': role
        }
        
        # Send OTP
        session['otp'] = otp
        if send_email_otp(email, otp):
             flash('✅ Verification Code Sent! Please check your email.', 'info')
             return redirect(url_for('verify_email'))
        else:
             flash('❌ Failed to send OTP. Please check the email address.', 'danger')
             return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/verify_email', methods=['GET', 'POST'])

def verify_email():
    if 'pending_reg' not in session or 'otp' not in session:
        flash('Session expired. Please register again.', 'danger')
        return redirect(url_for('register'))
        
    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session['otp']:
            # --- FINAL REGISTRATION ---
            data = session['pending_reg']
            username = data['username']
            
            salt = generate_salt()
            priv_key, pub_key = generate_rsa_keys()
            
            # Store public key as bytes (Binary) in Mongo
            users_col.insert_one({
                'username': username,
                'email': data['email'],
                'hash': hash_password(data['password'], salt),
                'salt': salt,
                'role': data['role'],
                'public_key': pub_key
            })
            
            # Clear Session
            session.pop('pending_reg', None)
            session.pop('otp', None)
            
            logs_col.insert_one({'user': username, 'action': f'Registered as {data["role"]} (Verified)', 'time': str(datetime.datetime.now())})
            
            return render_template('register_success.html', 
                                   username=username, 
                                   role=data['role'], 
                                   private_key=priv_key.decode('utf-8'))
        else:
            flash('❌ Invalid OTP. Please try again.', 'danger')
            
    return render_template('verify_email.html')

@app.route('/login', methods=['GET', 'POST'])


#Single-Factor Authentication
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = users_col.find_one({'username': username})
        
        if user and user['hash'] == hash_password(password, user['salt']):   
            session['user'] = username
            session['role'] = user['role']
            
            logs_col.insert_one({'user': username, 'action': 'Logged In', 'time': str(datetime.datetime.now())})
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials!', 'danger')
            
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session: 
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=session['user'], role=session['role'])

@app.route('/upload', methods=['GET', 'POST'])
@role_required(['Researcher'])
def upload_dataset():
    if request.method == 'POST':
        desc = request.form['description']
        
        # Retrieve uploaded private key
        private_key_file = request.files.get('private_key')
        if not private_key_file:
            flash("Private Key is required!", "danger")
            return redirect(url_for('upload_dataset'))
            
        private_key_pem = private_key_file.read()
        
        # files and durations are lists
        files = request.files.getlist('files[]')
        durations = request.form.getlist('durations[]')
        
        uploaded_files_data = []
        
        for i, file in enumerate(files):
            if file.filename == '': continue
            
            try:
                duration = int(durations[i])
            except (IndexError, ValueError):
                duration = 1
                
            fb = file.read()
            fn = secure_filename(file.filename)
            
            # Encrypt File
            aes = Fernet.generate_key()
            f = Fernet(aes)
            enc = f.encrypt(fb)
            
            # Sign File using Uploaded Private Key
            try:
                sig = sign_data(fb, private_key_pem)
            except Exception as e:
                print(f"Signing Error: {e}")
                flash("Invalid Private Key provided.", "danger")
                return redirect(url_for('upload_dataset'))
            
            uploaded_files_data.append({
                'filename': fn, 
                'aes_key': aes.decode(), 
                'encrypted_content': base64.b64encode(enc).decode(), 
                'signature': sig,
                'expiry_time': datetime.datetime.now() + datetime.timedelta(minutes=duration)
            })
        
        if uploaded_files_data:
            new_dataset = {
                'owner': session['user'], 
                'description': desc, 
                'files': uploaded_files_data, 
                'upload_time': datetime.datetime.now()
            }
            datasets_col.insert_one(new_dataset)
            
            logs_col.insert_one({'user': session['user'], 'action': f'Uploaded {len(uploaded_files_data)} files', 'time': str(datetime.datetime.now())})
            
            # --- RECEIPT GENERATION ---
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            receipt_str = f"{session['user']}_UPLOAD_REC_{timestamp}"
            receipt_b64 = base64.b64encode(receipt_str.encode('utf-8')).decode('utf-8')
            
            return render_template('upload_success_receipt.html', receipt=receipt_b64)
            
    return render_template('upload.html')

@app.route('/view_datasets')
@role_required(['Reviewer'])
def view_datasets():
    data = []
    # Fetch all datasets
    all_datasets = datasets_col.find()
    
    for ds in all_datasets:
        files = []
        owner_doc = users_col.find_one({'username': ds['owner']})
        if not owner_doc:
            continue # Skip if owner deleted
            
        public_key = owner_doc['public_key']
        # Convert to PEM strings if bytes
        if isinstance(public_key, bytes):
            # In signature verification it expects bytes for key loading usually?
            # verify_signature function: serialization.load_pem_public_key(public_key_pem) 
            # If stored as bytes in Mongo, pass as is.
            pass
            
        for f in ds['files']:
            # Check Expiry per file
            if datetime.datetime.now() < f['expiry_time']:
                try:
                    # Decrypt
                    dec = Fernet(f['aes_key'].encode()).decrypt(base64.b64decode(f['encrypted_content']))
                    # Verify Signature
                    valid = verify_signature(dec, f['signature'], public_key)
                    
                    files.append({
                        'filename': f['filename'], 
                        'signature_valid': valid, 
                        'download_data': base64.b64encode(dec).decode(),
                        'expiry': f['expiry_time']
                    })
                except Exception as e:
                    print(f"Decryption/Verification Error: {e}")
                    continue
        
        if files: 
             # Use '_id' for ID, convert to string
             data.append({'id': str(ds['_id']), 'owner': ds['owner'], 'description': ds['description'], 'files': files, 'status': 'active'})
            
    logs_col.insert_one({'user': session['user'], 'action': 'Viewed Data', 'time': str(datetime.datetime.now())})
    return render_template('view_datasets.html', data=data)

@app.route('/logs')
@role_required(['Admin'])
def view_logs(): 
    # Get all logs, sort by time? We store time as string, so sort might be tricky unless ISO format.
    # For now just list them.
    all_logs = list(logs_col.find())
    return render_template('view_logs.html', logs=all_logs)

@app.route('/manage_users')
@role_required(['Admin'])
def manage_users():
    # Convert cursor to dict/list for template
    all_users = {u['username']: u for u in users_col.find()}
    return render_template('manage_users.html', users=all_users)

@app.route('/delete_user/<username>')
@role_required(['Admin'])
def delete_user(username):
    result = users_col.delete_one({'username': username})
    if result.deleted_count > 0:
        flash(f'User {username} deleted successfully.', 'success')
        logs_col.insert_one({'user': session['user'], 'action': f'Deleted user {username}', 'time': str(datetime.datetime.now())})
    else:
        flash(f'User {username} not found.', 'danger')
    return redirect(url_for('manage_users'))

@app.route('/logout')
def logout(): 
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__': 
    app.run(debug=True, port=5000)