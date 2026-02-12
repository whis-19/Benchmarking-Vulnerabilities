import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from werkzeug.utils import secure_filename
from functools import wraps
import hashlib
import hmac
import time
from threading import Lock

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a strong, random secret key

# Configuration
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')  # Store uploads outside web root
ALLOWED_EXTENSIONS = {'pdf'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_ATTEMPTS = 5
login_attempts = {}
login_lock = Lock()

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# CSP Header
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self';"
    return response

# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# CSRF Token Generation
def generate_csrf_token():
    return secrets.token_hex(16)

# CSRF Token Validation
def validate_csrf_token(token):
    return hmac.compare_digest(token, session.get('csrf_token', ''))

# Rate Limiting
def is_rate_limited(ip_address):
    with login_lock:
        now = time.time()
        if ip_address in login_attempts:
            attempts, last_attempt = login_attempts[ip_address]
            if now - last_attempt < RATE_LIMIT_WINDOW and attempts >= RATE_LIMIT_MAX_ATTEMPTS:
                return True
            elif now - last_attempt >= RATE_LIMIT_WINDOW:
                login_attempts[ip_address] = (1, now)
            else:
                login_attempts[ip_address] = (attempts + 1, now)
        else:
            login_attempts[ip_address] = (1, now)
        return False

# Password Hashing (Example - use a proper library like bcrypt)
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# Check Password (Example - use a proper library like bcrypt)
def check_password(password, hashed_password):
    return hash_password(password) == hashed_password

# Allowed File Extension Check
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = request.remote_addr

        if is_rate_limited(ip_address):
            return render_template('login.html', error='Too many login attempts. Please try again later.')

        # In a real application, you would fetch the user from a database
        # and compare the password hash.  This is a placeholder.
        # NEVER HARDCODE CREDENTIALS
        if username == 'testuser' and check_password(password, hash_password('password')):
            session['username'] = username
            session['csrf_token'] = generate_csrf_token()
            return redirect(url_for('upload_form'))
        else:
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    session.pop('csrf_token', None)
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def upload_form():
    if request.method == 'POST':
        if 'csrf_token' not in request.form or not validate_csrf_token(request.form['csrf_token']):
            return render_template('upload.html', error='CSRF token is invalid.')

        # Check if the post request has the file part
        if 'file' not in request.files:
            return render_template('upload.html', error='No file part')

        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return render_template('upload.html', error='No selected file')

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)  # Sanitize filename
            if filename != file.filename:
                return render_template('upload.html', error='Invalid filename.  Please rename the file.')

            if len(request.files['file'].read()) > MAX_FILE_SIZE:
                return render_template('upload.html', error=f'File size exceeds the limit of {MAX_FILE_SIZE / (1024 * 1024)} MB')

            file.seek(0) # Reset file pointer after reading for size check

            filepath = os.path.join(UPLOAD_FOLDER, filename)

            # Prevent path traversal attacks
            if not os.path.abspath(filepath).startswith(os.path.abspath(UPLOAD_FOLDER)):
                return render_template('upload.html', error='Invalid file path')

            try:
                file.save(filepath)
                return render_template('upload.html', message='File uploaded successfully')
            except Exception as e:
                return render_template('upload.html', error=f'Error saving file: {str(e)}')

        else:
            return render_template('upload.html', error='Invalid file type. Only PDF files are allowed.')

    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    return render_template('upload.html', csrf_token=csrf_token)

@app.route('/uploads/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

if __name__ == '__main__':
    app.run(debug=True)

