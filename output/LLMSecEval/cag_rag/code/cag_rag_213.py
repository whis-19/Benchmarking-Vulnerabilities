import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from werkzeug.utils import secure_filename
from functools import wraps
import hashlib
import hmac
import time

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a strong, random secret key

# Configuration
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')  # Store uploads outside web root
ALLOWED_EXTENSIONS = {'pdf'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
RATE_LIMIT_WINDOW = 60  # seconds
MAX_LOGIN_ATTEMPTS = 5
login_attempts = {}  # Store login attempts per IP address

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# CSP Header
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';"
    return response

# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# CSRF Token Generation and Validation
def generate_csrf_token():
    return secrets.token_hex(16)

def validate_csrf_token(token):
    return 'csrf_token' in session and session['csrf_token'] == token

# Rate Limiting
def is_rate_limited(ip_address):
    now = time.time()
    if ip_address in login_attempts:
        attempts, last_attempt = login_attempts[ip_address]
        if now - last_attempt < RATE_LIMIT_WINDOW and attempts >= MAX_LOGIN_ATTEMPTS:
            return True
        else:
            login_attempts[ip_address] = (attempts + 1, now)
    else:
        login_attempts[ip_address] = (1, now)
    return False

# Password Hashing (Example - use a proper user database in a real application)
def hash_password(password):
    salt = secrets.token_hex(16)
    hashed_password = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    return salt, hashed_password

def verify_password(password, salt, hashed_password):
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest() == hashed_password

# Dummy User Data (Replace with a database)
users = {
    'testuser': hash_password('password123')  # (salt, hashed_password)
}

# Helper Functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_filename(filename):
    """Sanitizes filename to prevent path traversal."""
    filename = secure_filename(filename)  # Remove potentially dangerous characters
    if ".." in filename:
        raise ValueError("Filename contains invalid characters.")
    return filename

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr

        if is_rate_limited(ip_address):
            return render_template('login.html', error='Too many login attempts. Please try again later.')

        if username in users:
            salt, hashed_password = users[username]
            if verify_password(password, salt, hashed_password):
                session['username'] = username
                session['csrf_token'] = generate_csrf_token()
                login_attempts.pop(ip_address, None)  # Reset attempts on successful login
                return redirect(url_for('index'))
            else:
                return render_template('login.html', error='Invalid credentials')
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
def index():
    csrf_token = session['csrf_token']
    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token')):
            return render_template('index.html', error='CSRF token validation failed.', csrf_token=csrf_token)

        # Check if the post request has the file part
        if 'file' not in request.files:
            return render_template('index.html', error='No file part', csrf_token=csrf_token)
        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return render_template('index.html', error='No selected file', csrf_token=csrf_token)

        if file and allowed_file(file.filename):
            try:
                filename = sanitize_filename(file.filename)
                filepath = os.path.join(UPLOAD_FOLDER, filename)

                # Check file size before saving
                file.seek(0, os.SEEK_END)
                file_length = file.tell()
                file.seek(0)  # Reset file pointer

                if file_length > MAX_FILE_SIZE:
                    return render_template('index.html', error=f'File size exceeds the limit of {MAX_FILE_SIZE / (1024 * 1024)} MB', csrf_token=csrf_token)

                file.save(filepath)

                # File Permissions (Restrict access)
                os.chmod(filepath, 0o600)  # Owner read/write only

                return render_template('index.html', message='File uploaded successfully', csrf_token=csrf_token)

            except ValueError as e:
                return render_template('index.html', error=str(e), csrf_token=csrf_token)
            except Exception as e:
                return render_template('index.html', error=f'An error occurred: {str(e)}', csrf_token=csrf_token)

        else:
            return render_template('index.html', error='Invalid file type. Only PDF files are allowed.', csrf_token=csrf_token)

    return render_template('index.html', csrf_token=csrf_token)

@app.route('/uploads/<filename>')
@login_required
def download_file(filename):
    """Serve files from the uploads directory (with authentication)."""
    try:
        return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)
    except FileNotFoundError:
        return "File not found", 404

if __name__ == '__main__':
    app.run(debug=True) # Disable debug mode in production

