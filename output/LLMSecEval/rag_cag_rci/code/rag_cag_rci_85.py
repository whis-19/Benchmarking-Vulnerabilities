import os
import secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, abort
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Change this to a strong, random key
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
CSRF_TOKEN_LENGTH = 32

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# CSP Header
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# CSRF Token Generation and Validation
def generate_csrf_token():
    token = secrets.token_hex(CSRF_TOKEN_LENGTH // 2)
    session['csrf_token'] = token
    return token

def validate_csrf_token(token):
    return 'csrf_token' in session and session['csrf_token'] == token

def csrf_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = request.form.get('csrf_token')
            if not token or not validate_csrf_token(token):
                logging.warning("CSRF token validation failed.")
                abort(400, description="CSRF token is missing or invalid.")
        return f(*args, **kwargs)
    return decorated_function

# File Handling Functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_filename(filename):
    """Sanitizes a filename to prevent path traversal and other attacks."""
    if not filename:
        return None

    filename = secure_filename(filename)  # Werkzeug's secure_filename
    if filename is None or filename == "":
        return None

    # Additional checks:  No directory separators, no ".." sequences, only one "."
    if "/" in filename or "\\" in filename or ".." in filename or filename.count(".") > 1:
        logging.warning(f"Filename {filename} contains invalid characters.")
        return None

    return filename

def save_file(file, filename):
    """Saves the file to the upload directory after sanitizing the filename."""
    if not file:
        logging.warning("No file provided for saving.")
        return False

    sanitized_name = sanitize_filename(file.filename)
    if not sanitized_name:
        logging.warning(f"Invalid filename: {file.filename}")
        return False

    filepath = os.path.join(UPLOAD_FOLDER, sanitized_name)

    try:
        file.save(filepath)
        logging.info(f"File saved successfully to {filepath}")
        return True
    except Exception as e:
        logging.error(f"Error saving file: {e}")
        return False

# Routes
@app.route('/')
def index():
    csrf_token = generate_csrf_token()
    return render_template('index.html', csrf_token=csrf_token)

@app.route('/upload', methods=['POST'])
@csrf_required
def upload_file():
    if 'file' not in request.files:
        logging.warning("No file part in the request.")
        return render_template('index.html', message='No file part', csrf_token=generate_csrf_token())

    file = request.files['file']

    if file.filename == '':
        logging.warning("No file selected.")
        return render_template('index.html', message='No file selected', csrf_token=generate_csrf_token())

    if file and allowed_file(file.filename):
        if save_file(file, file.filename):
            return render_template('index.html', message='File uploaded successfully!', csrf_token=generate_csrf_token())
        else:
            return render_template('index.html', message='File upload failed.', csrf_token=generate_csrf_token())
    else:
        logging.warning(f"Invalid file type: {file.filename}")
        return render_template('index.html', message='Invalid file type. Allowed types: ' + ', '.join(ALLOWED_EXTENSIONS), csrf_token=generate_csrf_token())

@app.route('/uploads/<filename>')
def download_file(filename):
    """Serve files from the upload directory."""
    sanitized_filename = sanitize_filename(filename)
    if not sanitized_filename:
        abort(400, description="Invalid filename.")

    try:
        return send_from_directory(UPLOAD_FOLDER, sanitized_filename)
    except FileNotFoundError:
        abort(404)

@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', error=str(e)), 400

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal Server Error")
    return render_template('error.html', error="Internal server error"), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

